"""Gadyen Safeguard web interface (deployed with gunicorn, see gunicorn.conf.py).

Security hardening (shared controls live in chatbot/security.py, see SECURITY.md):
  * Startup: refuses to run without a strong SECRET_KEY; debugger off unless FLASK_DEBUG=1.
  * AuthN: password policy, login brute-force lockout, session reset on login, logout,
    automatic sign-out after 10 minutes without activity.
  * AuthZ: user_id comes only from the signed session cookie.
  * CSRF: cross-origin POSTs rejected + SameSite=Strict cookies.
  * Abuse: per-user chat rate limits, message size cap, request body cap.
  * Privacy: PII/secrets redacted before the database and before the LLM.
  * Prompt injection: direct attempts answered by the guard; the model is never called.
  * Output: system-prompt leak blocking and secret redaction on every reply.
  * Headers: CSP, X-Frame-Options, nosniff, Referrer-Policy.
"""
import logging
import os
import re
import time
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, redirect, request, send_from_directory, session  # noqa: E402
from mysql.connector import errors  # noqa: E402

from chatbot.security import (RateLimiter, filter_output, looks_like_injection,  # noqa: E402
                              redact_sensitive, validate_registration)
from database.database import get_table, check_user, add_user, check_username  # noqa: E402
from gadyen_web import accounts  # noqa: E402
from gadyen_web import conversations as store  # noqa: E402
from gadyen_web.chatbot import (QUOTABLE, ChatError, forget_conversation, get_reply,  # noqa: E402
                                system_instruction)
from gadyen_web.languages import normalize_language, welcome_message  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
security_log = logging.getLogger("gadyen.security")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_MESSAGE_CHARS = 2000
# A signed-in session ends after this long without any request (default 10 minutes).
IDLE_TIMEOUT_SECONDS = int(os.getenv("IDLE_TIMEOUT_SECONDS", "600"))
EMAIL_RE = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,24}$")

INJECTION_REPLY = ("I can't follow instructions that try to change my role or reveal my "
                   "internal setup. I'm happy to keep helping with your office's security plan.")


def _require_secret_key() -> str:
    key = os.getenv("SECRET_KEY", "")
    if len(key) < 32:
        raise RuntimeError("SECRET_KEY must be set to a random value of at least 32 characters. "
                           "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
    return key


app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = _require_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")) or os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=64 * 1024,
)

# Create the tables automatically when the server starts
try:
    get_table()
    store.ensure_tables()
except Exception as e:  # noqa: BLE001
    security_log.error("could not create tables: %s", type(e).__name__)

# In-memory limits. gunicorn.conf.py runs ONE worker, so they are shared by all requests.
login_failures = RateLimiter(limit=5, window=15 * 60)    # failed logins per IP+username
register_limiter = RateLimiter(limit=5, window=60 * 60)  # registrations per IP
chat_minute = RateLimiter(limit=10, window=60)           # messages per user per minute
chat_day = RateLimiter(limit=200, window=24 * 60 * 60)   # messages per user per day


def client_ip() -> str:
    # Render sits behind a proxy; use the first X-Forwarded-For hop only there.
    if os.getenv("RENDER"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ------------------------------------------------------------------ cross-cutting checks
@app.before_request
def reject_cross_origin_posts():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if source and urlparse(source).netloc != request.host:
        security_log.warning("csrf_blocked ip=%s path=%s origin=%s", client_ip(), request.path, source)
        return jsonify(error="forbidden"), 403
    return None


@app.before_request
def enforce_idle_timeout():
    """Sign the user out on the server after IDLE_TIMEOUT_SECONDS without a request.
    The page runs the same timer, but the server decides: a stolen or forgotten
    session cookie stops working even if the browser never runs our script."""
    if "user_id" not in session:
        return None
    now = time.time()
    last_seen = session.get("last_seen")
    if isinstance(last_seen, (int, float)) and now - last_seen > IDLE_TIMEOUT_SECONDS:
        security_log.info("session_idle_timeout user=%s", session.get("user_id"))
        session.clear()
        if request.path == "/dashboard":
            return redirect("/?error=idle")
        if request.path.startswith(("/chat", "/conversations", "/me")):
            return jsonify(error="not_logged_in", reason="idle"), 401
        return None
    session["last_seen"] = now
    return None


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; "
                            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith(("/chat", "/dashboard", "/conversations", "/me")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ------------------------------------------------------------------ pages
@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "public"), "login.html")


@app.get("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")
    return send_from_directory(os.path.join(BASE_DIR, "views"), "dashboard.html")


# ------------------------------------------------------------------ auth
@app.post("/register")
def register():
    if not register_limiter.hit(client_ip()):
        security_log.warning("register_rate_limited ip=%s", client_ip())
        return redirect("/register.html?error=rate")
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if validate_registration(username, password):
        return redirect("/register.html?error=policy")
    if not name or len(name) > 255 or not EMAIL_RE.match(email):
        return redirect("/register.html?error=policy")
    if check_username(username):
        return redirect("/register.html?error=1")
    try:
        add_user(username, password, name, email)
    except errors.IntegrityError as e:
        if e.errno == 1062:  # duplicate entry
            return redirect("/register.html?error=1")
        raise
    security_log.info("user_registered username=%s ip=%s", username, client_ip())
    return redirect("/")


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    key = (client_ip(), username.lower())
    if login_failures.blocked(key):
        security_log.warning("login_locked username=%s ip=%s", username, client_ip())
        return redirect("/?error=locked"), 302, {"Retry-After": str(login_failures.retry_after(key))}
    if not username or not password or len(password.encode("utf-8")) > 72:
        user_id = None
    else:
        user_id = check_user(username, password)
    if user_id:
        login_failures.reset(key)
        session.clear()               # prevent session fixation
        session.permanent = True
        session["user_id"] = user_id
        session["last_seen"] = time.time()
        security_log.info("login_ok user=%s ip=%s", user_id, client_ip())
        return redirect("/dashboard")
    login_failures.hit(key)
    security_log.warning("login_failed username=%s ip=%s", username, client_ip())
    return redirect("/?error=1")


@app.post("/logout")
def logout():
    if "user_id" in session:
        security_log.info("logout user=%s", session["user_id"])
    session.clear()
    return redirect("/")


@app.get("/me")
def me():
    """Name of the signed-in user for the account menu. Also used by the page as a
    keep-alive while the user is active."""
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    try:
        profile = accounts.get_profile(session["user_id"])
    except Exception:
        app.logger.exception("could not load the account profile")
        return jsonify(error="unavailable"), 500
    if profile is None:
        session.clear()
        return jsonify(error="not_logged_in"), 401
    return jsonify(name=profile["name"], username=profile["username"],
                   idle_seconds=IDLE_TIMEOUT_SECONDS)


# ------------------------------------------------------------------ chat
def _conversation_id(value):
    """A positive integer id, or None for 'start a new conversation'."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None



@app.post("/chat")
def chat():
    """Always answers with JSON, so the page can show a real reason on failure."""
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    user_id = session["user_id"]
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="invalid_json"), 400
    
    message = data.get("message")
    if not isinstance(message, str):
        return jsonify(error="invalid_message"), 400
    message = message.strip() if isinstance(message, str) else ""
    language = normalize_language(data.get("language"))
    conversation_id = _conversation_id(data.get("conversation_id"))

    if not message:
        return jsonify(error="empty_message"), 400
    if len(message) > MAX_MESSAGE_CHARS:
        return jsonify(error="too_long"), 413
    if not chat_day.hit(user_id) or not chat_minute.hit(user_id):
        security_log.warning("chat_rate_limited user=%s", user_id)
        return jsonify(error="rate_limited"), 429

    # Input guard: PII/secrets never reach the database or the model.
    clean, kinds = redact_sensitive(message)
    if kinds:
        security_log.warning("input_redacted user=%s kinds=%s", user_id, kinds)

    conversation = None
    try:
        if conversation_id is None:
            # First message of a new conversation: it appears in the history now.
            # The title is built from the REDACTED text, so no PII in the side panel.
            conversation = store.create_conversation(user_id, clean)
            conversation_id = conversation["id"]
            history = []
        elif not store.owns_conversation(user_id, conversation_id):
            security_log.warning("conversation_access_denied user=%s conversation=%s",
                                 user_id, conversation_id)
            return jsonify(error="not_found"), 404
        else:
            # History BEFORE this message: lets the agent recover its context
            # after a server restart or a language switch.
            history = store.get_messages(user_id, conversation_id, limit=30)
        store.add_message(conversation_id, "user", clean)
        if looks_like_injection(message):
            security_log.warning("prompt_injection_blocked user=%s", user_id)
            reply = INJECTION_REPLY       # the model is never called
        else:
            to_model = clean
            if kinds:
                to_model += ("\n\n[Note to assistant: sensitive data (" + ", ".join(kinds) +
                             ") was removed from this message. Remind the user not to share it.]")
            raw = get_reply(user_id, to_model, language, history, conversation_id)
            reply, issues = filter_output(raw, system_instruction, quotable=QUOTABLE)
            if issues:
                security_log.warning("output_filtered user=%s issues=%s", user_id, issues)
        store.add_message(conversation_id, "bot", reply)
    except ChatError as exc:
        app.logger.error("chat failed for user %s: %s (%s)", user_id, exc.code, exc)
        return jsonify(error=exc.code, conversation_id=conversation_id), exc.status
    except Exception:
        app.logger.exception("chat failed for user %s", user_id)
        return jsonify(error="unavailable", conversation_id=conversation_id), 500
    return jsonify(reply=reply, conversation_id=conversation_id,
                   title=conversation["title"] if conversation else None)


@app.get("/conversations")
def conversations_list():
    """The user's earlier conversations, newest first, for the side panel."""
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    user_id = session["user_id"]
    try:
        store.import_earlier_chat(user_id)
        return jsonify(store.list_conversations(user_id))
    except Exception:
        app.logger.exception("could not list conversations")
        return jsonify(error="unavailable"), 500


@app.get("/conversations/<int:conversation_id>/messages")
def conversation_messages(conversation_id):
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    user_id = session["user_id"]
    try:
        if not store.owns_conversation(user_id, conversation_id):
            return jsonify(error="not_found"), 404
        return jsonify(store.get_messages(user_id, conversation_id))
    except Exception:
        app.logger.exception("could not load conversation")
        return jsonify(error="unavailable"), 500


@app.delete("/conversations/<int:conversation_id>")
def conversation_delete(conversation_id):
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    user_id = session["user_id"]
    try:
        if not store.delete_conversation(user_id, conversation_id):
            return jsonify(error="not_found"), 404
        forget_conversation(user_id, conversation_id)
    except Exception:
        app.logger.exception("could not delete conversation")
        return jsonify(error="unavailable"), 500
    return jsonify(deleted=True)


@app.get("/chat/welcome")
def chat_welcome():
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    return jsonify(reply=welcome_message(request.args.get("lang")))


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "3000")),
            debug=os.getenv("FLASK_DEBUG", "0") == "1")
