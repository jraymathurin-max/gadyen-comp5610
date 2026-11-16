"""Gadyen Safeguard web app (Flask). Run from the repo root:  python -m database.server

Security hardening (see SECURITY.md):
  * Startup: refuses to run without a strong SECRET_KEY; debugger off unless FLASK_DEBUG=1;
    binds to 127.0.0.1 by default.
  * AuthN: bcrypt hashes, password policy, login brute-force lockout, session reset on
    login (no fixation), logout.
  * AuthZ: every chat endpoint requires a session; user_id comes only from the session.
  * CSRF: cross-origin POSTs rejected (Origin/Referer check) + SameSite cookies.
  * Abuse: per-user chat rate limits and message size cap protect the paid LLM API.
  * Privacy: PII/secrets are redacted before anything is written to the database.
  * Headers: CSP, X-Frame-Options, nosniff, Referrer-Policy.
"""
import logging
import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from mysql.connector import errors

from chatbot.chatbot import get_reply
from chatbot.security import MAX_MESSAGE_CHARS, RateLimiter, redact_sensitive, validate_registration
from database.database import add_user, check_user, check_username, get_chat_history, save_chat_message

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
security_log = logging.getLogger("gadyen.security")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",  # set to 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=64 * 1024,   # reject large request bodies outright
)

# Rate limits (in-memory; use Redis or similar if you run several workers).
login_failures = RateLimiter(limit=5, window=15 * 60)    # 5 failed logins / 15 min per IP+user
register_limiter = RateLimiter(limit=5, window=60 * 60)  # 5 registrations / hour per IP
chat_minute = RateLimiter(limit=10, window=60)           # 10 messages / minute per user
chat_day = RateLimiter(limit=200, window=24 * 60 * 60)   # 200 messages / day per user


def client_ip() -> str:
    return request.remote_addr or "unknown"


# ------------------------------------------------------------------ cross-cutting checks
@app.before_request
def reject_cross_origin_posts():
    """CSRF defence: a state-changing request must come from our own origin."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if source and urlparse(source).netloc != request.host:
        security_log.warning("csrf_blocked ip=%s path=%s origin=%s", client_ip(), request.path, source)
        return jsonify(error="Cross-origin request blocked"), 403
    return None


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; object-src 'none'; "
                            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith(("/chat", "/dashboard")):
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
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    problem = validate_registration(username, password)
    if problem:
        return redirect("/register.html?error=policy")
    if check_username(username):
        return redirect("/register.html?error=1")
    try:
        add_user(username, password)
    except errors.IntegrityError as e:
        if e.errno == 1062:  # duplicate entry (ER_DUP_ENTRY)
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
        security_log.info("login_ok user=%s ip=%s", user_id, client_ip())
        return redirect("/dashboard")
    login_failures.hit(key)
    security_log.warning("login_failed username=%s ip=%s", username, client_ip())
    return redirect("/?error=1")


@app.post("/logout")
def logout():
    session.clear()
    return redirect("/")


# ------------------------------------------------------------------ chat
@app.post("/chat")
def chat():
    if "user_id" not in session:
        return jsonify(error="Not logged in"), 401
    user_id = session["user_id"]

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("message"), str):
        return jsonify(error="Expected JSON {\"message\": \"...\"}"), 400
    message = body["message"].strip()
    if not message:
        return jsonify(error="Empty message"), 400
    if len(message) > MAX_MESSAGE_CHARS:
        return jsonify(error=f"Message too long (max {MAX_MESSAGE_CHARS} characters)"), 413

    if not chat_day.hit(user_id) or not chat_minute.hit(user_id):
        security_log.warning("chat_rate_limited user=%s", user_id)
        return jsonify(error="Too many messages. Please wait a moment and try again."), 429

    # Never persist secrets/PII: store the redacted form only.
    stored_message, _ = redact_sensitive(message)
    save_chat_message(user_id, "user", stored_message)
    try:
        reply = get_reply(user_id, message)
    except Exception:  # noqa: BLE001 - never leak stack traces / API errors to the browser
        security_log.exception("llm_error user=%s", user_id)
        return jsonify(error="The assistant is unavailable right now. Please try again."), 502
    save_chat_message(user_id, "bot", reply)
    return jsonify(reply=reply)


@app.get("/chat/history")
def chat_history():
    if "user_id" not in session:
        return jsonify(error="Not logged in"), 401
    return jsonify(get_chat_history(session["user_id"]))


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "3000")),
            debug=os.getenv("FLASK_DEBUG", "0") == "1")
