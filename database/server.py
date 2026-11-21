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
<<<<<<< HEAD
import re
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()  # before importing modules that read environment variables

from flask import Flask, jsonify, redirect, request, send_from_directory, session  # noqa: E402
from mysql.connector import errors  # noqa: E402

from chatbot.chatbot import get_reply  # noqa: E402
from chatbot.security import (MAX_MESSAGE_CHARS, RateLimiter, redact_sensitive,  # noqa: E402
                              validate_registration)
from database.database import (add_user, check_user, check_username, get_chat_history,  # noqa: E402
                               get_table, save_chat_message)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
security_log = logging.getLogger("gadyen.security")
=======
import random
import string
from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors
from dotenv import load_dotenv
from google import genai
from chatbot.chatbot import get_reply
from flask_mail import Mail
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from database.database import check_user, add_user, check_username, save_chat_message, get_chat_history
client = genai.Client()

load_dotenv()
>>>>>>> bd91423 (Added email verification and information page)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_RE = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,24}$")


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
<<<<<<< HEAD
    SESSION_COOKIE_SAMESITE="Strict",
    # HTTPS-only cookies on Render, or when SESSION_COOKIE_SECURE=1 behind another HTTPS proxy
    SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")) or os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=64 * 1024,   # reject large request bodies outright
)

# Create the tables automatically when the server starts
try:
    get_table()
except Exception as e:  # noqa: BLE001 - app can still serve pages; DB errors surface per request
    security_log.error("could not create tables: %s", type(e).__name__)

# Rate limits (in-memory; use Redis or similar if you run several workers).
login_failures = RateLimiter(limit=5, window=15 * 60)    # 5 failed logins / 15 min per IP+user
register_limiter = RateLimiter(limit=5, window=60 * 60)  # 5 registrations / hour per IP
chat_minute = RateLimiter(limit=10, window=60)           # 10 messages / minute per user
chat_day = RateLimiter(limit=200, window=24 * 60 * 60)   # 200 messages / day per user
=======
    SESSION_COOKIE_SAMESITE="Lax",
)

app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
)
>>>>>>> bd91423 (Added email verification and information page)

mail = Mail(app)
otp_storage = {}

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

<<<<<<< HEAD

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
        if e.errno == 1062:  # duplicate entry (ER_DUP_ENTRY)
            return redirect("/register.html?error=1")
        raise
    security_log.info("user_registered username=%s ip=%s", username, client_ip())
    return redirect("/")


=======
>>>>>>> bd91423 (Added email verification and information page)
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

@app.post("/register")
def register():
    print("REGISTER ROUTE REACHED")
    name = request.form["name"]
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]

    # re_enter_password = request.form["re_enter_password"]
    if check_username(username):
        return redirect("/register.html?error=1")

    otp = ''.join(random.choice(string.digits) for _ in range(6))
    otp_storage[email] = {
        "otp": otp,
        "username": username,
        "password": password
    }
    try:
        mail.send_message(
            subject=f"Verify your email",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=f"Your verification code is: {otp}"
        )
        print("OTP EMAIL SENT SUCCESSFULLY")
    except errors.IntegrityError as e:
        print("EMAIL ERROR: ", repr(e))
        otp_storage.pop(email, None)
        return redirect("/register.html?error=email")
    return redirect(f"/verify.html?email={email}")

@app.post("/verify")
def verify_email():
    email = request.form.get("email")
    entered_otp = request.form.get("otp")

    if not email or not entered_otp:
        return redirect("/register.html?error=missing")

    stored_data = otp_storage.get(email)

    if not stored_data:
        return redirect("/register.html?error=expired")

    if entered_otp != stored_data["otp"]:
        return redirect(
            f"/verify.html?email={email}&error=invalid"
        )

    try:
        add_user(
            stored_data["username"],
            stored_data["password"]
        )
        print(f"User {stored_data['username']} verified and registered")
    except errors.IntegrityError:
        return redirect("/register.html?error=1")

    otp_storage.pop(email, None)
    return redirect("/")

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
<<<<<<< HEAD
=======
    message = request.get_json().get("message", "").strip()
>>>>>>> bd91423 (Added email verification and information page)

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
    user_id = session["user_id"]
    history = get_chat_history(user_id)
    if history:
        return jsonify(reply=None)

    prompt = """
     "Introduce yourself as Gayden Safeguard and welcome the user. Briefly explain that you help create WISPs and ask what language they prefer."
    """
    

# @app.get("/chat/history")
# def chat_history():
#     if "user_id" not in session:
#         return jsonify(error="Not logged in"), 401
#     history = get_chat_history(session["user_id"])
#     return jsonify(history)
    

<<<<<<< HEAD

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "3000")),
            debug=os.getenv("FLASK_DEBUG", "0") == "1")
=======
if __name__=="__main__":
    app.run(port=3000, debug=True)
>>>>>>> bd91423 (Added email verification and information page)
