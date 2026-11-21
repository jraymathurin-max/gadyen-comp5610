import os
import string
import secrets
import time
from urllib.parse import quote
from flask_mail import Mail
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors

from gadyen_web.chatbot import ChatError, get_reply
from gadyen_web.languages import normalize_language, welcome_message
from database.database import (
    get_table, get_cursor, check_user, add_user, check_username, save_chat_message, get_chat_history,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_MESSAGE_CHARS = 4000

app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")),  # HTTPS on Render
)
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
)

mail = Mail(app)
otp_storage = {}
OTP_TTL = 600

# Create the tables automatically when the server starts
try:
    get_table()
except Exception as e:
    print("Could not create tables:", e)


@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "public"), "login.html")


@app.get("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")
    return send_from_directory(os.path.join(BASE_DIR, "views"), "dashboard.html")


@app.post("/register")
def register():
    print("REGISTER ROUTE REACHED")
    name = request.form["name"].strip()
    email = request.form["email"].strip().lower()
    username = request.form["username"]
    password = request.form["password"]

    # re_enter_password = request.form["re_enter_password"]
    if check_username(username):
        return redirect("/register.html?error=1")

    otp = ''.join(secrets.choice(string.digits) for _ in range(6))
    otp_storage[email] = {
        "otp": otp,
        "name": name,
        "username": username,
        "password": password,
        "expires": time.time() + OTP_TTL
    }
    try:
        mail.send_message(
            subject=f"Verify your email",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=f"Your verification code is: {otp}"
        )
        print("OTP EMAIL SENT SUCCESSFULLY")
    except Exception as e:
        print("EMAIL ERROR: ", repr(e))
        otp_storage.pop(email, None)
        return redirect("/register.html?error=email")
    return redirect(f"/verify.html?email={quote(email)}")

@app.post("/verify")
def verify_email():
    email = (request.form.get("email") or "").strip().lower()
    entered_otp = (request.form.get("otp") or "").strip()

    if not email or not entered_otp:
        return redirect("/register.html?error=missing")

    stored_data = otp_storage.get(email)

    if not stored_data or time.time() > stored_data["expires"]:
        otp_storage.pop(email, None)
        return redirect("/register.html?error=expired")

    if entered_otp != stored_data["otp"]:
        return redirect(
            f"/verify.html?email={quote(email)}&error=invalid"
        )

    try:
        add_user(
            stored_data["username"],
            stored_data["password"],
            stored_data["name"],
            email,
        )
        print(f"User {stored_data['username']} verified and registered")
    except errors.IntegrityError:
        return redirect("/register.html?error=1")

    otp_storage.pop(email, None)
    return redirect("/")


@app.post("/login")
def login():
    username = request.form["username"]
    password = request.form["password"]

    try:
        user_id = check_user(username, password)
    except Exception:
        app.logger.exception("login failed")
        return redirect("/?error=1")
    
    if user_id:
        session["user_id"] = user_id
        return redirect("/dashboard")
    return redirect("/?error=1")

@app.post("/chat")
def chat():
    """Always answers with JSON, so the page can show a real reason on failure."""
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    user_id = session["user_id"]
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    message = data.get("message")
    message = message.strip() if isinstance(message, str) else ""
    language = normalize_language(data.get("language"))

    if not message:
        return jsonify(error="empty_message"), 400
    if len(message) > MAX_MESSAGE_CHARS:
        return jsonify(error="too_long"), 413

    try:
        # History BEFORE this message: lets the agent recover its context
        # after a server restart or a language switch.
        history = get_chat_history(user_id, limit=30)
        save_chat_message(user_id, "user", message)
        reply = get_reply(user_id, message, language, history)
        save_chat_message(user_id, "bot", reply)
    except ChatError as exc:
        app.logger.error("chat failed for user %s: %s (%s)", user_id, exc.code, exc)
        return jsonify(error=exc.code), exc.status
    except Exception:
        app.logger.exception("chat failed for user %s", user_id)
        return jsonify(error="unavailable"), 500
    return jsonify(reply=reply)


@app.get("/chat/history")
def chat_history():
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    try:
        return jsonify(get_chat_history(session["user_id"]))
    except Exception:
        app.logger.exception("could not load chat history")
        return jsonify(error="unavailable"), 500

@app.get("/user-info")
def user_info_page():
    if "user_id" not in session:
        return redirect("/")
    return send_from_directory(os.path.join(BASE_DIR, "views"), "user_info.html")

@app.get("/api/me")
def user_info():
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    with get_cursor() as cur:
        cur.execute(
            "SELECT u.username, i.name, i.email "
            "FROM user_login u "
            "LEFT JOIN user_info i ON i.user_id = u.id "
            "WHERE u.id = %s",
            (session["user_id"],),
        )
        row = cur.fetchone()
    return jsonify(row or {})


@app.get("/chat/welcome")
def chat_welcome():
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    return jsonify(reply=welcome_message(request.args.get("lang")))


if __name__ == "__main__":
    app.run(port=3000, debug=True)