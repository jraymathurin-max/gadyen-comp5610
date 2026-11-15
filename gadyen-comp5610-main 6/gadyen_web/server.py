import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors

from gadyen_web.chatbot import ChatError, get_reply
from gadyen_web.languages import normalize_language, welcome_message
from database.database import (
    get_table, check_user, add_user, check_username,
    save_chat_message, get_chat_history,
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
    name = request.form["name"]
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]

    if check_username(username):
        return redirect("/register.html?error=1")

    try:
        add_user(username, password, name, email)
    except errors.IntegrityError as e:
        if e.errno == 1062:  # duplicate entry
            return redirect("/register.html?error=1")
        raise
    return redirect("/")


@app.post("/login")
def login():
    username = request.form["username"]
    password = request.form["password"]
    user_id = check_user(username, password)

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


@app.get("/chat/welcome")
def chat_welcome():
    if "user_id" not in session:
        return jsonify(error="not_logged_in"), 401
    return jsonify(reply=welcome_message(request.args.get("lang")))


if __name__ == "__main__":
    app.run(port=3000, debug=True)
