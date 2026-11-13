import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors

from chatbot.chatbot import get_reply
from database.database import (
    get_table, check_user, add_user, check_username,
    save_chat_message, get_chat_history,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
    if "user_id" not in session:
        return jsonify(error="Not logged in"), 401
    user_id = session["user_id"]
    message = (request.get_json() or {}).get("message", "").strip()

    if not message:
        return jsonify(error="Empty message"), 400

    save_chat_message(user_id, "user", message)
    reply = get_reply(user_id, message)
    save_chat_message(user_id, "bot", reply)
    return jsonify(reply=reply)


@app.get("/chat/history")
def chat_history():
    if "user_id" not in session:
        return jsonify(error="Not logged in"), 401
    return jsonify(get_chat_history(session["user_id"]))


@app.get("/chat/welcome")
def chat_welcome():
    if "user_id" not in session:
        return jsonify(error="Not logged in"), 401
    return jsonify(reply="Welcome to Gayden Safeguard! I help you create a Written Information "
                         "Security Plan (WISP). What language would you prefer to use?")


if __name__ == "__main__":
    app.run(port=3000, debug=True)
