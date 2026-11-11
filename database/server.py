import os
from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors
from dotenv import load_dotenv
from google import genai
from chatbot.chatbot import get_reply

from database.database import check_user, add_user, check_username
client = genai.Client()

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

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

    # re_enter_password = request.form["re_enter_password"]
    if check_username(username):
        return redirect("/register.html?error=1")

    try:
        add_user(username, password)
    except errors.IntegrityError as e:
        if e.errno == 1062: # diplicate entry (ER_DUP_ENTRY)
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
    message = request.get_json()["message"]
    return jsonify(reply=get_reply(session["user_id"], message))

if __name__=="__main__":
    app.run(port=3000, debug=True)