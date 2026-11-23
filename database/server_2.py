import os
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
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

mail = Mail(app)
otp_storage = {}

@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "public"), "login.html")


@app.get("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")
    return send_from_directory(os.path.join(BASE_DIR, "views"), "dashboard.html")

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
    message = request.get_json().get("message", "").strip()

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
    
# debug to false
if __name__=="__main__":
    app.run(port=3000, debug=False)