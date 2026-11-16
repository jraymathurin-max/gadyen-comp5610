import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, session, redirect, request, send_from_directory, jsonify
from mysql.connector import errors

from gadyen_web import conversations as store
from gadyen_web.chatbot import ChatError, forget_conversation, get_reply
from gadyen_web.languages import normalize_language, welcome_message
from database.database import get_table, check_user, add_user, check_username

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
    store.ensure_tables()
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
        data = {}
    message = data.get("message")
    message = message.strip() if isinstance(message, str) else ""
    language = normalize_language(data.get("language"))
    conversation_id = _conversation_id(data.get("conversation_id"))

    if not message:
        return jsonify(error="empty_message"), 400
    if len(message) > MAX_MESSAGE_CHARS:
        return jsonify(error="too_long"), 413

    conversation = None
    try:
        if conversation_id is None:
            # First message of a new conversation: it appears in the history now
            conversation = store.create_conversation(user_id, message)
            conversation_id = conversation["id"]
            history = []
        elif not store.owns_conversation(user_id, conversation_id):
            return jsonify(error="not_found"), 404
        else:
            # History BEFORE this message: lets the agent recover its context
            # after a server restart or a language switch.
            history = store.get_messages(user_id, conversation_id, limit=30)
        store.add_message(conversation_id, "user", message)
        reply = get_reply(user_id, message, language, history, conversation_id)
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
    app.run(port=3000, debug=True)
