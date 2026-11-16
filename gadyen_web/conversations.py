"""Conversation history for the gadyen_web interface.

Each chat is a separate conversation, listed in the side panel. The data lives
in three tables of its own (web_conversations, web_messages, web_import_done),
so the original chat_messages table and the code that uses it are untouched.
Every query filters on user_id: a user can only ever reach their own chats.
"""
import re

from database.database import get_cursor

TITLE_CHARS = 60
MAX_CONVERSATIONS_LISTED = 100


def ensure_tables():
    with get_cursor(commit=True) as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS web_conversations (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(120) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_web_conv_user (user_id, updated_at)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS web_messages (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                conversation_id BIGINT NOT NULL,
                role VARCHAR(20) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3),
                INDEX idx_web_msg_conv (conversation_id, created_at, id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS web_import_done (
                user_id INT PRIMARY KEY
            )
        """)


def make_title(text):
    """Short, single-line title taken from the first thing the user wrote."""
    title = re.sub(r"\s+", " ", text or "").strip()
    if len(title) > TITLE_CHARS:
        title = title[:TITLE_CHARS - 1].rstrip() + "…"
    return title or "Conversation"


def import_earlier_chat(user_id):
    """Copy the user's chat from before conversations existed into ONE history
    entry. Runs once per user; the original chat_messages rows are not changed."""
    with get_cursor(commit=True) as cur:
        cur.execute("INSERT IGNORE INTO web_import_done (user_id) VALUES (%s)", (user_id,))
        if cur.rowcount == 0:
            return  # already imported (or deliberately deleted since)
        cur.execute(
            "SELECT content FROM chat_messages WHERE user_id = %s AND role = 'user' "
            "ORDER BY created_at, id LIMIT 1", (user_id,))
        first = cur.fetchone()
        if first is None:
            return
        cur.execute(
            "SELECT MIN(created_at) AS first_at, MAX(created_at) AS last_at "
            "FROM chat_messages WHERE user_id = %s", (user_id,))
        span = cur.fetchone()
        cur.execute(
            "INSERT INTO web_conversations (user_id, title, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, make_title(first["content"]), span["first_at"], span["last_at"]))
        conversation_id = cur.lastrowid
        cur.execute(
            "INSERT INTO web_messages (conversation_id, role, content, created_at) "
            "SELECT %s, role, content, created_at FROM chat_messages "
            "WHERE user_id = %s ORDER BY created_at, id",
            (conversation_id, user_id))


def list_conversations(user_id):
    with get_cursor() as cur:
        cur.execute(
            "SELECT id, title, UNIX_TIMESTAMP(updated_at) AS updated_ts FROM web_conversations WHERE user_id = %s "
            "ORDER BY updated_at DESC, id DESC LIMIT %s",
            (user_id, MAX_CONVERSATIONS_LISTED))
        rows = cur.fetchall()
    # updated_at is sent as seconds since 1970 (UTC), so the browser can show
    # it in the visitor's own time zone whatever the database server uses.
    return [{"id": r["id"], "title": r["title"],
             "updated_at": int(r["updated_ts"]) if r["updated_ts"] is not None else None}
            for r in rows]


def create_conversation(user_id, first_message):
    title = make_title(first_message)
    with get_cursor(commit=True) as cur:
        cur.execute("INSERT INTO web_conversations (user_id, title) VALUES (%s, %s)",
                    (user_id, title))
        return {"id": cur.lastrowid, "title": title}


def owns_conversation(user_id, conversation_id):
    with get_cursor() as cur:
        cur.execute("SELECT id FROM web_conversations WHERE id = %s AND user_id = %s",
                    (conversation_id, user_id))
        return cur.fetchone() is not None


def get_messages(user_id, conversation_id, limit=200):
    """Messages of one conversation, oldest first. Empty if it is not the user's."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT m.role, m.content FROM web_messages m "
            "JOIN web_conversations c ON c.id = m.conversation_id "
            "WHERE m.conversation_id = %s AND c.user_id = %s "
            "ORDER BY m.created_at DESC, m.id DESC LIMIT %s",
            (conversation_id, user_id, limit))
        rows = cur.fetchall()
    return rows[::-1]


def add_message(conversation_id, role, content):
    with get_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO web_messages (conversation_id, role, content) VALUES (%s, %s, %s)",
            (conversation_id, role, content))
        cur.execute("UPDATE web_conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (conversation_id,))


def delete_conversation(user_id, conversation_id):
    """Permanently remove one conversation and its messages. True if it existed."""
    with get_cursor(commit=True) as cur:
        cur.execute("DELETE FROM web_conversations WHERE id = %s AND user_id = %s",
                    (conversation_id, user_id))
        if cur.rowcount == 0:
            return False
        cur.execute("DELETE FROM web_messages WHERE conversation_id = %s", (conversation_id,))
        return True
