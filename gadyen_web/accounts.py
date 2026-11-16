"""Who is signed in: the name shown in the account menu of the chat page."""
from database.database import get_cursor


def get_profile(user_id):
    """Return {"username", "name"} for the signed-in user, or None."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT l.username AS username, i.name AS name FROM user_login l "
            "LEFT JOIN user_info i ON i.user_id = l.id "
            "WHERE l.id = %s ORDER BY i.id DESC LIMIT 1", (user_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {"username": row["username"], "name": row["name"] or row["username"]}
