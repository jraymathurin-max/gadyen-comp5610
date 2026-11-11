import os
import bcrypt
import mysql.connector
import mysql.connector.pooling
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

pool = mysql.connector.pooling.MySQLConnectionPool(
    host=os.getenv("MYSQL_HOST"),
    user=os.getenv("MYSQL_USER"),
    password=os.getenv("MYSQL_PASSWORD"),
    database=os.getenv("MYSQL_DATABASE")
)

@contextmanager
def get_cursor(commit=False):
    connection = pool.get_connection()
    cur = connection.cursor(dictionary=True)
    try:
        yield cur
        if commit:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cur.close()
        connection.close() # Returns connection to the pool

def get_table():
    with get_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_login (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                role VARCHAR(20) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user_login(id)
            )
        """)
        print("Tables are ready")

def getUsers():
    with get_cursor() as cur:
        cur.execute("SELECT * FROM user_login")
        rows = cur.fetchall()
    print(rows)

def getUser(user_id):
    with get_cursor() as cur:
        cur.execute("SELECT * FROM user_login WHERE id = %s", (user_id,))
    return cur.fetchone()  #dict or None

def check_user(username, password):
    with get_cursor() as cur:
        cur.execute("SELECT id, password FROM user_login WHERE username = %s", (username,),
                    )
        row = cur.fetchone()

        if row is None:
            return None
        
        match = bcrypt.checkpw(
            password.encode("utf-8"), 
            row["password"].encode("utf-8"),
            )
        return row["id"] if match else None

def check_username(username):
    with get_cursor() as cur:
        cur.execute("SELECT id, password FROM user_login WHERE username = %s", (username,),
                    )
        row = cur.fetchone()

        if row is None:
            return False
        return True

def add_user(username, password):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    with get_cursor(commit=True) as cur:
        cur.execute ("INSERT INTO user_login (username, password) VALUES (%s,%s)", (username, hashed.decode("utf-8"))
        )
    print(f"{username} added")


def saveMessage(user_id, role, content):
    with get_cursor() as cur:
        cur.execute("INSERT INTO chat_messages (user_id, role, content) VALUES (%s,%s,%s)",
        (user_id, role, content),
        )

def getRecentMessages(user_id, limit=20):
    with get_cursor(commit=True) as cur:
        cur.execute(
            """ SELECT role, content FROM chat_messages 
                WHERE user_id = %s ORDER BY created_at DESC, id DESC LIMIT %s""",
                (user_id, limit),
                    )
        rows = cur.fetchall()
    return rows[::-1]   # oldest first


if __name__=="__main__":
    get_table()
    name = "Nick"
    try:
        add_user(name, "password")
    except Exception as e:
        print("add_user failed", e)
    getUsers()
    if check_user(name, "password"):
        print(f"{name} Successfully Logged in")
    else:
        print("Incorrect username or password")

    if check_user(name, "password1"):
        print(f"{name} Successfully Logged in")
    else:
        print("Incorrect username or password")