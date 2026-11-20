# Gadyen Safeguard

*Security compliance for tax professionals, in your language.*

Prototype of an AI agent that checks the security of a small tax practice, explains the
findings in English, Spanish, French or Haitian Creole, and drafts its Written Information
Security Plan (WISP). Term project, UMass Lowell, Fall 2026.

> Security guidance, not legal advice. Only test domains you own or are authorized in
> writing to test.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # then edit .env with your keys
pytest -q                            # all tests must pass

# Milestone 1: passive email check, no LLM needed
python -m gadyen.cli quickcheck yourdomain.com
# Active checks only on a domain you own
python -m gadyen.cli quickcheck yourdomain.com --i-own-this-domain

# Run the API, then open http://127.0.0.1:8000/docs
uvicorn gadyen.api:app --reload
```

## How it works

1. The owner answers the questionnaire and proves domain ownership with a DNS TXT record.
2. The LLM agent plans and calls tools; **every call goes through the policy guard**
   (`gadyen/scope.py`), which refuses unverified domains, private addresses and unknown tools.
3. A baseline guarantees the required checks always run.
4. **Deterministic rules** (`gadyen/scoring.py`) decide pass / warn / fail / unknown.
5. The LLM only explains the findings in the owner's language; its output is validated.
6. Everything is written to a hash-chained evidence log (`gadyen/store.py`).

## Layout

| Path | Purpose |
|---|---|
| `gadyen/scope.py` | Policy guard and scope checks |
| `gadyen/tools/` | Scanners (DNS, TLS, HTTP, ports) and endpoint report validation |
| `gadyen/scoring.py` | Deterministic control rules |
| `gadyen/agent.py`, `gadyen/prompts.py` | Agent loop and prompts |
| `gadyen/store.py` | SQLite storage and evidence chain |
| `gadyen/wisp.py` | WISP draft generator (.docx) |
| `gadyen/api.py`, `gadyen/cli.py` | HTTP API and command line |
| `endpoint-check/` | Read-only Windows and macOS self-check scripts |
| `lab/injection_cases.json` | Prompt-injection test catalog |
| `tests/` | Unit and adversarial tests |


# Elliot's Additions

## Starting up Server
1. Install mysql (See installation instructions)
2. In mysql, create a database by typing: "CREATE DATABASE compsec;"
3. To see if data is getting added to database in terminal (NOT NEEDED) type "use compsec"
4. Create a virtual enviornment like "python3 -m venv gadyen-env"
5. Start the server by running the command "python3 -m database.server" at the ~/gadyen-comp5610 directory

## Installations:
1. sudo apt update
2. sudo apt install mysql-server
3. In virtual environment:
   - pip3 install flask
   - pip3 install mysql-connector-python
   - pip3 install dotenv
   - python3 -m pip install google-genai
   - pip3 install bcrypt
4. Getting Render working
   - sudo apt install -y mkcert libnss3-tools
   - mkcert -install
   - mkcert localhost 127.0.0.1
   - gunicorn --certfile localhost+1.pem --keyfile localhost+1-key.pem gadyen_web.server:app

## Database.py
1. I created a .env folder:
   - MYSQL_HOST='127.0.0.1'
   - MYSQL_USER='[Your mysql username]'
   - MYSQL_PASSWORD='[Your mysql password]'
   - MYSQL_DATABASE='compsec'
   - SECRET_KEY=***Create your own secret key***

2. Connects to the mysql database
3. Gets cursor to use to communicate with database, created a function so it doesn't keep calling it
4. Get Table creates the table if it doesn't exist yet. The two tables as of now that it creates are for login and for chatbot. I also need to create a table for user information
5. getUsers() gets everything from user_login, the table. This is for testing, will likely remove this once we are done
6. getUser(user_id) Gets everything from the row of that user_id
7. check_user(username, password) is used for logging in. It compares the hashes
8. check_username(username) checks to see if username is already being used. If it is, it will return True meaning the user has to enter a different username
9. add_user(username, password): adds new username and hashed password to the user_login database
10. saveMessage(user_id, role, content) will be used for chatbot database, but I have not implemented that yet
11. getRecentMessages(user_id, limit=20) will be used for chatbot database, but I have not implemented that yet
12. Main function is for testing, does not get used when server is running

## Server.py
1. Uses flask to run the program
2. Import desired functions into server.py from database.py
3. load_dotenv() allows you to use .env variables
4. Sets up Flask and secret key
5. If url is nothing after localhost, just go to login page
6. If "/dashboard" after localhost in URL, display the dashboard html/css page
7. If "/register", store all the information from the user, test to see if username is already in use, if not, add username and hashed password to user_login table. Need to add another table for name, email.
8. If "/login", store user values for username and password, then check to see if it is in the database. If it is not in the database, throw an error message, if it is, redirect to dashboard.
9. If "/chat", (which will be on the dashboard page) connect with gemini-api.
10. Main function runs the server on port 3000

## Important Notes:
1. Most of the html, css is in a folder named "public", since the internet needs to be able to read the files. "dashboard is in a separate folder since it should only be accessed if the user puts in their correct username and password
2. Created another .env folder with my GEMINI_API_KEY in chatbot folder