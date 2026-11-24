#!/usr/bin/env bash
sudo apt update
sudo apt install mysql-server

python3 -m venv gadyen-env
source gadyen-env/bin/activate

pip3 install flask
pip3 install mysql-connector-python
pip3 install dotenv
python3 -m pip install google-genai
pip3 install bcrypt

sudo apt install -y mkcert libnss3-tools
mkcert -install
mkcert cyberRange 0.0.0.0
gunicorn --bind 0.0.0.0:8000 --certfile cyberRange+1.pem --keyfile cyberRange+1-key.pem gadyen_web.server:app