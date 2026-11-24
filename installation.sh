#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"    # always run form the repo root

sudo apt update
sudo apt install -y mysql-server python3-venv mkcert libnss3-tools

python3 -m venv gadyen-env
gadyen-env/bin/python -m pip install --upgrade pip
gadyen-env/bin/python -m pip install -r requirements.txt
gadyen-env/bin/python -m pip install flask flask-mail mysql-connector-python \
python-dotenv google-genai bcrypt pytest dnspython httpx gunicorn


mkcert -install
[ -f cyberRange+1.pem ] || mkcert cyberRange 0.0.0.0

echo
echo "Setup Complete. Active with: source gadyen-env/bin/activate"
