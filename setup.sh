#!/bin/bash

set -e

echo "[*] Installing system dependencies..."
sudo apt update
sudo apt install -y \
  python3.11 python3.11-venv python3.11-dev \
  build-essential libssl-dev libffi-dev \
  libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev \
  zlib1g-dev curl git

echo "[*] Creating virtual environment..."
rm -rf venv
python3.11 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install flask flask-login flask-socketio eventlet requests pycryptodome

echo "[✔] Setup complete. Run with: source venv/bin/activate && python server/app.py"

