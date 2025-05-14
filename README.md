# 👻 GhostC2

GhostC2 is a modular, encrypted, post-exploitation command-and-control (C2) framework built with Python and Flask. It features real-time WebSocket communication, polymorphic payload generation, operator authentication, and optional `.exe` packaging.

---

## 🚀 Features

- 🔐 AES-256 encrypted communication (symmetric)
- 🌐 Real-time bidirectional WebSocket tasking
- 🧠 Operator web console with live terminal view
- 🧬 Polymorphic payload generator with randomized variables
- 🖥️ Optional `.exe` compilation with PyInstaller
- 🛡️ Flask-Login based access control
- 🧾 SQLite-based task/result logging

---

## 📁 Project Structure

```
GhostC2/
├── builds/                 # Compiled payloads (.py, .exe)
├── output/                 # (Optional legacy output dir)
├── payloads/               # WebSocket and polling Python agents
│   └── ghost_socket_payload.py
├── server/
│   ├── app.py              # Main Flask + SocketIO server
│   └── templates/          # HTML templates for dashboard, console, login
├── tools/
│   └── generate_payload.py # Payload generator script
├── utils/
│   └── crypto.py           # AES encrypt/decrypt helpers
└── README.md
```

---

## ⚙️ Setup

### 1. Install dependencies
```bash
pip install flask flask-login flask-socketio eventlet pyinstaller
```

### 2. Run the server
```bash
cd server
python app.py
```

Visit [http://localhost:8080](http://localhost:8080)

**Login:**
```
Username: admin
Password: ghostpass123
```

---

## 👾 Payloads

### ✅ WebSocket Agent
```bash
python payloads/ghost_socket_payload.py
```

### 🧬 Generate Polymorphic Payload
```bash
python tools/generate_payload.py            # .py only
python tools/generate_payload.py --exe      # .py + .exe
```

Output saved to `builds/`

---

## 🖥️ Operator Console

- Live terminal view via `/console`
- Send commands to selected host
- Output streams back instantly via WebSocket

---

## 🔐 Security Notes

- All beacon traffic is AES-256 encrypted
- WebSocket messages are encrypted client/server-side
- Operators must log in via Flask-Login (sessions stored securely)

---

## 🧪 Red Team Use Cases

| Scenario              | Usage                                    |
|----------------------|------------------------------------------|
| Post-exploitation    | Remote shell via encrypted WebSocket     |
| Payload generation   | Obfuscated `.py` or `.exe` files         |
| Operator dashboards  | Web UI for task/result review            |
| C2 simulations       | Train detection or analyze traffic       |

---

## ⚠️ Legal

GhostC2 is provided for **educational and authorized red team use only**. Do not deploy this tool in any environment without proper authorization.

---

## 🧠 Built by Edward Wolfgang

- GitHub: [@wolfwashere](https://github.com/wolfwashere)
- Project: GhostC2 v1.0

Feel free to fork, contribute, or adapt for your research lab, red team, or academic project.
