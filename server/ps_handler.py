import socket
import threading
from datetime import datetime

def handle_client(conn, addr):
    print(f"[+] Connection from {addr[0]}:{addr[1]} at {datetime.now()}")
    conn.settimeout(2.0)

    try:
        while True:
            # Prompt for input first
            cmd = input().strip()
            if cmd.lower() in ['exit', 'quit']:
                conn.sendall(b"exit\n")
                break
            conn.sendall((cmd + '\n').encode())

            # Then read response
            output = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    output += chunk
                    if len(chunk) < 4096:
                        break
                except socket.timeout:
                    break

            if output:
                print(output.decode(errors='ignore'), end='')

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        print(f"[!] Connection from {addr[0]} closed")
        conn.close()

def start_listener(host='0.0.0.0', port=1443):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"[+] PowerShell listener started on port {port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.start()

if __name__ == "__main__":
    start_listener()

