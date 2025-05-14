# utils/crypto.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

AES_KEY = b"ThisIs32ByteAESKey_For_GhostC2!!"  # Must be 32 bytes

def aes_encrypt(plaintext: str) -> str:
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()

def aes_decrypt(ciphertext_b64: str) -> str:
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()
