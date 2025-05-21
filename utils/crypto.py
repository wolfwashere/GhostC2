# utils/crypto.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# ✅ Static default key (can be used for fallback or legacy)
AES_KEY = b"ThisIs32ByteAESKey_For_GhostC2!!"  # Must be 32 bytes

def aes_encrypt(plaintext: str, key: bytes = AES_KEY) -> str:
    """
    Encrypts plaintext using AES-CBC with the provided key.
    If no key is given, defaults to hardcoded AES_KEY.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()

def aes_decrypt(ciphertext_b64: str, key: bytes = AES_KEY) -> str:
    """
    Decrypts a base64-encoded AES-CBC ciphertext using the given key.
    """
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()
