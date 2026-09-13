import os
import urllib.parse
from Crypto.Cipher import AES

BLOCK_SIZE = 16

# 1. Global Key and IV (constant for program lifetime)
KEY = os.urandom(16)
IV = os.urandom(16)


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padding length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        enc = cipher.encrypt(xor_bytes(block, prev))
        ciphertext.extend(enc)
        prev = enc
    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = cipher.decrypt(block)
        plaintext.extend(xor_bytes(dec, prev))
        prev = block
    return unpad_pkcs7(bytes(plaintext))


# 2. Server Oracle: submit()
def submit(user_input: str) -> bytes:
    # URL encode ';' and '='
    safe_input = user_input.replace(";", "%3B").replace("=", "%3D")
    full_string = f"userid=456;userdata={safe_input};session-id=31337"
    return encrypt_cbc(full_string.encode("utf-8"), KEY, IV)


# 3. Server Oracle: verify()
def verify(ciphertext: bytes) -> bool:
    try:
        # Decrypt, ignoring decoding errors in corrupted blocks
        decrypted = decrypt_cbc(ciphertext, KEY, IV)
        # Just as a demonstration in output to visualize the decrypted text, we can print it. In a real scenario, this would not be printed.
        print(f"Decrypted text: {decrypted.decode('latin-1', errors='replace')}")
        text = decrypted.decode("latin-1")
        return ";admin=true;" in text
    except Exception:
        return False


# 4. Attack Demonstration
def exploit():
    # 'userid=456;userdata=' is 20 bytes:
    #   Block 0 (bytes 0..15):  'userid=456;userd'
    #   Block 1 (bytes 16..31): 'ata=' (4 bytes) + 12 dummy bytes = 16 bytes
    #
    # Block 2 (bytes 32..47) starts exactly with our target payload:
    alignment_pad = "A" * 12
    target_payload = "?admin?true?xxxx"
    user_input = alignment_pad + target_payload

    ciphertext = bytearray(submit(user_input))

    # We modify Block 1 (bytes 16 to 31) to alter Block 2 (bytes 32 to 47):
    # - Byte 16 targets Block 2 offset 0: '?' -> ';'
    # - Byte 22 targets Block 2 offset 6: '?' -> '='
    # - Byte 27 targets Block 2 offset 11: '?' -> ';'

    ciphertext[16 + 0] ^= ord("?") ^ ord(";")
    ciphertext[16 + 6] ^= ord("?") ^ ord("=")
    ciphertext[16 + 11] ^= ord("?") ^ ord(";")

    print(f"Normal input verify():      {verify(submit('admin=true'))}")
    print()
    print(f"Exploited ciphertext verify(): {verify(bytes(ciphertext))}")
    # Result from exploit would look something like this. Where ▒▒ is just whatever got scrambled
    # userid=456;userd▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒;admin=true;xxxx;session-id=31337


if __name__ == "__main__":
    exploit()