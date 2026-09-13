import os
import sys
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # AES uses 128 bit (16 byte) blocks


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad data to a multiple of block_size using PKCS#7 rules."""
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR between two byte sequences of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext in ECB mode block by block.
    AES.new(..., AES.MODE_ECB) is used strictly as the 16 byte block.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()

    # Step through 16 bytes at a time
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i : i + BLOCK_SIZE]
        encrypted_block = cipher.encrypt(block)
        ciphertext.extend(encrypted_block)

    return bytes(ciphertext)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext in CBC mode block by block.
    Each plaintext block is XORed with the prior ciphertext block (or IV).
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    prev_block = iv

    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i : i + BLOCK_SIZE]
        # XOR current plaintext block with previous ciphertext block
        xored_block = xor_bytes(block, prev_block)
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext.extend(encrypted_block)
        # Update prev_block for next iteration
        prev_block = encrypted_block

    return bytes(ciphertext)


def process_bmp(input_path: str, header_size: int = 54):
    """
    Reads a BMP file, encrypts its body using custom ECB and CBC modes,
    and writes out the results with the original unencrypted header.
    """
    with open(input_path, "rb") as f:
        raw_data = f.read()

    header = raw_data[:header_size]
    body = raw_data[header_size:]

    # Generate random 16 byte AES key and 16 byte IV
    key = os.urandom(16)
    iv = os.urandom(16)

    print(f"Key (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")

    # 1. ECB Encryption
    ecb_body = encrypt_ecb(body, key)
    ecb_output_path = "output_ecb.bmp"
    with open(ecb_output_path, "wb") as f:
        f.write(header + ecb_body)
    print(f"Saved: {ecb_output_path}")

    # 2. CBC Encryption
    cbc_body = encrypt_cbc(body, key, iv)
    cbc_output_path = "output_cbc.bmp"
    with open(cbc_output_path, "wb") as f:
        f.write(header + cbc_body)
    print(f"Saved: {cbc_output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python encrypt_bmp.py  [header_size]")
        sys.exit(1)

    file_path = sys.argv[1]
    hdr_size = int(sys.argv[2]) if len(sys.argv) > 2 else 54
    process_bmp(file_path, hdr_size)