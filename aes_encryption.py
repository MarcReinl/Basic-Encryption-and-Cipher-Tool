from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import os

def generate_salt():
    return get_random_bytes(16)

def derive_key_from_password(password, salt):
    return scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)

def encrypt_file(input_file: str, output_file: str, password: str, key_output_file: str):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    salt = generate_salt()
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Get the original file extension
    _, original_ext = os.path.splitext(input_file)
    output_file_path, _ = os.path.splitext(output_file)
    with open(output_file_path + original_ext, 'wb') as f:
        f.write(salt + cipher.nonce + tag + ciphertext)
    
    with open(key_output_file, 'w') as f:
        f.write(key.hex())

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # Get the original file extension
    _, original_ext = os.path.splitext(input_file)
    output_file_path, _ = os.path.splitext(output_file)
    with open(output_file_path + original_ext, 'wb') as f:
        f.write(data)

def decrypt_file_with_key(input_file: str, output_file: str, key_file: str):
    with open(key_file, 'r') as kf:
        key = bytes.fromhex(kf.read().strip())

    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Get the original file extension
    _, original_ext = os.path.splitext(input_file)
    output_file_path, _ = os.path.splitext(output_file)
    with open(output_file_path + original_ext, 'wb') as f:
        f.write(data)