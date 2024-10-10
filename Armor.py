import argparse
import marshal
import base64
import os
from cryptography.fernet import Fernet
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Util.Padding import pad, unpad

def generate_fernet_key():
    return Fernet.generate_key()

def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    encrypted_data, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(nonce + tag + encrypted_data)

def aes_decrypt(data, key):
    data = base64.b64decode(data)
    nonce = data[:16]
    tag = data[16:32]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(data[32:], tag)
    return decrypted_data

def fernet_encrypt(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data)

def fernet_decrypt(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data)

def compile_code(file_path):
    with open(file_path, 'r') as f:
        code = f.read()
    bytecode = compile(code, file_path, 'exec')
    return marshal.dumps(bytecode)

def obfuscate_code(file_path, layers):
    # Compile to bytecode and serialize
    serialized_bytecode = compile_code(file_path)
    
    # Encrypt with AES GCM
    aes_key = generate_aes_key()
    aes_encrypted = aes_encrypt(serialized_bytecode, aes_key)
    
    # Apply multiple layers of Fernet encryption
    fernet_keys = [generate_fernet_key() for _ in range(layers)]
    encrypted_bytecode = aes_encrypted
    for key in fernet_keys:
        encrypted_bytecode = fernet_encrypt(encrypted_bytecode, key)

    # Encode final encrypted bytecode
    base64_encoded = base64.b64encode(encrypted_bytecode).decode()
    hex_encoded = base64_encoded.encode('utf-8').hex()

    # Obfuscate keys
    obfuscated_keys = [base64.b64encode(key).decode().encode('utf-8').hex() for key in fernet_keys]
    aes_key_hex = aes_key.hex() 

    # Generate obfuscated code
    obfuscated_code = f"""
import base64 as b64, marshal as m
from cryptography.fernet import Fernet as F
from Cryptodome.Cipher import AES as A

def aes_decrypt(encrypted_data, aes_key):
    encrypted_data = b64.b64decode(encrypted_data)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    cipher = A.new(aes_key, A.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted_data[32:], tag)

def fernet_decrypt(encrypted_data, fernet_key):
    fernet = F(fernet_key)
    return fernet.decrypt(encrypted_data)

def decode_hex_string(hex_string):
    return bytes.fromhex(hex_string)

def execute_obfuscated_code():
    encoded_bytecode = '{hex_encoded}'
    obfuscated_keys = {obfuscated_keys}
    aes_key_hex = '{aes_key_hex}'
    aes_key = bytes.fromhex(aes_key_hex)

    encoded_data = decode_hex_string(encoded_bytecode)
    decrypted_data = b64.b64decode(encoded_data)
    
    # Decrypt with Fernet keys in reverse order
    for key in reversed([decode_hex_string(key) for key in obfuscated_keys]):
        decrypted_data = fernet_decrypt(decrypted_data, key)
    
    # Decrypt with AES
    final_data = aes_decrypt(decrypted_data, aes_key)
    
    # Load and execute bytecode
    bytecode = m.loads(final_data)
    exec(bytecode)

execute_obfuscated_code()
"""

    # Save obfuscated code to new file
    obfuscated_file_path = file_path.replace('.py', '_obfuscated.py')
    with open(obfuscated_file_path, 'w') as f:
        f.write(obfuscated_code)
    
    print(f"[+] Enhanced Python Obfuscator")
    print(f"[+] File obfuscated successfully -> {obfuscated_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enhanced Python Obfuscator')
    parser.add_argument('-f', '--file', type=str, required=True, help='File to obfuscate')
    parser.add_argument('-l', '--layers', type=int, default=4, help='Number of Fernet encryption layers (default: 4)')
    args = parser.parse_args()
    obfuscate_code(args.file, args.layers)
