import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    
    public_key = key.publickey().export_key()
    with open("public.pem", "wb") as f:
        f.write(public_key)
    
    print("RSA keys generated successfully!")

def encrypt_file_aes(file_path, password):
    backend = default_backend()
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        data = f.read()
        
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print("File encrypted successfully!")

def decrypt_file_aes(file_path, password):
    backend = default_backend()
    
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(data)

    print("File decrypted successfully!")

def encrypt_file_rsa(file_path, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    with open(file_path, 'rb') as f:
        data = f.read()
        
    encrypted_data = cipher_rsa.encrypt(data)
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)
    
    print("File encrypted successfully!")

def decrypt_file_rsa(file_path, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
        
    data = cipher_rsa.decrypt(encrypted_data)
    
    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(data)
    
    print("File decrypted successfully!")

def main():
    parser = argparse.ArgumentParser(description="Encrypt and decrypt files using AES and RSA")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("algorithm", choices=["aes", "rsa"], help="Algorithm: aes or rsa")
    parser.add_argument("file_path", help="Path to the file")
    parser.add_argument("--password", help="Password for AES encryption/decryption")
    parser.add_argument("--key", help="Path to the RSA key (public for encryption, private for decryption)")

    args = parser.parse_args()

    if args.algorithm == "aes":
        if not args.password:
            print("Password is required for AES encryption/decryption")
            return

        if args.mode == "encrypt":
            encrypt_file_aes(args.file_path, args.password)
        else:
            decrypt_file_aes(args.file_path, args.password)

    elif args.algorithm == "rsa":
        if not args.key:
            print("Key path is required for RSA encryption/decryption")
            return

        if args.mode == "encrypt":
            encrypt_file_rsa(args.file_path, args.key)
        else:
            decrypt_file_rsa(args.file_path, args.key)

if __name__ == "__main__":
    main()
