# File Encryption and Decryption

This Python application allows you to encrypt and decrypt files using various encryption algorithms such as AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman). It demonstrates the basics of file encryption and decryption using both symmetric and asymmetric encryption.

## Features

- **Symmetric Encryption (AES):** Encrypt and decrypt files using a password.
- **Asymmetric Encryption (RSA):** Encrypt files using a public key and decrypt files using a private key.
- **Key Generation:** Generate RSA public and private keys.

## Requirements

- Python 3.x
- `cryptography` library
- `pycryptodome` library

## Installation

1. **Clone the repository:**

    ```bash
   git clone https://github.com/Damilola-Yinusa/Data-Encryption-and-Decryption.git
    
   cd file-encryption-decryption
             
Set up a virtual environment (optional but recommended):

     ```bash
     python -m venv venv
     
   
On Windows:

      ```bash
     venv\Scripts\activate   

On macOS/Linux:

  ```bash
    source venv/bin/activate
     ```

Install the required libraries:

```bash
    pip install cryptography pycryptodome

     ```


Usage
Generate RSA Keys
To generate RSA public and private keys:

```bash
python Data-Encryption-and-Decryption.py generate_rsa_keys
      ```
This will create private.pem and public.pem files in your current directory.

Encrypt a File
AES Encryption:

```bash
python Data-Encryption-and-Decryption.py encrypt aes path/to/your/file.txt --password your_password

      ```
RSA Encryption:

```bash
python Data-Encryption-and-Decryption.py encrypt rsa path/to/your/file.txt --key path/to/public.pem
      ```
Decrypt a File
AES Decryption:

```bash
python Data-Encryption-and-Decryption.py decrypt aes path/to/your/file.txt.enc --password your_password
      ```
RSA Decryption:

```bash
python Data-Encryption-and-Decryption.py decrypt rsa path/to/your/file.txt.enc --key path/to/private.pe
      ```


Arguments
mode: Mode of operation, either encrypt or decrypt.
algorithm: Encryption algorithm to use, either aes or rsa.
file_path: Path to the file to be encrypted/decrypted.
--password: Password for AES encryption/decryption.
--key: Path to the RSA key (public key for encryption, private key for decryption).

