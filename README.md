# Encryption Tool

This project is a collection of encryption tools implemented in Python, including AES, Caesar Cipher, Vigenere Cipher, and RSA encryption.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the necessary dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Each encryption script can be used individually, or you can use the provided GUI tool.

### AES Encryption
- Encrypt: `encrypt_file('input.txt', 'output.enc', 'password')`
- Decrypt: `decrypt_file('input.enc', 'output.txt', 'password')`

### Caesar Cipher
- Encrypt: `encrypt_caesar('plaintext', shift=3)`
- Decrypt: `decrypt_caesar('ciphertext', shift=3)`

### Vigenere Cipher
- Encrypt: `encrypt_vigenere('plaintext', 'key')`
- Decrypt: `decrypt_vigenere('ciphertext', 'key')`

### RSA Encryption
- Generate Keys: `generate_rsa_keys()`
- Encrypt: `rsa_encrypt(public_key, 'plaintext')`
- Decrypt: `rsa_decrypt(private_key, 'ciphertext')`

### GUI Tool
- Run the GUI: `python encryption_tool_gui.py`

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
