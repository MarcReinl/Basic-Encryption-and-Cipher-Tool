# caesar_cipher.py


def encrypt_caesar(plaintext: str, shift: int) -> str:
    """Encrypt the plaintext using Caesar Cipher with the given shift."""
    encrypted_text = []
    for char in plaintext:
        if char.isalpha():  # Check if character is a letter
            shift_amount = shift % 26
            # Determine if the character is uppercase or lowercase
            base = ord("A") if char.isupper() else ord("a")
            # Perform the shift
            encrypted_char = chr((ord(char) - base + shift_amount) % 26 + base)
            encrypted_text.append(encrypted_char)
        else:
            # Non-alphabetic characters are added unchanged
            encrypted_text.append(char)
    return "".join(encrypted_text)


def decrypt_caesar(ciphertext: str, shift: int) -> str:
    """Decrypt the ciphertext using Caesar Cipher with the given shift."""
    # Decryption is just the inverse operation of encryption
    return encrypt_caesar(ciphertext, -shift)
