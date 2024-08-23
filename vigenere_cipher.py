def encrypt_vigenere(plaintext: str, keyword: str) -> str:
    """Encrypt the plaintext using Vigenère Cipher with the given keyword."""
    encrypted_text = []
    keyword_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)].upper()) - ord("A")
            base = ord("A") if char.isupper() else ord("a")
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted_text.append(encrypted_char)
            keyword_index += 1
        else:
            encrypted_text.append(char)

    return "".join(encrypted_text)


def decrypt_vigenere(ciphertext: str, keyword: str) -> str:
    """Decrypt the ciphertext using Vigenère Cipher with the given keyword."""
    decrypted_text = []
    keyword_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)].upper()) - ord("A")
            base = ord("A") if char.isupper() else ord("a")
            decrypted_char = chr((ord(char) - base - shift + 26) % 26 + base)
            decrypted_text.append(decrypted_char)
            keyword_index += 1
        else:
            decrypted_text.append(char)

    return "".join(decrypted_text)
