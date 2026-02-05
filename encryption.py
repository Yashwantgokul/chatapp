'''This module handles the end-to-end encryption and decryption of messages.'''
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# For demonstration purposes, we'll use a fixed key. 
# In a real application, this key would need to be securely shared 
# between the communicating users.
AES_KEY = os.environ.get("AES_KEY", "a_default_secret_key_that_is_32b").encode()

def encrypt_message(plaintext: str, key: bytes) -> tuple[str, str]:
    '''Encrypts a message using AES-GCM.

    Args:
        plaintext: The message to encrypt.
        key: The encryption key.

    Returns:
        A tuple containing the base64-encoded ciphertext and nonce (IV).
    '''
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    # The nonce is the same as the IV for GCM mode
    nonce = cipher.nonce
    # We'll also include the auth tag with the ciphertext for integrity checking
    encrypted_data = ciphertext + tag
    return b64encode(encrypted_data).decode('utf-8'), b64encode(nonce).decode('utf-8')

def decrypt_message(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    '''Decrypts a message using AES-GCM.

    Args:
        ciphertext_b64: The base64-encoded ciphertext.
        nonce_b64: The base64-encoded nonce (IV).
        key: The decryption key.

    Returns:
        The decrypted plaintext message, or "[Undecipherable]" if decryption fails.
    '''
    try:
        encrypted_data = b64decode(ciphertext_b64)
        nonce = b64decode(nonce_b64)

        # The tag is the last 16 bytes of the encrypted data
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError):
        # Decryption failed (e.g., wrong key, tampered message)
        return "[Undecipherable]"

