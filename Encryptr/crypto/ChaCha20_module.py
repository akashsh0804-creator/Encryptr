from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

class ChaCha20:
    #__________Conversion of string to bytes__________
    @staticmethod
    def strings_to_bytes(input_string):
        return input_string.encode('utf-8')
    
    #__________Conversion of bytes to string__________
    @staticmethod
    def bytes_to_strings(encoded_bytes):
        return encoded_bytes.decode('utf-8')
    
    #--------------------------------------------------------------------------------------------------------------
    #__________Keys generation__________
    #__________For option 1__________
    @staticmethod
    def generate_key():
        return os.urandom(32)

    #__________For option 2__________
    @staticmethod
    def derive_key(password, salt):
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(algorithm= hashes.SHA256(),
                         length= 32,
                         salt= salt,
                         iterations= 200_000)
        return kdf.derive(password_bytes)
    
    @staticmethod
    def pass_to_key(password):
        salt = os.urandom(16)
        key = ChaCha20.derive_key(password, salt)
        return key, salt

    #--------------------------------------------------------------------------------------------------------------
    #__________Encryption__________
    def encrypt(self, input_string, key, salt):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20")

        data_bytes = ChaCha20.strings_to_bytes(input_string)
        nonce = os.urandom(12)
        
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(
            nonce= nonce,
            data= data_bytes,
            associated_data= None
        )

        if salt is not None:
            blob = salt + nonce + ciphertext
        else:
            blob = nonce + ciphertext

        return base64.b64encode(blob).decode('utf-8')

    #__________Decryption__________
    def decrypt(self, cipher_string, key, pass_based= False):
        data = base64.b64decode(cipher_string)

        if pass_based:
            salt = data[:16]
            nonce = data[16:28]
            ciphertext = data[28:]

            key = ChaCha20.derive_key(key, salt)
        else:
            nonce = data[:12]
            ciphertext = data[12:]
            key = key
        
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20")

        chacha = ChaCha20Poly1305(key)

        try:
            plaintext_bytes = chacha.decrypt(
                nonce= nonce,
                data= ciphertext,
                associated_data= None
            )

        except Exception:
            raise ValueError("Decryption failed: wrong key or corrupted data")
        
        return self.bytes_to_strings(plaintext_bytes)
