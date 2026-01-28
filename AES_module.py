from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

class AES:
    #__________Conversion of string to bytes__________
    @staticmethod
    def strings_to_bytes(input_string):
        encoded_bytes = input_string.encode('utf-8')
        return encoded_bytes
    
    #__________Conversion of bytes to string__________
    @staticmethod
    def bytes_to_strings(encoded_bytes):
        decoded_bytes = encoded_bytes.decode('utf-8')
        return decoded_bytes
    
    #--------------------------------------------------------------------------------------------------------------
    #__________Keys generation__________
    #__________For option 1__________
    @staticmethod
    def generate_key(key_size):
        key = os.urandom(key_size)
        return key

    #__________For option 2__________
    @staticmethod
    def derive_key(password, key_size, salt):
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(algorithm= hashes.SHA256(),
                         length= key_size,
                         salt= salt,
                         iterations= 200000)
        key = kdf.derive(password_bytes)
        return key
    
    @staticmethod
    def pass_to_key(password, key_size):
        salt = os.urandom(16)
        key = AES.derive_key(password, key_size, salt)
        return key, salt

    #--------------------------------------------------------------------------------------------------------------
    #__________Encryption__________
    def encrypt(self, input_string, key, salt):
        data_bytes = AES.strings_to_bytes(input_string)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(
            nonce= nonce,
            data= data_bytes,
            associated_data= None
        )

        if salt:
            blob = salt + nonce + ciphertext
        else:
            blob = nonce + ciphertext

        encoded_text = base64.b64encode(blob).decode('utf-8')

        print("______________________________________")
        print("AES Encryption Successful")
        print(f"Your Encrypted text is: {encoded_text}")

        key_b64 = base64.b64encode(key).decode('utf-8')
    
        if salt is None:
            print(f"Key (base64): {key_b64}")
        else:
            print("Key derived from password (not displayed)")

        return encoded_text

    #__________Decryption__________
    def decrypt(self, cipher_string, key_input, key_size, pass_based= False):
        data = base64.b64decode(cipher_string)

        if pass_based == True:
            salt = data[:16]
            nonce = data[16:28]
            ciphertext = data[28:]

            key = AES.derive_key(key_input, key_size, salt)
        else:
            nonce = data[:12]
            ciphertext = data[12:]
            key = key_input
        
        aesgcm = AESGCM(key)

        plaintext_bytes = aesgcm.decrypt(
            nonce= nonce,
            data= ciphertext,
            associated_data= None
        )

        plaintext = AES.bytes_to_strings(plaintext_bytes)
        
        print("_______________________________________")
        print("AES Decryption Successful")
        print(f"Decryted text: {plaintext}")
