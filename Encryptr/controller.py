from crypto.DES_module import DES
from crypto.AES_module import AES
import base64

#--------------------------------------------------------------------------------------------------------------
#__________DES function__________
#__________Encryption__________
def des_encrypt(plaintext, key= None):
    des = DES()

    key = prepare_des_key(key)

    return{
        "ciphertext": des.encrypt(plaintext, key),
        "key": key
    } 

#__________Decryption__________
def des_decrypt(ciphertext, key):
    des = DES()

    key = prepare_des_key(key)

    return des.decrypt(ciphertext, key)

#__________DES key generation function__________
def prepare_des_key(user_input):
    if user_input is None:
        return DES.generate_key()

    if len(user_input) == 64 and set(user_input).issubset({'0','1'}):
        return DES.fix_key_parity(user_input)

    return DES.pass_to_key(user_input)


#--------------------------------------------------------------------------------------------------------------
#__________3DES function__________
#__________Encryption__________
def des3_encrypt(plaintext):
    des = DES()

    key1 = des.generate_key()
    key2 = des.generate_key()
    key3 = des.generate_key()

    blocks = DES.string_to_bits(plaintext)

    cipher_blocks = []

    for block in blocks:
        b1 = des.encrypt_block_with_key(block, key1)
        b2 = des.decrypt_block_with_key(b1, key2)
        b3 = des.encrypt_block_with_key(b2, key3)

        cipher_blocks.append(b3)

    cipher_bits = ''.join(cipher_blocks)
    cipher_hex = DES.bits_to_hex(cipher_bits)

    return{
        "ciphertext": cipher_hex,
        "key1": key1,
        "key2": key2,
        "key3": key3
    }

#__________Decryption__________
def des3_decrypt(ciphertext, key1, key2, key3):
    des = DES()
    
    for k in (key1, key2, key3):
            if len(k) != 64 or not set(k).issubset({'0', '1'}):
                raise ValueError("Each key must be a 64-bit binary string")
            
    cipher_bits = DES.hex_to_bits(ciphertext)

    blocks = [cipher_bits[i:i+64] for i in range(0, len(cipher_bits), 64)]

    plain_bits = ''
    for block in blocks:
        b1 = des.decrypt_block_with_key(block, key3)
        b2 = des.encrypt_block_with_key(b1, key2)
        b3 = des.decrypt_block_with_key(b2, key1)

        plain_bits += b3

    plaintext = DES.bits_to_string(plain_bits)

    return plaintext

#--------------------------------------------------------------------------------------------------------------
#__________AES function__________
#__________Encryption__________
def aes_encrypt(plaintext, mode, password= None):
    aes = AES()

    key_size_map = {
        128:16,
        192:24,
        256:32
        }
    
    key_size = key_size_map[mode]

    if password:
        key, salt = AES.pass_to_key(password, key_size)
    else:
        key = AES.generate_key(key_size)
        salt = None

    ciphertext = aes.encrypt(plaintext, key, salt)

    return{
        "ciphertext": ciphertext,
        "key": None if password else base64.b64encode(key).decode(),
        "salt": base64.b64encode(salt).decode() if salt else None,
        "mode": f"AES-{mode}"
    }

#__________Decryption__________
def aes_decrypt(ciphertext, mode, password= None, key_b64= None):
    aes = AES()

    key_size_map = {
        128:16,
        192:24,
        256:32
        }
    
    key_size = key_size_map[mode]
    
    if password:
        plaintext = aes.decrypt(ciphertext, password, key_size, pass_based= True)

    else:
        key = base64.b64decode(key_b64)
        plaintext = aes.decrypt(ciphertext, key, key_size, pass_based= False)

    return plaintext
