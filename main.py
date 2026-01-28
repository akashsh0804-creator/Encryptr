from DES_module import DES
from AES_module import AES

#__________User input__________
def user_input(module_type):
    is_running = True
    input_string = input("Enter your text: ")
    print("Please select the type of key you want.")
        
    print("1. Use automatically generated key.\n"
          "2. Use password as a key.")

    if module_type == 'D':
        print("3. Create your own key(64 bits).")
            
        while is_running:

            try:
                key_select = int(input("Enter your choice(1, 2 or 3): "))
            
            except ValueError:
                print("Please enter a number.")
                continue
            
            if key_select == 1:
                key = DES.generate_key()
                is_running = False
            elif key_select == 2:
                password = input("Enter your password: ")
                key = DES.pass_to_key(password)
                is_running = False
            elif key_select == 3:
                key = input("Enter your key(64 bits): ")
                if len(key) < 64 :
                    print(f"Your key is only {len(key)} long. It should be exactly 64 bits long")
                elif len(key) > 64 :
                    print(f"Your key is {len(key)} long. It should be exactly 64 bits long")
                elif not set(key).issubset({"0", "1"}):
                    print("Key must contain only 0 and 1.")
                else :
                    key = DES.fix_key_parity(key)
                    is_running = False
            else:
                print("Invalid option!")
            
        return input_string, key
    
    elif module_type == 'A':
        
        while is_running:

            try:
                key_select = int(input("Enter your choice(1 or 2): "))
            
            except ValueError:
                print("Please enter a number.")
                continue

            #selection of AES type for correct key generation
            print("Which type of encryption do you want\n"
              "1. AES-128\n"
              "2. AES-192\n"
              "3. AES-256")

            try:
                aes_type = input("Enter your choice(1, 2 or 3): ")

            except ValueError:
                print("Please enter a number.")
                continue

            key_size_map = {
                '1':16,
                '2':24,
                '3':32
                }
            
            if aes_type not in key_size_map:
                print("Invalid AES type")
                continue

            key_size = key_size_map[aes_type]

            #key generation
            if key_select == 1:
                key = AES.generate_key(key_size)
                salt = None
                is_running = False
            elif key_select == 2:
                password = input("Enter your password: ")
                key, salt = AES.pass_to_key(password, key_size)
                is_running = False
            else:
                print("Invalid option!")
        
        return input_string, key, salt

#--------------------------------------------------------------------------------------------------------------
#__________DES function__________
def des():

    d = DES()
    
    print("__________________________________\n"
          "THIS IS DES MODULE\n"
          "What do you want to do?\n"
          "1. Encryption\n"
          "2. Decryption\n"
          "Press 'Q' to go back")
    choice = input("Enter your choice: ").upper()

    if choice == '1':
        #__________Encryption__________
        input_string, key = user_input('D')
        d.encrypt(input_string, key)
    elif choice == '2':
        #__________Decryption__________
        hex_cipher = input("Enter HEX ciphertext: ")
        key = input("Enter the key used(binary): ")
        d.decrypt(hex_cipher, key)
    elif choice == 'Q':
        return
    else:
        print("Invalid Option!")

#--------------------------------------------------------------------------------------------------------------
#__________3DES function__________
def des3():

    d = DES()

    print("__________________________________\n"
          "THIS IS 3DES MODULE\n"
          "What do you want to do?\n"
          "1. Encryption\n"
          "2. Decryption\n"
          "Press 'Q' to go back")
    choice = input("Enter your choice: ").upper()

    if choice == '1':
        #__________Encryption__________
        input_string = input("Enter your text: ")
        
        key1 = d.generate_key()
        key2 = d.generate_key()
        key3 = d.generate_key()

        blocks = DES.string_to_bits(input_string)

        cipher_blocks = []

        for block in blocks:
            b1 = d.encrypt_block_with_key(block, key1)
            b2 = d.decrypt_block_with_key(b1, key2)
            b3 = d.encrypt_block_with_key(b2, key3)

            cipher_blocks.append(b3)

        cipher_bits = ''.join(cipher_blocks)
        cipher_hex = DES.bits_to_hex(cipher_bits)

        print("_______________________________________")
        print("3DES Encryption Successful")
        print(f"3DES Ciphertext (HEX): {cipher_hex}")
        print(f"Key1: {key1}")
        print(f"Key2: {key2}")
        print(f"Key3: {key3}")

    elif choice == '2':
        #__________Decryption__________
        hex_ciphertext = input("Enter your HEX ciphertext: ")
        key1 = input("Enter Key1: ")
        key2 = input("Enter Key2: ")
        key3 = input("Enter Key3: ")

        for k in (key1, key2, key3):
            if len(k) != 64 or not set(k).issubset({'0', '1'}):
                raise ValueError("Each key must be a 64-bit binary string")

        cipher_bits = DES.hex_to_bits(hex_ciphertext)

        blocks = [cipher_bits[i:i+64] for i in range(0, len(cipher_bits), 64)]

        plain_bits = ''
        for block in blocks:
            b1 = d.decrypt_block_with_key(block, key3)
            b2 = d.encrypt_block_with_key(b1, key2)
            b3 = d.decrypt_block_with_key(b2, key1)

            plain_bits += b3

        plain_text = DES.bits_to_string(plain_bits)

        print("_____________________________________")
        print("3DES Decryption Successful")
        print(f"Decrypted text: {plain_text}")

    elif choice == 'Q':
        return

    else:
        print("Invalid Option!")

#--------------------------------------------------------------------------------------------------------------
#__________AES function__________
def aes():
    
    a = AES()

    print("__________________________________\n"
          "THIS IS AES MODULE\n"
          "What do you want to do?\n"
          "1. Encryption\n"
          "2. Decryption\n"
          "Press 'Q' to go back")
    choice = input("Enter your choice: ").upper()

    if choice == '1':
        #__________Encryption__________
        input_string, key, salt = user_input('A')
        a.encrypt(input_string, key, salt)
    elif choice == '2':
        #__________Decryption__________
        cipher_string = input("Enter Ciphertext: ")
        
        pass_val = input("Was your Key user defined?(Y/N): ").upper()
        
        if pass_val == 'Y':
            pass_based = True
            print("Which type of encryption did you used\n"
              "1. AES-128\n"
              "2. AES-192\n"
              "3. AES-256")
        
            key_size_map = {
                    '1':16,
                    '2':24,
                    '3':32
                    }
            
            aes_type = input("Enter your choice(1, 2 or 3): ")

            if aes_type not in key_size_map:
                print("Invalid AES type")
                return
            else:
                key_size = key_size_map[aes_type]

        elif pass_val == 'N':
            pass_based = False
            key_size = None
        else :
            print("Invalid option!")
            return
        
        key = input("Enter the key used: ")
        
        a.decrypt(cipher_string, key, key_size, pass_based)
    elif choice == 'Q':
        return
    else:
        print("Invalid Option!")
            
#--------------------------------------------------------------------------------------------------------------
#__________Main function__________
def main():
    is_running = True

    while is_running:
        print("__________________________________________________\n"
              "Select which type of encryption do you want. \n" 
              "Press '1' for DES\n" 
              "Press '2' for 3DES\n"
              "Press '3' for AES\n"
              "Press 'Q' to quit")
        choice = input("Enter your choice: ").upper()

        match choice:
            case '1':
                des()
            case '2':
                des3()
            case '3':
                aes()
            case 'Q':
                is_running = False
            case _:
                print("Invalid Option!")

#--------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    print("This is a text encryption tool 'ENCRYPTR'")
    main()
