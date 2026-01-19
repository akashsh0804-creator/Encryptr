from DES_module import DES

#__________DES function__________
#__________User input__________
def user_input():
    is_running = True
    input_string = input("Enter your text: ")
    print("Please select the type of key you want.")
        
    print("1. Use automatically generated key.")
    print("2. Use password as a key.")
    print("3. Create your own key(64 bits).")
        
    while is_running:

        try:
            key_select = int(input("Enter your choice(1, 2, or 3): "))
        
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
                print(f"Your key is only {len(key)} long. It should be 64 bits long")
            elif len(key) > 64 :
                print(f"Your key is only {len(key)} long. It should be 64 bits long")
            elif not set(key).issubset({"0", "1"}):
                print("Key must contain only 0 and 1.")
            else :
                key = DES.fix_key_parity(key)
                is_running = False
        else:
            print("Invalid option!")
        
    return input_string, key


#__________DES function__________
def des():
    
    print("What do you want to do?")
    print("1. Encryption")
    print("2. Decryption")
    choice = input("Enter your choice: ")

    if choice == '1':
        input_string, key = user_input()
        d = DES()
        d.encrypt(input_string, key)
    elif choice == '2':
        hex_cipher = input("Enter HEX ciphertext: ")
        key = input("Enter the key used(binary): ")
        d = DES()
        d.decrypt(hex_cipher, key)
    else:
        print("Invalid Option!")

#__________3DES function__________
def des3():

    print("What do you want to do?")
    print("1. Encryption")
    print("2. Decryption")
    choice = input("Enter your choice: ")

    if choice == '1':
        d = DES()

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

        print(f"3DES Ciphertext (HEX): {cipher_hex}")
        print(f"Key1: {key1}")
        print(f"Key2: {key2}")
        print(f"Key3: {key3}")

    elif choice == '2':
        d = DES()

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

        print(f"Decrypted text: {plain_text}")

    else:
        print("Invalid Option!")
            
#--------------------------------------------------------------------------------------------------------------
#__________Main function__________
def main():
    is_running = True

    while is_running:
        print("Select which type of encryption do you want. \n" 
        "Press '1' for DES\n" 
        "Press '2' for 3DES\n"
        "Press 'Q' to quit")
        choice = input("Enter your choice: ").upper()

        if  choice == '1':
            des()
        elif choice == '2':
            des3()
        elif choice == 'Q':
            is_running = False
        else:
            print("Invalid Option!")

if __name__ == '__main__':
    print("This is a text encryption tool 'ENCRYPTR'")
    main()
