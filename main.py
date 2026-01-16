from DES_module import DES

#__________DES function__________
def des():
    
    print("What do you want to do?")
    print("1. Encryption")
    print("2. Decryption")
    choice = input("Enter your choice: ")

    if choice == '1':
        text, key = DES.user_input()
        d = DES()
        d.encrypt(text, key)
    elif choice == '2':
        hex_cipher = input("Enter HEX ciphertext: ")
        key = input("Enter the key used(binary): ")
        d = DES()
        d.decrypt(hex_cipher, key)
    else:
        print("Invalid Option!")

#--------------------------------------------------------------------------------------------------------------
#__________Main function__________
def main():
    is_running = True

    while is_running:
        print("Select which type of encryption do you want. \n" \
        "Press '1' for DES\n" \
        "Press 'Q' to quit")
        choice = input("Enter your choice: ").upper()

        if  choice == '1':
            des()
        elif choice == 'Q':
            is_running = False
        else:
            print("Invalid Option!")

if __name__ == '__main__':
    print("This is a text encryption tool 'ENCRYPTR'")
    main()
