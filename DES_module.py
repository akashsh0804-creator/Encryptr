import random as rd

class DES:
    #__________Conversion of the text and padding the bits__________
    @staticmethod
    def string_to_bits(text):
            
        #convert text to bits
        data = text.encode('utf-8')
        padded = DES.pkcs7_pad(data)
        bits = ''.join(format(byte, '08b') for byte in padded)
            
        #slices string to 64 bits
        blocks = []
        for i in range(0, len(bits), 64):
            block = bits[i:i+64]

            blocks.append(block)
        return blocks
    
    #__________Conversion of bits to text__________ 
    @staticmethod 
    def bits_to_string(bits): 
        chars = bytes(
            int(bits[i:i+8],2)
            for i in range(0,len(bits),8)
        )

        unpadded = DES.pkcs7_unpad(chars)

        return unpadded.decode('utf-8')

    #__________Conversion of bits to hex__________
    @staticmethod
    def bits_to_hex(bits):
        return ''.join(format(int(bits[i:i+4], 2), 'X') for i in range(0, len(bits), 4))

    #__________Conversion of hex to bits__________
    @staticmethod
    def hex_to_bits(hex_string):
        return ''.join(format(int(c, 16), '04b') for c in hex_string)
    
    #__________Padding/Unpadding with PKCS#7__________
    @staticmethod
    def pkcs7_pad(data_bytes, block_size=8):
        pad_len = block_size - (len(data_bytes) % block_size)
        return data_bytes + bytes([pad_len] * pad_len)

    @staticmethod
    def pkcs7_unpad(data_bytes):
        pad_len = data_bytes[-1]
        if pad_len < 1 or pad_len > 8:
            raise ValueError("Invalid PKCS#7 padding")
        return data_bytes[:-pad_len]


    #___________Permutation bits__________
    @staticmethod
    def permute(bits, table):
        return ''.join(bits[i - 1] for i in table)
    
    #__________Left circular shift__________
    @staticmethod
    def left_shift(bits, n):
        return bits[n:] + bits[:n]
    
    #__________Keys generation__________
    #__________For option 1__________
    @staticmethod
    def generate_key():
        key_56 = ''.join(str(rd.randint(0,1)) for i in range(56))

        key_64 = ""
        for i in range(0,56,7):
            seven_bits = key_56[i:i+7]
            parity_bit = "1" if seven_bits.count("1") % 2 == 0 else "0"
            key_64 += seven_bits + parity_bit
            
        return key_64

    #__________For option 2__________
    @staticmethod
    def pass_to_key(password):
        password = password.ljust(8, '\x00')[:8]  # make exactly 8 chars
        bits = ''.join(format(b, '08b') for b in password.encode('utf-8'))  # 64 bits

        # Insert parity every 7 bits
        key = ""
        for i in range(0, 64, 8):
            seven_bits = bits[i:i+7]
            parity_bit = "1" if seven_bits.count("1") % 2 == 0 else "0"
            key += seven_bits + parity_bit
        return key
    
    #__________For option 3__________
    @staticmethod
    def fix_key_parity(key64):
        fixed_key = ""
        for i in range(0, 64, 8):
            seven_bits = key64[i:i+7]
            parity_bit = "1" if seven_bits.count("1") % 2 == 0 else "0"
            fixed_key += seven_bits + parity_bit
        return fixed_key

    #--------------------------------------------------------------------------------------------------------------
    def __init__(self, key= None):
        #__________DES tables__________
        #__________Initial permutation table__________
        self.ip_table = [
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
        ]

        self.ip_inv_table = [
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25
        ]

                        
        #__________PC-1 (64-bit → 56-bit)__________
        self.pc1_table = [
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        ]

        #__________PC-2 (56-bit → 48-bit subkey)__________-
        self.pc2_table = [
            14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
        ]

        #__________Left shifts for each round__________
        self.shift_schedule = [
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        ]

        #__________Expansion table (32 -> 48 bits)__________
        self.expansion_table = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1
        ]

        #__________S boxes__________
        self.s_boxes = [
            # S1
            [
                [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
                [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
                [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
                [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
            ],
            # S2
            [
                [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
                [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
                [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
                [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
            ],
            # S3
            [
                [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
                [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
                [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
                [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
            ],
            # S4
            [
                [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
                [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
                [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
                [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
            ],
            # S5
            [
                [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
                [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
                [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0],
                [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
            ],
            # S6
            [
                [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
                [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
                [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
                [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
            ],
            # S7
            [
                [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
                [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
                [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
                [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
            ],
            # S8
            [
                [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
                [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
                [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
                [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
            ]
        ]

    #__________P-box permutation (32 bits)__________
    p_table = [
        16,7,20,21,
        29,12,28,17,
        1,15,23,26,
        5,18,31,10,
        2,8,24,14,
        32,27,3,9,
        19,13,30,6,
        22,11,4,25
    ]

    #--------------------------------------------------------------------------------------------------------------
    #__________DES key schedule__________
    def generate_round_keys(self, key):
        key56 = ''.join(key[i - 1] for i in self.pc1_table) #PC!: 64-bit → 56-bit

        c = key56[:28]
        d = key56[28:]

        round_keys = []

        for shift in self.shift_schedule:
            c = self.left_shift(c, shift)
            d = self.left_shift(d,shift)
                
            cd = c + d
            round_keys.append(DES.permute(cd, self.pc2_table)) #Creates 56 bits to 48 bits
            
        return round_keys

    #__________Round functiom__________
    def round_function(self, R, key):
        expanded_R = DES.permute(R, self.expansion_table)

        xor_result = ''.join(str(int(expanded_R[i]) ^ int(key[i])) for i in range(48))

        sbox_output = ""

        for i in range(8):
            block6 = xor_result[i*6:(i+1)*6]
            row = int(block6[0] + block6[5], 2)
            col = int(block6[1:5], 2)
            val = self.s_boxes[i][row][col]
            sbox_output += format(val, "04b")

        return DES.permute(sbox_output, self.p_table)
    
    #__________Encrytion over one block__________
    def des_encrypt_block(self, block, round_keys):
        block = DES.permute(block, self.ip_table)
        L = block[:32]
        R = block[32:]

        for i in range(16):
            F_out = self.round_function(R, round_keys[i])
            new_R = ''.join(str(int(L[j]) ^ int(F_out[j])) for j in range(32))
            L, R = R, new_R
            
        final_block = R + L
        return DES.permute(final_block, self.ip_inv_table)
    
    #__________Encryption__________
    def encrypt(self, input_string, key):
        round_keys = self.generate_round_keys(key)
        blocks = DES.string_to_bits(input_string)

        cipher_blocks = [self.des_encrypt_block(block, round_keys) for block in blocks]
        cipher_bits = ''.join(cipher_blocks)
        cipher_hex = DES.bits_to_hex(cipher_bits)

        print(f"Your Encrypted text is: {cipher_hex}")
        print(f"Key used (binary): {key}")

    #__________Decryption__________
    def decrypt(self, hex_ciphertext, key):
        round_keys = self.generate_round_keys(key)
        round_keys.reverse()

        cipher_bits = DES.hex_to_bits(hex_ciphertext)

        blocks = [cipher_bits[i:i+64] for i in range(0, len(cipher_bits), 64)]

        plain_bits = ""
        for block in blocks:
            plain_bits += self.des_encrypt_block(block, round_keys)
            
        plain_text = DES.bits_to_string(plain_bits)
        
        print(f"Decrypted text: {plain_text}")

    #--------------------------------------------------------------------------------------------------------------
    #__________3DES Encryption__________
    def encrypt_block_with_key(self, block, key):
        round_keys = self.generate_round_keys(key)
        return self.des_encrypt_block(block, round_keys)
    
    #__________3DES Decryption__________
    def decrypt_block_with_key(self, block, key):
        round_keys = self.generate_round_keys(key)
        round_keys.reverse()
        return self.des_encrypt_block(block, round_keys)
