import customtkinter as ctk
from controller import chacha_encrypt, chacha_decrypt

class ChaCha20View(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent", corner_radius=20)
        self.pack(fill= "both", expand= True, padx=20, pady=20)

        # ---------- INPUT BOX ----------
        self.inputbox = ctk.CTkTextbox(
            self,
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            font=("Arial",20),
            border_width=2,
            border_color="#5C5C5C"
            )
        self.inputbox.place(
            relx=0.33,
            rely=0.19,
            anchor="center",
            relwidth=0.65,
            relheight=0.35
        )

        self.placeholder = "Enter your Plain/Encrypted text here..."
        self.inputbox.insert("1.0", self.placeholder)
        self.inputbox.configure(text_color="#888888")
        self.inputbox.bind("<FocusIn>", self.clear_placeholder)
        self.inputbox.bind("<FocusOut>", self.add_placeholder)

        self.pass_inputbox = ctk.CTkEntry(
            self,
            show="*",
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            font=("Arial",20),
            placeholder_text="Enter your password here...",
            placeholder_text_color="#888888"
        )
        self.pass_inputbox.place(
            relx=0.33,
            rely=0.47,
            anchor="center",
            relwidth=0.65,
            relheight=0.13
        )

        # ---------- BUTTONS ----------
        self.encrypt = ctk.CTkButton(
            self,
            corner_radius=8,
            fg_color="#38b000",
            hover_color="#007200",
            text="Encrypt",
            text_color="#212529",
            font=("Arial", 13),
            command=self.encrypt_action
            )
        self.encrypt.place(
            relx=1,
            rely=0.08,
            anchor="e",
            relwidth=0.33,
            relheight=0.13
        )

        self.decrypt = ctk.CTkButton(
            self,
            corner_radius=8,
            fg_color="#ED254E",
            hover_color="#9B2226",
            text="Decrypt",
            text_color="#212529",
            font=("Arial", 13),
            command=self.decrypt_action
            )
        self.decrypt.place(
            relx=1,
            rely=0.28,
            anchor="e",
            relwidth=0.33,
            relheight=0.13
        )

        # ---------- OUTPUT BOX ----------
        self.outputbox = ctk.CTkTextbox(
            self,
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            border_width=2,
            border_color="#5C5C5C",
            font=("Arial",20),
            state="disabled"
            )
        self.outputbox.place(
            relx=0.5,
            rely=0.8,
            anchor="center",
            relwidth=1,
            relheight=0.4
        )

    # ---------- ENCRYPTION ----------
    def encrypt_action(self):
        text = self.inputbox.get("1.0", "end").strip()
        key_or_password = self.pass_inputbox.get()

        if text == self.placeholder:
            text = ""

        if not text:
            self.set_output("Please enter plaintext.")
            return
        
        result = chacha_encrypt(
            plaintext=text,
            password=key_or_password if key_or_password else None
        )

        output_text = f"Ciphertext:\n{result['ciphertext']}\n\n"

        if result.get("key"):
            output_text += f"Key:\n{result['key']}\n"

        self.set_output(output_text)

    # ---------- DECRYPTION ----------
    def decrypt_action(self):
        text = self.inputbox.get("1.0", "end").strip()
        user_key = self.pass_inputbox.get()

        if text == self.placeholder:
            text = ""

        if not text:
            self.set_output("Please enter ciphertext.")
            return

        try:
            if user_key:
                if user_key and user_key.endswith("CHKY"):
                    result = chacha_decrypt(
                        ciphertext=text,
                        password=None,
                        key_b64=user_key[:-4]
                    )
                else:
                    result = chacha_decrypt(
                        ciphertext=text,
                        password=user_key,
                        key_b64=None
                    )
            else:
                self.set_output("Enter password or key")
                return
            
            self.set_output(f"Plaintext:\n{result}")

        except Exception as e:
            self.set_output(f"Error:\n{str(e)}")

    # ---------- SETTING OUTPUT ----------
    def set_output(self, text):
        self.outputbox.configure(state="normal")
        self.outputbox.delete("1.0","end")
        self.outputbox.insert("end", text)
        self.outputbox.configure(state="disabled")

    # ---------- DECORATION ----------
    def clear_placeholder(self, event):
        current_text = self.inputbox.get("1.0", "end").strip()

        if current_text == self.placeholder:
            self.inputbox.delete("1.0", "end")
            self.inputbox.configure(text_color="#69433A")  # normal color


    def add_placeholder(self, event):
        current_text = self.inputbox.get("1.0", "end").strip()

        if not current_text:
            self.inputbox.insert("1.0", self.placeholder)
            self.inputbox.configure(text_color="#888888")
