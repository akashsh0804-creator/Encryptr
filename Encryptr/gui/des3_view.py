import customtkinter as ctk
from controller import des3_encrypt, des3_decrypt

class DES3View(ctk.CTkFrame):
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

        self.pass1_inputbox = ctk.CTkEntry(
            self,
            show="*",
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            font=("Arial",20),
            placeholder_text="Enter your 1st key here...",
            placeholder_text_color="#888888"
        )
        self.pass1_inputbox.place(
            relx=0,
            rely=0.47,
            anchor="w",
            relwidth=0.33,
            relheight=0.13
        )
        self.pass2_inputbox = ctk.CTkEntry(
            self,
            show="*",
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            font=("Arial",20),
            placeholder_text="Enter your 2nd key here...",
            placeholder_text_color="#888888"
        )
        self.pass2_inputbox.place(
            relx=0.5,
            rely=0.47,
            anchor="center",
            relwidth=0.33,
            relheight=0.13
        )
        self.pass3_inputbox = ctk.CTkEntry(
            self,
            show="*",
            corner_radius=8,
            fg_color="#EDE0D4",
            text_color="#69433A",
            font=("Arial",20),
            placeholder_text="Enter your 3rd key here...",
            placeholder_text_color="#888888"
        )
        self.pass3_inputbox.place(
            relx=1,
            rely=0.47,
            anchor="e",
            relwidth=0.33,
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

        if text == self.placeholder:
            text = ""

        if not text:
            self.set_output("Please enter plaintext.")
            return
        
        result = des3_encrypt(
            plaintext=text
        )

        output_text = f"Ciphertext:\n{result['ciphertext']}\n\n"

        if result.get("key1"):
            output_text += f"Key1:\n{result['key1']}\n"
        if result.get("key2"):
            output_text += f"Key2:\n{result['key2']}\n"
        if result.get("key3"):
            output_text += f"Key3:\n{result['key3']}\n"

        self.set_output(output_text)

    # ---------- DECRYPTION ----------
    def decrypt_action(self):
        text = self.inputbox.get("1.0", "end").strip()
        user_key1 = self.pass1_inputbox.get()
        user_key2 = self.pass2_inputbox.get()
        user_key3 = self.pass3_inputbox.get()

        if text == self.placeholder:
            text = ""

        if not text:
            self.set_output("Please enter ciphertext.")
            return

        try:
            if user_key1 and user_key2 and user_key3:
                result = des3_decrypt(
                    ciphertext=text,
                    key1=user_key1,
                    key2=user_key2,
                    key3=user_key3
                )
            else:
                output_text = ""

                if not user_key1:
                    output_text += "Enter 1st key\n"
                
                if not user_key2:
                    output_text += "Enter 2nd key\n"

                if not user_key3:
                    output_text += "Enter 3rd key\n"

                self.set_output(output_text)
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
