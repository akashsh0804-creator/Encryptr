import customtkinter as ctk
from controller import aes_encrypt, aes_decrypt

class AESView(ctk.CTkFrame):
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

        self.mode_selector = ctk.CTkSegmentedButton(
            self,
            values=["128", "192", "256"],
            corner_radius=8,
            fg_color="#679499",
            selected_color="#00b4d8",
            selected_hover_color="#07beb8",
            unselected_color="#80ced7",
            unselected_hover_color="#3dccc7",
            text_color="#212529",
            font=("Arial", 13)
        )
        self.mode_selector.place(
            relx=1,
            rely=0.47,
            anchor="e",
            relwidth=0.33,
            relheight=0.13
        )
        self.mode_selector.set("256")

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
        
        result = aes_encrypt(
            plaintext=text,
            password=key_or_password if key_or_password else None,
            mode=self.get_mode()
        )

        output_text = f"Ciphertext:\n{result['ciphertext']}\n\n"

        if result.get("key"):
            output_text += f"Key:\n{result['key']}\n"

        if result.get("salt"):
            output_text += f"Salt:\n{result['salt']}\n"

        self.set_output(output_text)

    # ---------- DECRYPTION ----------
    def decrypt_action(self):
        text = self.inputbox.get("1.0", "end").strip()
        key_or_password = self.pass_inputbox.get()

        if text == self.placeholder:
            text = ""

        if not text:
            self.set_output("Please enter ciphertext.")
            return

        try:
            if key_or_password:
                result = aes_decrypt(
                    ciphertext=text,
                    password=key_or_password,
                    mode=self.get_mode()
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

    # ---------- MODE SELECTION ----------
    def get_mode(self):
        return int(self.mode_selector.get())

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
