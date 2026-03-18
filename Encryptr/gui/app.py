import customtkinter as ctk
from gui.des_view import DESView
from gui.des3_view import DES3View
from gui.aes_view import AESView

class EncryptrApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")

        self.title("ENCRYPTR")
        self.geometry("1200x800")

        self.configure(fg_color="#c6ac8f")

        # ---------- UI CONTROLS (ON TOP) ----------
        self.encryption_options = ctk.CTkOptionMenu(
            self,
            values=["HOME", "DES", "3DES", "AES"],
            corner_radius=8,
            fg_color="#F5ECD2",
            button_color="#ED254E",
            dropdown_fg_color="#F5ECD2",
            button_hover_color="#9B2226",
            dropdown_hover_color="#E3D5B8",
            text_color="#69433A",
            dropdown_text_color="#69433A",
            font=("Arial", 13),
            command=self.encryption
        )
        self.encryption_options.place(relx=0.5, rely=0.05, anchor="n", relwidth=0.17)

        # ---------- CONTENT CONTAINER ----------
        self.content_frame = ctk.CTkFrame(
            self,
            fg_color="#E3D5B8"
        )
        self.content_frame.place(
            relx=0.5,
            rely=0.6,
            anchor="center",
            relwidth=0.85,
            relheight=0.65
        )

        # ---------- LABEL ----------
        label = ctk.CTkLabel(
            self,
            text="ENCRYPTR",
            font=("Arial", 100),
            text_color="#69433A"
            )

        label.place(
            relx=0.5,
            rely=0.17,
            anchor="center"
        )

    # ---------- CONTENT HANDLING ----------
    def content_clear(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def encryption(self, choice):
        self.content_clear()

        match choice:
            case "DES":
                DESView(self.content_frame)
            case "3DES":
                DES3View(self.content_frame)
            case "AES":
                AESView(self.content_frame)
            case _:
                pass
