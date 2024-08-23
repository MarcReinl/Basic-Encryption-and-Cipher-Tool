import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from cryptography.hazmat.primitives import serialization
from caesar_cipher import encrypt_caesar, decrypt_caesar
from vigenere_cipher import encrypt_vigenere, decrypt_vigenere
from aes_encryption import encrypt_file, decrypt_file, decrypt_file_with_key
from rsa_encryption import generate_rsa_keys, rsa_encrypt, rsa_decrypt


class EncryptionToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Tool")

        # Main menu frame
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(padx=20, pady=20)

        tk.Label(self.main_frame, text="Select Cipher or Encryption:").grid(
            row=0, column=0, pady=10
        )
        self.cipher_var = tk.StringVar(value="Caesar Cipher")
        cipher_menu = tk.OptionMenu(
            self.main_frame,
            self.cipher_var,
            "Caesar Cipher",
            "Vigenere Cipher",
            "AES Encryption",
            "RSA Encryption",
        )
        cipher_menu.grid(row=0, column=1, pady=10)

        tk.Button(self.main_frame, text="Next", command=self.open_cipher_window).grid(
            row=1, column=0, columnspan=2, pady=20
        )

    def open_cipher_window(self):
        cipher = self.cipher_var.get()
        self.main_frame.pack_forget()

        if cipher == "Caesar Cipher":
            CaesarCipherWindow(self.root, self)
        elif cipher == "Vigenere Cipher":
            VigenereCipherWindow(self.root, self)
        elif cipher == "AES Encryption":
            AESWindow(self.root, self)
        elif cipher == "RSA Encryption":
            RSAWindow(self.root, self)

    def show_main_frame(self):
        self.main_frame.pack(padx=20, pady=20)


class CaesarCipherWindow:
    def __init__(self, root, app):
        self.root = root
        self.app = app

        # Create a frame for the Caesar Cipher
        self.caesar_frame = tk.Frame(root)
        self.caesar_frame.pack(padx=20, pady=20)

        tk.Label(self.caesar_frame, text="Caesar Cipher").grid(
            row=0, column=0, columnspan=3, pady=10, sticky="ew"
        )

        tk.Label(self.caesar_frame, text="Enter text:").grid(row=1, column=0, pady=5)
        self.text_entry = tk.Entry(self.caesar_frame, width=50)
        self.text_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.caesar_frame, text="Shift:").grid(row=2, column=0, pady=5)
        self.shift_entry = tk.Entry(self.caesar_frame, width=10)
        self.shift_entry.grid(row=2, column=0, columnspan=2, pady=5)

        # Adjust the grid configuration for centering with columnspan
        tk.Button(self.caesar_frame, text="Encrypt", command=self.encrypt_text).grid(
            row=3, column=1, padx=50, sticky="w"
        )
        tk.Button(self.caesar_frame, text="Decrypt", command=self.decrypt_text).grid(
            row=3, column=1, padx=50, pady=10, sticky="e"
        )

        tk.Button(self.caesar_frame, text="←", command=self.back_to_main).grid(
            row=0, column=0, pady=10
        )

    def encrypt_text(self):
        text = self.text_entry.get()
        try:
            shift = int(self.shift_entry.get())
            encrypted_text = encrypt_caesar(text, shift)
            messagebox.showinfo("Encrypted Text", encrypted_text)
        except ValueError:
            messagebox.showerror("Error", "Shift value must be an integer.")

    def decrypt_text(self):
        text = self.text_entry.get()
        try:
            shift = int(self.shift_entry.get())
            decrypted_text = decrypt_caesar(text, shift)
            messagebox.showinfo("Decrypted Text", decrypted_text)
        except ValueError:
            messagebox.showerror("Error", "Shift value must be an integer.")

    def back_to_main(self):
        self.caesar_frame.pack_forget()  # Hide the Caesar frame
        self.app.show_main_frame()  # Show the main frame
        self.root.update_idletasks()  # Force UI to refresh


class VigenereCipherWindow:

    def __init__(self, root, app):
        self.root = root
        self.app = app

        # Create a frame for the Vigenere Cipher
        self.vigenere_frame = tk.Frame(root)
        self.vigenere_frame.pack(padx=20, pady=20)

        tk.Label(self.vigenere_frame, text="Vigenere Cipher").grid(
            row=0, column=0, columnspan=2, pady=10
        )

        tk.Label(self.vigenere_frame, text="Enter text:").grid(row=1, column=0, pady=5)
        self.text_entry = tk.Entry(self.vigenere_frame, width=50)
        self.text_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.vigenere_frame, text="Key:").grid(row=2, column=0, pady=5)
        self.key_entry = tk.Entry(self.vigenere_frame, width=20)
        self.key_entry.grid(row=2, column=1, pady=5)

        tk.Button(self.vigenere_frame, text="Encrypt", command=self.encrypt_text).grid(
            row=3, column=0, pady=5
        )
        tk.Button(self.vigenere_frame, text="Decrypt", command=self.decrypt_text).grid(
            row=3, column=1, pady=5
        )

        tk.Button(self.vigenere_frame, text="←", command=self.back_to_main).grid(
            row=0, column=0, pady=10
        )

    def encrypt_text(self):
        text = self.text_entry.get()
        key = self.key_entry.get()
        encrypted_text = encrypt_vigenere(text, key)
        messagebox.showinfo("Encrypted Text", encrypted_text)

    def decrypt_text(self):
        text = self.text_entry.get()
        key = self.key_entry.get()
        decrypted_text = decrypt_vigenere(text, key)
        messagebox.showinfo("Decrypted Text", decrypted_text)

    def back_to_main(self):
        self.vigenere_frame.pack_forget()  # Hide the Vigenere frame
        self.app.show_main_frame()  # Show the main frame
        self.root.update_idletasks()  # Force UI to refresh


class AESWindow:
    def __init__(self, root, app):
        self.root = root
        self.app = app

        self.aes_frame = tk.Frame(root)
        self.aes_frame.pack(padx=20, pady=20)

        # Create a Notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.aes_frame)
        self.notebook.pack(expand=1, fill="both")

        # Create frames for Encrypt and Decrypt tabs
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)

        # Add tabs to the notebook
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")

        # Setup Encrypt tab
        self.setup_encrypt_tab()

        # Setup Decrypt tab
        self.setup_decrypt_tab()

        tk.Button(self.aes_frame, text="Back", command=self.back_to_main).pack(pady=10)

    def setup_encrypt_tab(self):
        tk.Label(self.encrypt_frame, text="Input File:").grid(row=0, column=0, pady=5)
        self.input_entry_encrypt = tk.Entry(self.encrypt_frame, width=50)
        self.input_entry_encrypt.grid(row=0, column=1, padx=10)
        tk.Button(
            self.encrypt_frame, text="Browse", command=self.browse_input_file_encrypt
        ).grid(row=0, column=2, padx=10)

        tk.Label(self.encrypt_frame, text="Output File:").grid(row=1, column=0, pady=5)
        self.output_entry_encrypt = tk.Entry(self.encrypt_frame, width=50)
        self.output_entry_encrypt.grid(row=1, column=1, padx=10)
        tk.Button(
            self.encrypt_frame, text="Browse", command=self.browse_output_file_encrypt
        ).grid(row=1, column=2, padx=10)

        tk.Label(self.encrypt_frame, text="Password:").grid(row=2, column=0, pady=5)
        self.password_entry_encrypt = tk.Entry(self.encrypt_frame, show="*", width=50)
        self.password_entry_encrypt.grid(row=2, column=1, padx=10)

        tk.Label(self.encrypt_frame, text="Key Output File:").grid(
            row=3, column=0, pady=5
        )
        self.key_output_entry_encrypt = tk.Entry(self.encrypt_frame, width=50)
        self.key_output_entry_encrypt.grid(row=3, column=1, padx=10)
        tk.Button(
            self.encrypt_frame,
            text="Browse",
            command=self.browse_key_output_file_encrypt,
        ).grid(row=3, column=2, padx=10)

        tk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt_file).grid(
            row=4, column=0, columnspan=3, pady=10
        )

    def setup_decrypt_tab(self):
        tk.Label(self.decrypt_frame, text="Input File:").grid(row=0, column=0, pady=5)
        self.input_entry_decrypt = tk.Entry(self.decrypt_frame, width=50)
        self.input_entry_decrypt.grid(row=0, column=1, padx=10)
        tk.Button(
            self.decrypt_frame, text="Browse", command=self.browse_input_file_decrypt
        ).grid(row=0, column=2, padx=10)

        tk.Label(self.decrypt_frame, text="Output File:").grid(row=1, column=0, pady=5)
        self.output_entry_decrypt = tk.Entry(self.decrypt_frame, width=50)
        self.output_entry_decrypt.grid(row=1, column=1, padx=10)
        tk.Button(
            self.decrypt_frame, text="Browse", command=self.browse_output_file_decrypt
        ).grid(row=1, column=2, padx=10)

        # Checkbox to select decryption method
        self.use_aes_key_var = tk.BooleanVar()
        tk.Checkbutton(
            self.decrypt_frame,
            text="Use AES Key",
            variable=self.use_aes_key_var,
            command=self.toggle_decrypt_method,
        ).grid(row=2, column=0, pady=5)

        # Password field
        tk.Label(self.decrypt_frame, text="Password:").grid(row=3, column=0, pady=5)
        self.password_entry_decrypt = tk.Entry(self.decrypt_frame, show="*", width=50)
        self.password_entry_decrypt.grid(row=3, column=1, padx=10)

        # AES Key field
        tk.Label(self.decrypt_frame, text="AES Key File:").grid(row=4, column=0, pady=5)
        self.aes_key_entry_decrypt = tk.Entry(
            self.decrypt_frame, width=50, state="disabled"
        )
        self.aes_key_entry_decrypt.grid(row=4, column=1, padx=10)
        tk.Button(
            self.decrypt_frame, text="Browse", command=self.browse_key_file_decrypt
        ).grid(row=4, column=2, padx=10)

        tk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt_file).grid(
            row=5, column=0, columnspan=3, pady=10
        )

    def toggle_decrypt_method(self):
        if self.use_aes_key_var.get():
            self.password_entry_decrypt.config(state="disabled")
            self.aes_key_entry_decrypt.config(state="normal")
        else:
            self.password_entry_decrypt.config(state="normal")
            self.aes_key_entry_decrypt.config(state="disabled")

    def browse_input_file_encrypt(self):
        file_path = filedialog.askopenfilename()
        self.input_entry_encrypt.insert(0, file_path)

    def browse_output_file_encrypt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".")
        self.output_entry_encrypt.insert(0, file_path)

    def browse_key_output_file_encrypt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        self.key_output_entry_encrypt.insert(0, file_path)

    def browse_input_file_decrypt(self):
        file_path = filedialog.askopenfilename()
        self.input_entry_decrypt.insert(0, file_path)

    def browse_output_file_decrypt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".")
        self.output_entry_decrypt.insert(0, file_path)

    def browse_key_file_decrypt(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        self.aes_key_entry_decrypt.insert(0, file_path)

    def encrypt_file(self):
        input_file = self.input_entry_encrypt.get()
        output_file = self.output_entry_encrypt.get()
        password = self.password_entry_encrypt.get()
        key_output_file = self.key_output_entry_encrypt.get()

        if not input_file or not output_file or not password or not key_output_file:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            encrypt_file(input_file, output_file, password, key_output_file)
            messagebox.showinfo(
                "Success", f"File encrypted successfully and saved to {output_file}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        input_file = self.input_entry_decrypt.get()
        output_file = self.output_entry_decrypt.get()

        if self.use_aes_key_var.get():
            key_file = self.aes_key_entry_decrypt.get()
            if not input_file or not output_file or not key_file:
                messagebox.showerror("Error", "All fields are required!")
                return
            try:
                decrypt_file_with_key(input_file, output_file, key_file)
                messagebox.showinfo(
                    "Success", f"File decrypted successfully and saved to {output_file}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            password = self.password_entry_decrypt.get()
            if not input_file or not output_file or not password:
                messagebox.showerror("Error", "All fields are required!")
                return
            try:
                decrypt_file(input_file, output_file, password)
                messagebox.showinfo(
                    "Success", f"File decrypted successfully and saved to {output_file}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

    def back_to_main(self):
        self.aes_frame.pack_forget()
        self.app.show_main_frame()
        self.root.update_idletasks()  # Force UI to refresh


import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from rsa_encryption import generate_rsa_keys, rsa_encrypt, rsa_decrypt


class RSAWindow:
    def __init__(self, root, app):
        self.root = root
        self.app = app

        self.rsa_frame = tk.Frame(root)
        self.rsa_frame.pack(padx=20, pady=20)

        # Create a Notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.rsa_frame)
        self.notebook.pack(expand=1, fill="both")

        # Create frames for each tab
        self.generate_keys_frame = ttk.Frame(self.notebook)
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)

        # Add tabs to the notebook
        self.notebook.add(self.generate_keys_frame, text="Generate Keys")
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")

        # Setup each tab
        self.setup_generate_keys_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        tk.Button(self.rsa_frame, text="Back", command=self.back_to_main).pack(pady=10)

        # Initialize variables for imported keys
        self.public_key_path = None
        self.private_key_path = None

    def setup_generate_keys_tab(self):
        tk.Label(self.generate_keys_frame, text="Save Keys To Folder:").grid(
            row=0, column=0, pady=5
        )
        self.key_dir_entry = tk.Entry(self.generate_keys_frame, width=50)
        self.key_dir_entry.grid(row=0, column=1, padx=10)
        tk.Button(
            self.generate_keys_frame, text="Browse", command=self.browse_key_directory
        ).grid(row=0, column=2, padx=10)

        tk.Button(
            self.generate_keys_frame, text="Generate Keys", command=self.generate_keys
        ).grid(row=1, column=0, pady=10, columnspan=3)

    def setup_encrypt_tab(self):
        tk.Label(self.encrypt_frame, text="Input File:").grid(row=0, column=0, pady=5)
        self.input_entry_encrypt = tk.Entry(self.encrypt_frame, width=50)
        self.input_entry_encrypt.grid(row=0, column=1, padx=10)
        tk.Button(
            self.encrypt_frame,
            text="Browse File",
            command=self.browse_input_file_encrypt,
        ).grid(row=0, column=2, padx=10)

        tk.Label(self.encrypt_frame, text="Output File:").grid(row=1, column=0, pady=5)
        self.output_entry_encrypt = tk.Entry(self.encrypt_frame, width=50)
        self.output_entry_encrypt.grid(row=1, column=1, padx=10)
        tk.Button(
            self.encrypt_frame,
            text="Browse Output File",
            command=self.browse_output_file_encrypt,
        ).grid(row=1, column=2, padx=10)

        tk.Button(
            self.encrypt_frame, text="Import Public Key", command=self.import_public_key
        ).grid(row=2, column=0, columnspan=3, pady=5)

        tk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt_file).grid(
            row=3, column=0, columnspan=3, pady=10
        )

    def setup_decrypt_tab(self):
        tk.Label(self.decrypt_frame, text="Input File:").grid(row=0, column=0, pady=5)
        self.input_entry_decrypt = tk.Entry(self.decrypt_frame, width=50)
        self.input_entry_decrypt.grid(row=0, column=1, padx=10)
        tk.Button(
            self.decrypt_frame,
            text="Browse File",
            command=self.browse_input_file_decrypt,
        ).grid(row=0, column=2, padx=10)

        tk.Label(self.decrypt_frame, text="Output File:").grid(row=1, column=0, pady=5)
        self.output_entry_decrypt = tk.Entry(self.decrypt_frame, width=50)
        self.output_entry_decrypt.grid(row=1, column=1, padx=10)
        tk.Button(
            self.decrypt_frame,
            text="Browse Output File",
            command=self.browse_output_file_decrypt,
        ).grid(row=1, column=2, padx=10)

        tk.Button(
            self.decrypt_frame,
            text="Import Private Key",
            command=self.import_private_key,
        ).grid(row=2, column=0, columnspan=3, pady=5)

        tk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt_file).grid(
            row=3, column=0, columnspan=3, pady=10
        )

    def browse_key_directory(self):
        directory = filedialog.askdirectory()
        self.key_dir_entry.insert(0, directory)

    def generate_keys(self):
        key_dir = self.key_dir_entry.get()

        if not key_dir:
            messagebox.showerror("Error", "Please select a directory to save the keys.")
            return

        public_key_path = f"{key_dir}/public_key.pem"
        private_key_path = f"{key_dir}/private_key.pem"

        try:
            generate_rsa_keys(public_key_path, private_key_path)
            messagebox.showinfo("Success", f"Keys generated successfully!")
            self.public_key_path = public_key_path
            self.private_key_path = private_key_path

        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def import_public_key(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
            if file_path:
                self.public_key_path = file_path
                messagebox.showinfo("Success", f"Public key imported successfully!")
            else:
                raise ValueError("No public key file selected.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import public key: {e}")

    def import_private_key(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
            if file_path:
                self.private_key_path = file_path
                messagebox.showinfo("Success", f"Private key imported successfully!")

            else:
                raise ValueError("No private key file selected.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import private key: {e}")

    def browse_input_file_encrypt(self):
        file_path = filedialog.askopenfilename()
        self.input_entry_encrypt.insert(0, file_path)

    def browse_output_file_encrypt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        self.output_entry_encrypt.insert(0, file_path)

    def browse_input_file_decrypt(self):
        file_path = filedialog.askopenfilename()
        self.input_entry_decrypt.insert(0, file_path)

    def browse_output_file_decrypt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        self.output_entry_decrypt.insert(0, file_path)

    def encrypt_file(self):
        input_file = self.input_entry_encrypt.get()
        output_file = self.output_entry_encrypt.get()
        public_key_path = self.public_key_path

        if not input_file or not output_file or not public_key_path:
            messagebox.showerror(
                "Error", "Input, output, and public key paths are required!"
            )
            return

        try:
            with open(input_file, "rb") as f:
                data = f.read()
            encrypted_data = rsa_encrypt(data, public_key_path)
            with open(output_file, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo(
                "Success", f"File encrypted successfully and saved to {output_file}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        input_file = self.input_entry_decrypt.get()
        output_file = self.output_entry_decrypt.get()
        private_key_path = self.private_key_path

        if not input_file or not output_file or not private_key_path:
            messagebox.showerror(
                "Error", "Input, output, and private key paths are required!"
            )
            return

        try:
            with open(input_file, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = rsa_decrypt(encrypted_data, private_key_path)
            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            messagebox.showinfo(
                "Success", f"File decrypted successfully and saved to {output_file}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def back_to_main(self):
        self.rsa_frame.pack_forget()
        self.app.show_main_frame()
        self.root.update_idletasks()  # Force UI to refresh


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionToolApp(root)
    root.mainloop()
