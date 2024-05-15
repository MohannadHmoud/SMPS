import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import secrets
import json

conn = sqlite3.connect('encrypted_payment_data.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    encrypted_data BLOB,
    receiver_id TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS reported_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    encrypted_data BLOB,
    FOREIGN KEY(original_id) REFERENCES transactions(id)
)
''')
conn.commit()

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(public_key, plaintext):
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    combined_data = urlsafe_b64encode(encrypted_aes_key + iv + encrypted_data)
    return combined_data

def decrypt_data(private_key, combined_data):
    combined_data = urlsafe_b64decode(combined_data)

    rsa_key_size_bytes = private_key.key_size // 8
    encrypted_aes_key = combined_data[:rsa_key_size_bytes]
    iv = combined_data[rsa_key_size_bytes:rsa_key_size_bytes+16]
    encrypted_data = combined_data[rsa_key_size_bytes+16:]

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

def store_private_key(private_key, password, file_path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    with open(file_path, 'wb') as pem_out:
        pem_out.write(pem)

def load_private_key(password, file_path):
    with open(file_path, 'rb') as pem_in:
        pem = pem_in.read()
    private_key = serialization.load_pem_private_key(
        pem,
        password=password.encode(),
        backend=default_backend()
    )
    return private_key

def tokenize_data(data):
    token_map = {}
    for key, value in data.items():
        token = secrets.token_hex(16)
        token_map[token] = value
        data[key] = token
    return data, token_map

def detokenize_data(data, token_map):
    for key, value in data.items():
        if value in token_map:
            data[key] = token_map[value]
    return data

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_token_map(token_map, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(json.dumps(token_map).encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encrypted_data).decode()

def decrypt_token_map(encrypted_token_map, password):
    try:
        encrypted_data = urlsafe_b64decode(encrypted_token_map.encode())
        salt, iv, encrypted_token_map = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(encrypted_token_map) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return json.loads(decrypted_data.decode())
    except Exception as e:
        raise ValueError(f"Failed to decrypt token map: {e}")

def save_token_map(token_map, file_path, password):
    encrypted_token_map = encrypt_token_map(token_map, password)
    with open(file_path, 'w') as file:
        file.write(encrypted_token_map)
    os.chmod(file_path, 0o600)

def load_token_map(file_path, password):
    try:
        with open(file_path, 'r') as file:
            encrypted_token_map = file.read()
        return decrypt_token_map(encrypted_token_map, password)
    except Exception as e:
        raise ValueError(f"Failed to load token map: {e}")

password = 'DrAmmarIsTheBestDoctor@1234#<3'
private_key_file = 'private_key.pem'
token_map_file = 'token_map.json'

if not os.path.exists(private_key_file):
    private_key, public_key = generate_keys()
    store_private_key(private_key, password, private_key_file)
else:
    private_key = load_private_key(password, private_key_file)
    public_key = private_key.public_key()

os.chmod(private_key_file, 0o600)

if os.path.exists(token_map_file):
    try:
        token_map = load_token_map(token_map_file, password)
    except ValueError as e:
        messagebox.showerror("Error", f"Failed to load token map: {e}")
        token_map = {}
else:
    token_map = {}

class PaymentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Payment Encryption System")
        self.root.geometry("1150x600")
        self.root.configure(bg="#f0f0f0")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 12), padding=10)
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("TEntry", font=("Helvetica", 12), padding=5)
        style.configure("TListbox", font=("Helvetica", 12))
        style.configure("TFrame", background="#f0f0f0")

        self.input_frame = ttk.Frame(root, padding="20 10 20 10")
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="EW")

        self.button_frame = ttk.Frame(root, padding="20 10 20 10")
        self.button_frame.grid(row=1, column=0, padx=10, pady=10, sticky="EW")

        self.listbox_frame = ttk.Frame(root, padding="20 10 20 10")
        self.listbox_frame.grid(row=2, column=0, padx=10, pady=10, sticky="EW")

        ttk.Label(self.input_frame, text="Name:").grid(row=0, column=0, padx=10, pady=10, sticky="E")
        self.name_entry = ttk.Entry(self.input_frame, width=30)
        self.name_entry.grid(row=0, column=1, padx=10, pady=10, sticky="W")

        ttk.Label(self.input_frame, text="Credit Card Number:").grid(row=1, column=0, padx=10, pady=10, sticky="E")
        self.card_number_entry = ttk.Entry(self.input_frame, width=30)
        self.card_number_entry.grid(row=1, column=1, padx=10, pady=10, sticky="W")

        ttk.Label(self.input_frame, text="Receiver ID:").grid(row=2, column=0, padx=10, pady=10, sticky="E")
        self.receiver_id_entry = ttk.Entry(self.input_frame, width=30)
        self.receiver_id_entry.grid(row=2, column=1, padx=10, pady=10, sticky="W")

        ttk.Label(self.input_frame, text="Amount:").grid(row=3, column=0, padx=10, pady=10, sticky="E")
        self.amount_entry = ttk.Entry(self.input_frame, width=30)
        self.amount_entry.grid(row=3, column=1, padx=10, pady=10, sticky="W")

        self.encrypt_button = ttk.Button(self.button_frame, text="Encrypt & Store Data",
                                         command=self.encrypt_and_store_data)
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=10)

        self.show_encrypted_button = ttk.Button(self.button_frame, text="Show Encrypted Transactions",
                                                command=self.show_encrypted_data)
        self.show_encrypted_button.grid(row=0, column=1, padx=10, pady=10)

        self.show_raw_button = ttk.Button(self.button_frame, text="Show Raw Encrypted Data", command=self.show_raw_data)
        self.show_raw_button.grid(row=0, column=2, padx=10, pady=10)

        self.report_button = ttk.Button(self.button_frame, text="Report Transaction", command=self.report_transaction)
        self.report_button.grid(row=0, column=3, padx=10, pady=10)

        self.show_reported_button = ttk.Button(self.button_frame, text="Show Reported Transactions",
                                               command=self.show_reported_transactions)
        self.show_reported_button.grid(row=0, column=4, padx=10, pady=10)

        self.transaction_listbox = tk.Listbox(self.listbox_frame, height=10, width=100, font=("Helvetica", 12))
        self.transaction_listbox.grid(row=0, column=0, padx=10, pady=10)
        self.transaction_listbox.bind('<Double-1>', self.decrypt_display_from_list)

    def encrypt_and_store_data(self):
        name = self.name_entry.get()
        receiver_id = self.receiver_id_entry.get()
        card_number = self.card_number_entry.get()
        amount = self.amount_entry.get()
        data = {"Name": name, "Receiver ID": receiver_id, "Card Number": card_number, "Amount": amount}

        tokenized_data, new_token_map = tokenize_data(data)
        token_map.update(new_token_map)
        save_token_map(token_map, token_map_file, password)

        tokenized_data_str = json.dumps(tokenized_data)

        encrypted_data = encrypt_data(public_key, tokenized_data_str)

        cursor.execute('INSERT INTO transactions (encrypted_data, receiver_id) VALUES (?, ?)', (encrypted_data, receiver_id))
        conn.commit()

        messagebox.showinfo("Encryption", "Data encrypted and stored successfully!")

    def show_encrypted_data(self):
        cursor.execute('SELECT id FROM transactions')
        records = cursor.fetchall()
        self.transaction_listbox.delete(0, tk.END)
        for record in records:
            self.transaction_listbox.insert(tk.END, f"Transaction ID {record[0]}")

    def show_raw_data(self):
        cursor.execute('SELECT id, encrypted_data FROM transactions')
        records = cursor.fetchall()
        self.transaction_listbox.delete(0, tk.END)
        for record in records:
            encrypted_hex = record[1].hex()
            self.transaction_listbox.insert(tk.END, f"ID {record[0]}: Encrypted Data: {encrypted_hex[:60]}...")

    def decrypt_display_from_list(self, event):
        if not self.transaction_listbox.curselection():
            messagebox.showerror("Error", "No transaction selected.")
            return
        index = self.transaction_listbox.curselection()[0]
        cursor.execute('SELECT encrypted_data FROM transactions')
        records = cursor.fetchall()
        encrypted_data = records[index][0]
        decrypted_tokenized_data = decrypt_data(private_key, encrypted_data)
        tokenized_data = json.loads(decrypted_tokenized_data)
        decrypted_message = detokenize_data(tokenized_data, token_map)
        messagebox.showinfo("Decrypted Transaction", f"Transaction Details: {decrypted_message}")

    def report_transaction(self):
        if not self.transaction_listbox.curselection():
            messagebox.showerror("Error", "Please select a transaction to report.")
            return
        index = self.transaction_listbox.curselection()[0]
        cursor.execute('SELECT id, encrypted_data FROM transactions')
        records = cursor.fetchall()
        transaction_id, encrypted_data = records[index]

        cursor.execute('INSERT INTO reported_transactions (original_id, encrypted_data) VALUES (?, ?)', (transaction_id, encrypted_data))
        conn.commit()

        cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
        conn.commit()

        self.show_encrypted_data()
        messagebox.showinfo("Reported", "Transaction reported and moved to the reported transactions table.")

    def show_reported_transactions(self):
        cursor.execute('SELECT original_id, encrypted_data FROM reported_transactions')
        records = cursor.fetchall()
        display_text = "Reported Transactions:\n"
        for record in records:
            original_id, encrypted_data = record
            decrypted_tokenized_data = decrypt_data(private_key, encrypted_data)
            tokenized_data = json.loads(decrypted_tokenized_data)
            decrypted_message = detokenize_data(tokenized_data, token_map)
            display_text += f"Original ID {original_id}: {decrypted_message}\n"

        messagebox.showinfo("Reported Transactions", display_text)

    def on_closing(self):
        cursor.execute('DELETE FROM transactions')
        cursor.execute('DELETE FROM reported_transactions')
        conn.commit()
        conn.close()
        self.root.destroy()

root = tk.Tk()
app = PaymentApp(root)
root.mainloop()
