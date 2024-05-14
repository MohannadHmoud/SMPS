import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

# Set up database connection and cursor
conn = sqlite3.connect('encrypted_payment_data.db')
cursor = conn.cursor()

# Create transactions table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    encrypted_data BLOB,
    receiver_id TEXT
)
''')

# Create reported transactions table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS reported_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    encrypted_data BLOB,
    FOREIGN KEY(original_id) REFERENCES transactions(id)
)
''')
conn.commit()

# Function to generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data using the public key
def encrypt_data(public_key, plaintext):
    encrypted = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Function to decrypt data using the private key
def decrypt_data(private_key, encrypted):
    decrypted = private_key.decrypt(
        encrypted,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Encrypt and store the private key
def store_private_key(private_key, password, file_path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    with open(file_path, 'wb') as pem_out:
        pem_out.write(pem)

# Load and decrypt the private key
def load_private_key(password, file_path):
    with open(file_path, 'rb') as pem_in:
        pem = pem_in.read()
    private_key = serialization.load_pem_private_key(
        pem,
        password=password.encode(),
        backend=default_backend()
    )
    return private_key

# Generate and store keys (in a real application, this should be done securely and the keys should be persistent)
password = 'your-strong-password'
private_key_file = 'private_key.pem'

# Check if the private key file exists; if not, generate and store new keys
if not os.path.exists(private_key_file):
    private_key, public_key = generate_keys()
    store_private_key(private_key, password, private_key_file)
else:
    private_key = load_private_key(password, private_key_file)
    public_key = private_key.public_key()

# Ensure the private key file has restricted permissions
os.chmod(private_key_file, 0o600)

# GUI Application class
class PaymentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Payment Encryption System")
        self.root.geometry("1150x600")
        self.root.configure(bg="#f0f0f0")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Styles
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 12), padding=10)
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("TEntry", font=("Helvetica", 12), padding=5)
        style.configure("TListbox", font=("Helvetica", 12))
        style.configure("TFrame", background="#f0f0f0")

        # Frames for better organization
        self.input_frame = ttk.Frame(root, padding="20 10 20 10")
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="EW")

        self.button_frame = ttk.Frame(root, padding="20 10 20 10")
        self.button_frame.grid(row=1, column=0, padx=10, pady=10, sticky="EW")

        self.listbox_frame = ttk.Frame(root, padding="20 10 20 10")
        self.listbox_frame.grid(row=2, column=0, padx=10, pady=10, sticky="EW")

        # Input fields
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

        # Buttons
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

        # Listbox to display transactions
        self.transaction_listbox = tk.Listbox(self.listbox_frame, height=10, width=100, font=("Helvetica", 12))
        self.transaction_listbox.grid(row=0, column=0, padx=10, pady=10)
        self.transaction_listbox.bind('<Double-1>', self.decrypt_display_from_list)

    def encrypt_and_store_data(self):
        # Gather data from entry widgets
        name = self.name_entry.get()
        receiver_id = self.receiver_id_entry.get()
        card_number = self.card_number_entry.get()
        amount = self.amount_entry.get()
        data = f"Name: {name}, Receiver ID: {receiver_id}, Card Number: {card_number}, Amount: {amount}"

        # Encrypt the data using the public key
        encrypted_data = encrypt_data(public_key, data)

        # Store encrypted data and Receiver ID in the database
        cursor.execute('INSERT INTO transactions (encrypted_data, receiver_id) VALUES (?, ?)', (encrypted_data, receiver_id))
        conn.commit()

        # Display success message
        messagebox.showinfo("Encryption", "Data encrypted and stored successfully!")

    def show_encrypted_data(self):
        # Fetch and display transaction IDs
        cursor.execute('SELECT id FROM transactions')
        records = cursor.fetchall()
        self.transaction_listbox.delete(0, tk.END)
        for record in records:
            self.transaction_listbox.insert(tk.END, f"Transaction ID {record[0]}")

    def show_raw_data(self):
        # Fetch and display encrypted data in hexadecimal format
        cursor.execute('SELECT id, encrypted_data FROM transactions')
        records = cursor.fetchall()
        self.transaction_listbox.delete(0, tk.END)
        for record in records:
            encrypted_hex = record[1].hex()
            self.transaction_listbox.insert(tk.END, f"ID {record[0]}: Encrypted Data: {encrypted_hex[:60]}...")

    def decrypt_display_from_list(self, event):
        # Decrypt and display selected transaction details
        if not self.transaction_listbox.curselection():
            messagebox.showerror("Error", "No transaction selected.")
            return
        index = self.transaction_listbox.curselection()[0]
        cursor.execute('SELECT encrypted_data FROM transactions')
        records = cursor.fetchall()
        encrypted_data = records[index][0]
        decrypted_message = decrypt_data(private_key, encrypted_data)
        messagebox.showinfo("Decrypted Transaction", f"Transaction Details: {decrypted_message}")

    def report_transaction(self):
        # Report the selected transaction
        if not self.transaction_listbox.curselection():
            messagebox.showerror("Error", "Please select a transaction to report.")
            return
        index = self.transaction_listbox.curselection()[0]
        cursor.execute('SELECT id, encrypted_data FROM transactions')
        records = cursor.fetchall()
        transaction_id, encrypted_data = records[index]

        # Move to reported transactions table
        cursor.execute('INSERT INTO reported_transactions (original_id, encrypted_data) VALUES (?, ?)', (transaction_id, encrypted_data))
        conn.commit()

        # Optionally remove from the main table
        cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
        conn.commit()

        # Update UI
        self.show_encrypted_data()
        messagebox.showinfo("Reported", "Transaction reported and moved to the reported transactions table.")

    def show_reported_transactions(self):
        # Fetch and display reported transactions
        cursor.execute('SELECT original_id, encrypted_data FROM reported_transactions')
        records = cursor.fetchall()
        display_text = "Reported Transactions:\n"
        for record in records:
            original_id, encrypted_data = record
            decrypted_message = decrypt_data(private_key, encrypted_data)
            display_text += f"Original ID {original_id}: {decrypted_message}\n"

        messagebox.showinfo("Reported Transactions", display_text)

    def on_closing(self):
        # Clean up and close the application
        cursor.execute('DELETE FROM transactions')
        cursor.execute('DELETE FROM reported_transactions')
        conn.commit()
        conn.close()
        self.root.destroy()

# Main window
root = tk.Tk()
app = PaymentApp(root)
root.mainloop()
