import unittest
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import random
import string

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(public_key, plaintext):
    if not plaintext:  
        raise ValueError("Plaintext cannot be empty")
    encrypted = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_data(private_key, encrypted_message):
    if encrypted_message is None:  
        raise ValueError("Encrypted message cannot be None")
    decrypted = private_key.decrypt(
        encrypted_message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

class TestPaymentSystem(unittest.TestCase):

    @staticmethod
    def generate_random_text(length):
        """Generate a random text of given length."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
           CREATE TABLE IF NOT EXISTS transactions (
               id INTEGER PRIMARY KEY,
               encrypted_data BLOB
           )
           ''')
        self.conn.commit()
        self.private_key, self.public_key = generate_rsa_keys()

    def test_high_volume_random_texts(self):
        random_texts = [self.generate_random_text(random.randint(1, 100)) for _ in range(10000)]
        for text in random_texts:
            encrypted_data = encrypt_data(self.public_key, text)
            decrypted_text = decrypt_data(self.private_key, encrypted_data)
            self.assertEqual(decrypted_text, text)

    def test_encrypt_decrypt(self):
        plaintext = "Test data"
        encrypted_data = encrypt_data(self.public_key, plaintext)
        decrypted_text = decrypt_data(self.private_key, encrypted_data)
        self.assertEqual(decrypted_text, plaintext)

    def test_empty_plaintext_encryption(self):
        with self.assertRaises(ValueError):
            encrypt_data(self.public_key, "")

    def test_null_inputs_in_decryption(self):
        with self.assertRaises(ValueError):
            decrypt_data(self.private_key, None)

    def test_high_volume_rsa_encryption(self):
        random_texts = [self.generate_random_text(10) for _ in range(10000)]
        for text in random_texts:
            encrypted_data = encrypt_data(self.public_key, text)
            decrypted_text = decrypt_data(self.private_key, encrypted_data)
            self.assertEqual(decrypted_text, text)

    def test_database_operations(self):
        plaintext = "Database test data"
        encrypted_data = encrypt_data(self.public_key, plaintext)
        self.cursor.execute('INSERT INTO transactions (encrypted_data) VALUES (?)', (encrypted_data,))
        self.conn.commit()
        self.cursor.execute('SELECT encrypted_data FROM transactions')
        fetched_data = self.cursor.fetchone()
        decrypted_data = decrypt_data(self.private_key, fetched_data[0])
        self.assertEqual(decrypted_data, plaintext)

    def test_large_key_sizes(self):
        key_sizes = [2048, 3072, 4096]
        plaintext = "Test data"
        for key_size in key_sizes:
            private_key, public_key = generate_rsa_keys(key_size)
            encrypted_data = encrypt_data(public_key, plaintext)
            decrypted_text = decrypt_data(private_key, encrypted_data)
            self.assertEqual(decrypted_text, plaintext)

    def test_retrieving_nonexistent_data(self):
        self.cursor.execute('SELECT encrypted_data FROM transactions WHERE id = ?', (999,))
        fetched_data = self.cursor.fetchone()
        self.assertIsNone(fetched_data)

    def test_large_data_volume(self):
        large_plaintext = 'A' * 10000  
        with self.assertRaises(ValueError):
            encrypt_data(self.public_key, large_plaintext)

    def test_sql_injection_attempt(self):
        plaintext = "Test data"
        receiver_id = "test'); DROP TABLE transactions; --"
        data = f"Name: Alice, Receiver ID: {receiver_id}, Card Number: 1234567890123456, Amount: 100"
        encrypted_data = encrypt_data(self.public_key, data)
        self.cursor.execute('INSERT INTO transactions (encrypted_data) VALUES (?)', (encrypted_data,))
        self.conn.commit()

        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
        self.assertIsNotNone(self.cursor.fetchone(), "SQL injection attempt succeeded, table 'transactions' was dropped")

    def tearDown(self):
        self.conn.close()


class CustomTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"{test.id()}: PASSED")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"{test.id()}: FAILED")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"{test.id()}: ERROR")

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPaymentSystem)
    runner = unittest.TextTestRunner(resultclass=CustomTestResult)
    runner.run(suite)
