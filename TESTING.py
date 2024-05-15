import unittest
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import secrets
import random
import string
import json


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
    if combined_data is None:
        raise ValueError("Encrypted message cannot be None")

    combined_data = urlsafe_b64decode(combined_data)

    rsa_key_size_bytes = private_key.key_size // 8
    encrypted_aes_key = combined_data[:rsa_key_size_bytes]
    iv = combined_data[rsa_key_size_bytes:rsa_key_size_bytes + 16]
    encrypted_data = combined_data[rsa_key_size_bytes + 16:]

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


def tokenize_data(data):
    token_map = {}
    tokenized_data = {}
    for key, value in data.items():
        token = secrets.token_hex(16)
        token_map[token] = value
        tokenized_data[key] = token
    return tokenized_data, token_map



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
    encrypted_data = urlsafe_b64decode(encrypted_token_map.encode())
    salt, iv, encrypted_token_map = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_token_map) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return json.loads(decrypted_data.decode())


def tokenize_then_encrypt_data(public_key, data):
    tokenized_data, token_map = tokenize_data(data)
    encrypted_token_map = encrypt_data(public_key, json.dumps(token_map))
    return tokenized_data, encrypted_token_map


def decrypt_then_detokenize_data(private_key, tokenized_data, encrypted_token_map):
    decrypted_token_map = decrypt_data(private_key, encrypted_token_map)
    token_map = json.loads(decrypted_token_map)
    detokenized_data = detokenize_data(tokenized_data, token_map)
    return detokenized_data


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

    def test_sql_injection_attempt(self):
        plaintext = "Test data"
        receiver_id = "test'); DROP TABLE transactions; --"
        data = f"Name: Alice, Receiver ID: {receiver_id}, Card Number: 1234567890123456, Amount: 100"
        encrypted_data = encrypt_data(self.public_key, data)
        self.cursor.execute('INSERT INTO transactions (encrypted_data) VALUES (?)', (encrypted_data,))
        self.conn.commit()

        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
        self.assertIsNotNone(self.cursor.fetchone(),
                             "SQL injection attempt succeeded, table 'transactions' was dropped")

    def test_tokenization_detokenization(self):
        original_data = {
            "Name": "Alice",
            "Card Number": "1234567890123456",
            "Amount": "100"
        }
        tokenized_data, token_map = tokenize_data(original_data.copy())
        self.assertNotEqual(original_data, tokenized_data)
        self.assertEqual(len(tokenized_data), len(original_data))
        self.assertEqual(len(token_map), len(original_data))

        detokenized_data = detokenize_data(tokenized_data.copy(), token_map)
        self.assertEqual(original_data, detokenized_data)

    def test_encrypt_decrypt_token_map(self):
        original_token_map = {
            secrets.token_hex(16): "Alice",
            secrets.token_hex(16): "1234567890123456",
            secrets.token_hex(16): "100"
        }
        password = "testpassword"
        encrypted_token_map = encrypt_token_map(original_token_map, password)
        decrypted_token_map = decrypt_token_map(encrypted_token_map, password)
        self.assertEqual(original_token_map, decrypted_token_map)

    def test_tokenize_then_encrypt(self):
        original_data = {
            "Name": "Alice",
            "Card Number": "1234567890123456",
            "Amount": "100"
        }
        tokenized_data, encrypted_token_map = tokenize_then_encrypt_data(self.public_key, original_data)
        self.assertNotEqual(original_data, tokenized_data, "Tokenized data should not equal original data")

        for key in tokenized_data:
            self.assertNotEqual(tokenized_data[key], original_data[key],
                                "Tokenized value should not be the same as original value")

        detokenized_data = decrypt_then_detokenize_data(self.private_key, tokenized_data, encrypted_token_map)
        self.assertEqual(original_data, detokenized_data, "Detokenized data should equal original data")

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
