from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets

def generate_key(password, salt):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8') + salt)
    hashed_password = digest.finalize()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    derived_key = kdf.derive(hashed_password)

    nonce = secrets.token_bytes(16)
    key_with_nonce = derived_key + nonce
    
    return key_with_nonce

def get_password():
    return input("Введите парольную фразу: ")

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key[:32]), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)

    print(f"Файл '{file_path}' успешно зашифрован и сохранен как '{file_path}.enc'.")

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key[:32]), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        decrypted_file_path = file_path[:-4]
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"Файл '{file_path}' успешно дешифрован и сохранен как '{decrypted_file_path}'.")
    except Exception as e:
        print(f"Произошла ошибка при дешифровании файла '{file_path}': {str(e)}")

# Пример использования
password = get_password()

# Шифрование файла
encrypt_file('users.txt', password)

# Дешифрование файла
decrypt_file('users.txt.enc', password)
