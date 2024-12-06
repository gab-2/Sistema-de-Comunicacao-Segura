from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def sign_file(file_path, private_key_path, signed_file_path):
    # Lê o arquivo original
    with open(file_path, "rb") as f:
        data = f.read()

    # Lê a chave privada
    from cryptography.hazmat.primitives import serialization
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Assina o arquivo
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Salva o arquivo assinado
    with open(signed_file_path, "wb") as f:
        f.write(signature + data)

def encrypt_file(file_path, aes_key_path, encrypted_file_path):
    # Lê o arquivo e a chave AES
    with open(file_path, "rb") as f:
        data = f.read()

    with open(aes_key_path, "rb") as key_file:
        aes_key = key_file.read()

    # Gera um vetor de inicialização (IV) para o AES
    iv = os.urandom(16)

    # Cifra o arquivo
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

    # Salva o arquivo cifrado
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)
