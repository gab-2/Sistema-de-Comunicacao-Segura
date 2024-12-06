from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import os


def sign_file(file_path, private_key_path, signed_file_path):
    """
    Assina digitalmente um arquivo usando uma chave privada RSA.

    :param file_path: Caminho do arquivo a ser assinado.
    :param private_key_path: Caminho da chave privada RSA.
    :param signed_file_path: Caminho para salvar o arquivo assinado.
    """
    # Lê o arquivo original
    with open(file_path, "rb") as f:
        data = f.read()

    # Lê a chave privada
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
    """
    Cifra um arquivo usando uma chave AES.

    :param file_path: Caminho do arquivo a ser cifrado.
    :param aes_key_path: Caminho da chave AES.
    :param encrypted_file_path: Caminho para salvar o arquivo cifrado.
    """
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


def protect_aes_key(aes_key_path, public_key_path, output_path):
    """
    Cifra uma chave AES usando uma chave pública RSA.

    :param aes_key_path: Caminho do arquivo contendo a chave AES.
    :param public_key_path: Caminho do arquivo contendo a chave pública RSA.
    :param output_path: Caminho para salvar a chave AES cifrada.
    """
    # Lê a chave AES
    with open(aes_key_path, "rb") as aes_file:
        aes_key = aes_file.read()

    # Lê a chave pública RSA
    with open(public_key_path, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    # Cifra a chave AES com a chave pública RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Salva a chave AES cifrada
    with open(output_path, "wb") as output_file:
        output_file.write(encrypted_aes_key)


def verify_signature(file_path, signature_path, public_key_path):
    """
    Verifica a assinatura digital de um arquivo usando a chave pública RSA.

    :param file_path: Caminho do arquivo original.
    :param signature_path: Caminho do arquivo contendo a assinatura.
    :param public_key_path: Caminho da chave pública RSA para verificação.
    :return: True se a assinatura for válida, False caso contrário.
    """
    # Lê o arquivo original e a assinatura
    with open(file_path, "rb") as f:
        data = f.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    # Lê a chave pública
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    try:
        # Verifica a assinatura
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Assinatura válida
    except Exception as e:
        return False  # Assinatura inválida


def decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path):
    """
    Descriptografa um arquivo cifrado usando a chave privada RSA.

    :param encrypted_file_path: Caminho do arquivo cifrado.
    :param private_key_path: Caminho da chave privada RSA para descriptografar o arquivo.
    :param decrypted_file_path: Caminho para salvar o arquivo descriptografado.
    """
    # Lê o arquivo cifrado
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    # Lê a chave privada
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Descriptografa a chave AES usando a chave privada RSA
    decrypted_aes_key = private_key.decrypt(
        # Assumindo que a chave AES foi cifrada e tem tamanho fixo de 256 bytes
        encrypted_data[:256],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Extraímos o IV e o restante dos dados para a descriptografia do arquivo
    iv = encrypted_data[256:272]  # O IV deve ser o próximo bloco de 16 bytes
    cipher_data = encrypted_data[272:]

    # Descriptografa os dados do arquivo usando o AES
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()

    # Salva o arquivo descriptografado
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)
