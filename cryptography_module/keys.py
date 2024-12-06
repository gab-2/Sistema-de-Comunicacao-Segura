from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def generate_aes_key():
    """Gera uma chave simétrica AES."""
    return get_random_bytes(16)


def load_rsa_private_key(private_key_path):
    """
    Carrega a chave privada RSA a partir de um arquivo PEM.

    :param private_key_path: Caminho do arquivo PEM contendo a chave privada.
    :return: A chave privada RSA.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


def load_rsa_public_key(public_key_path):
    """
    Carrega a chave pública RSA a partir de um arquivo PEM.

    :param public_key_path: Caminho do arquivo PEM contendo a chave pública.
    :return: A chave pública RSA.
    """
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key


def save_rsa_private_key(private_key, private_key_path):
    """
    Salva a chave privada RSA em um arquivo PEM.

    :param private_key: A chave privada RSA a ser salva.
    :param private_key_path: Caminho do arquivo onde a chave privada será salva.
    """
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key)


def save_rsa_public_key(public_key, public_key_path):
    """
    Salva a chave pública RSA em um arquivo PEM.

    :param public_key: A chave pública RSA a ser salva.
    :param public_key_path: Caminho do arquivo onde a chave pública será salva.
    """
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key)
