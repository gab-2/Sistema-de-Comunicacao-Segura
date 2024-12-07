import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """
    Gera um par de chaves RSA (privada e pública).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serializar a chave privada
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar a chave pública
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

def generate_aes_key(key_size=16):
    """
    Gera uma chave simétrica AES de tamanho especificado.
    """
    if key_size not in (16, 24, 32):  # 16 bytes = 128 bits, 24 bytes = 192 bits, 32 bytes = 256 bits
        raise ValueError("O tamanho da chave deve ser 16, 24 ou 32 bytes.")
    return os.urandom(key_size)

def load_rsa_private_key(private_key_path, password=None):
    """
    Carrega uma chave privada RSA a partir de um arquivo PEM.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
        )
    return private_key

def load_rsa_public_key(public_key_path):
    """
    Carrega uma chave pública RSA a partir de um arquivo PEM.
    """
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key
