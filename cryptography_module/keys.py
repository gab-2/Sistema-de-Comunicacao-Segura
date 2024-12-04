from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_rsa_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def generate_aes_key():
    """Gera uma chave simétrica AES."""
    return get_random_bytes(16)
