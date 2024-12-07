from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def validate_rsa_keys(private_key_path, public_key_path):
    """
    Valida as chaves RSA carregando-as e verificando se a chave pública
    corresponde à chave privada.

    :param private_key_path: Caminho para a chave privada.
    :param public_key_path: Caminho para a chave pública.
    """
    try:
        # Carrega a chave privada
        with open(private_key_path, "rb") as priv_file:
            private_key = serialization.load_pem_private_key(
                priv_file.read(),
                password=None
            )
        
        # Verifica se a chave privada é do tipo RSA
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("A chave privada não é do tipo RSA.")

        # Carrega a chave pública
        with open(public_key_path, "rb") as pub_file:
            public_key = serialization.load_pem_public_key(
                pub_file.read()
            )
        
        # Verifica se a chave pública é do tipo RSA
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("A chave pública não é do tipo RSA.")
        
        # Verifica se a chave pública corresponde à privada
        private_numbers = private_key.private_numbers()
        public_numbers = public_key.public_numbers()

        if private_numbers.public_numbers != public_numbers:
            raise ValueError("A chave pública não corresponde à chave privada.")

        print("As chaves RSA são válidas e correspondentes.")
    except Exception as e:
        print(f"Erro ao validar as chaves: {e}")

if __name__ == "__main__":
    # Altere os caminhos abaixo para testar com seus arquivos
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"
    validate_rsa_keys(private_key_path, public_key_path)
