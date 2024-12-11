import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def validate_key_pair(private_key_path, public_key_path):
    """
    Valida se uma chave privada RSA corresponde à chave pública.

    :param private_key_path: Caminho da chave privada.
    :param public_key_path: Caminho da chave pública.
    """
    try:
        logging.debug(f"Carregando chave privada de: {private_key_path}")
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None  # Substituir por senha se necessário
            )
        
        logging.debug(f"Carregando chave pública de: {public_key_path}")
        with open(public_key_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())

        private_public_match = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) == public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if private_public_match:
            logging.debug("As chaves pública e privada correspondem.")
        else:
            logging.error("As chaves pública e privada não correspondem.")
            raise ValueError("As chaves pública e privada não correspondem.")

    except Exception as e:
        logging.error(f"Erro ao validar chaves RSA: {e}")
        raise


def validate_encrypted_file(file_path):
    """
    Valida um arquivo cifrado para verificar integridade básica.

    :param file_path: Caminho do arquivo cifrado.
    """
    try:
        logging.debug(f"Validando arquivo cifrado em: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()

        logging.debug(f"Tamanho do arquivo criptografado: {len(data)} bytes")
        assert len(data) > 272, "O arquivo criptografado está incompleto ou corrompido."
        iv = data[256:272]
        assert len(iv) == 16, "IV extraído do arquivo não possui 16 bytes."
        logging.debug(f"IV validado: {iv.hex()}")
    except Exception as e:
        logging.error(f"Erro ao validar o arquivo criptografado: {e}")
        raise


def sign_file(file_path, private_key_path, signature_path):
    """
    Assina digitalmente um arquivo usando uma chave privada RSA.

    :param file_path: Caminho do arquivo a ser assinado.
    :param private_key_path: Caminho da chave privada RSA.
    :param signature_path: Caminho para salvar o arquivo da assinatura.
    """
    try:
        logging.debug(f"Iniciando a assinatura do arquivo: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  # Substituir por senha se necessário
            )

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open(signature_path, "wb") as sig_file:
            sig_file.write(signature)

        logging.debug(f"Assinatura salva em: {signature_path}")
    except Exception as e:
        logging.error(f"Erro ao assinar o arquivo: {e}")
        raise


def verify_signature(file_path, signature_path, public_key_path):
    """
    Verifica a assinatura digital de um arquivo usando a chave pública RSA.

    :param file_path: Caminho do arquivo original.
    :param signature_path: Caminho do arquivo contendo a assinatura.
    :param public_key_path: Caminho da chave pública RSA para verificação.
    :return: True se a assinatura for válida, False caso contrário.
    """
    try:
        logging.debug("Verificando a assinatura digital.")

        with open(file_path, "rb") as f:
            data = f.read()

        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        logging.debug(f"Tamanho do arquivo original: {len(data)} bytes")
        logging.debug(f"Dados originais (primeiros 100 bytes): {data[:100].hex()}")
        logging.debug(f"Tamanho da assinatura: {len(signature)} bytes")

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logging.debug("Assinatura válida.")
        return True
    except Exception as e:
        logging.error(f"Erro ao verificar a assinatura: {e}")
        raise


def encrypt_file(file_path, aes_key_path, encrypted_file_path):
    """
    Cifra um arquivo usando uma chave AES.

    :param file_path: Caminho do arquivo a ser cifrado.
    :param aes_key_path: Caminho da chave AES.
    :param encrypted_file_path: Caminho para salvar o arquivo cifrado.
    """
    try:
        logging.debug(f"Iniciando criptografia do arquivo: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        with open(aes_key_path, "rb") as key_file:
            aes_key = key_file.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        logging.debug(f"Arquivo criptografado salvo em: {encrypted_file_path}")
    except Exception as e:
        logging.error(f"Erro ao criptografar o arquivo: {e}")
        raise


def decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path):
    """
    Descriptografa um arquivo cifrado usando uma chave privada RSA.

    :param encrypted_file_path: Caminho do arquivo cifrado.
    :param private_key_path: Caminho da chave privada RSA.
    :param decrypted_file_path: Caminho para salvar o arquivo descriptografado.
    """
    try:
        logging.debug(f"Descriptografando o arquivo: {encrypted_file_path}")

        # Validar chaves e arquivo criptografado
        validate_key_pair(private_key_path, "public_key.pem")
        validate_encrypted_file(encrypted_file_path)

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  # Substituir por senha se necessário
            )

        with open(encrypted_file_path, "rb") as ef:
            encrypted_data = ef.read()

        logging.debug(f"Tamanho do arquivo criptografado: {len(encrypted_data)} bytes")

        decrypted_aes_key = private_key.decrypt(
            encrypted_data[:256],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        logging.debug(f"Chave AES descriptografada: {decrypted_aes_key.hex()}")

        iv = encrypted_data[256:272]
        cipher_data = encrypted_data[272:]
        logging.debug(f"IV extraído: {iv.hex()}")
        logging.debug(f"Tamanho dos dados cifrados: {len(cipher_data)} bytes")

        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()

        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        logging.debug(f"Arquivo descriptografado salvo em: {decrypted_file_path}")
        logging.debug(f"Tamanho dos dados descriptografados: {len(decrypted_data)} bytes")
        logging.debug(f"Dados descriptografados (primeiros 100 bytes): {decrypted_data[:100].hex()}")
    except Exception as e:
        logging.error(f"Erro ao descriptografar o arquivo: {e}")
        raise


def protect_aes_key(aes_key_path, public_key_path, output_path):
    """
    Cifra uma chave AES usando uma chave pública RSA.

    :param aes_key_path: Caminho do arquivo contendo a chave AES.
    :param public_key_path: Caminho do arquivo contendo a chave pública RSA.
    :param output_path: Caminho para salvar a chave AES cifrada.
    """
    try:
        logging.debug("Protegendo a chave AES com a chave pública RSA.")

        with open(aes_key_path, "rb") as aes_file:
            aes_key = aes_file.read()

        with open(public_key_path, "rb") as pub_file:
            public_key = serialization.load_pem_public_key(pub_file.read())

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_path, "wb") as output_file:
            output_file.write(encrypted_aes_key)

        logging.debug(f"Chave AES protegida salva em: {output_path}")
    except Exception as e:
        logging.error(f"Erro ao proteger a chave AES: {e}")
        raise


def generate_file_hash(file_path):
    """
    Gera um hash SHA-256 de um arquivo.

    :param file_path: Caminho do arquivo.
    :return: Hash do arquivo em formato hexadecimal.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        file_hash = digest.finalize()

        logging.debug(f"Hash SHA-256 gerado para {file_path}: {file_hash.hex()}")
        return file_hash
    except Exception as e:
        logging.error(f"Erro ao gerar hash do arquivo: {e}")
        raise
