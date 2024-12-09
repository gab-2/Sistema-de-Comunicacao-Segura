import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def sign_file(file_path, private_key_path, signature_path):
    """
    Assina digitalmente um arquivo usando uma chave privada RSA.

    :param file_path: Caminho do arquivo a ser assinado.
    :param private_key_path: Caminho da chave privada RSA.
    :param signature_path: Caminho para salvar o arquivo da assinatura.
    """
    logging.debug(f"Iniciando a assinatura do arquivo: {file_path}")

    # Lê o arquivo original
    with open(file_path, "rb") as f:
        data = f.read()

    # Lê a chave privada
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Gera a assinatura
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Salva a assinatura em um arquivo separado
    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)

    logging.debug(f"Assinatura salva em: {signature_path}")


def encrypt_file(file_path, aes_key_path, encrypted_file_path):
    """
    Cifra um arquivo usando uma chave AES.

    :param file_path: Caminho do arquivo a ser cifrado.
    :param aes_key_path: Caminho da chave AES.
    :param encrypted_file_path: Caminho para salvar o arquivo cifrado.
    """
    logging.debug(f"Iniciando criptografia do arquivo: {file_path}")

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

    logging.debug(f"Arquivo criptografado salvo em: {encrypted_file_path}")


def protect_aes_key(aes_key_path, public_key_path, output_path):
    """
    Cifra uma chave AES usando uma chave pública RSA.

    :param aes_key_path: Caminho do arquivo contendo a chave AES.
    :param public_key_path: Caminho do arquivo contendo a chave pública RSA.
    :param output_path: Caminho para salvar a chave AES cifrada.
    """
    logging.debug("Protegendo a chave AES com a chave pública RSA.")

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

    logging.debug(f"Chave AES protegida salva em: {output_path}")


def verify_signature(file_path, signature_path, public_key_path):
    """
    Verifica a assinatura digital de um arquivo usando a chave pública RSA.

    :param file_path: Caminho do arquivo original.
    :param signature_path: Caminho do arquivo contendo a assinatura.
    :param public_key_path: Caminho da chave pública RSA para verificação.
    :return: True se a assinatura for válida, False caso contrário.
    """
    logging.debug("Verificando a assinatura digital.")

    # Lê o arquivo original
    with open(file_path, "rb") as f:
        data = f.read()

    # Lê a assinatura
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
        logging.debug("Assinatura válida.")
        return True
    except Exception as e:
        logging.error(f"Erro ao verificar a assinatura: {e}")
        return False
def decrypt_file(encrypted_file_path, private_key_content, decrypted_file_path):
    logging.debug(f"Descriptografando o arquivo: {encrypted_file_path}")

    try:
        # Carregar a chave privada
        private_key = serialization.load_pem_private_key(
            private_key_content,
            password=None,
        )
        logging.debug("Chave privada carregada com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao carregar a chave privada: {e}")
        raise ValueError(f"Erro ao carregar a chave privada: {e}")

    try:
        with open(encrypted_file_path, "rb") as ef:
            encrypted_data = ef.read()

        # Descriptografar a chave AES
        decrypted_aes_key = private_key.decrypt(
            encrypted_data[:256],  # Assume-se que os primeiros 256 bytes são a chave AES criptografada
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        logging.debug(f"Chave AES descriptografada: {decrypted_aes_key.hex()}")

        # Continuar com o processo de descriptografia
        iv = encrypted_data[256:272]
        cipher_data = encrypted_data[272:]

        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()

        # Salvar o arquivo descriptografado
        with open(decrypted_file_path, "wb") as df:
            df.write(decrypted_data)

        logging.debug(f"Arquivo descriptografado salvo em: {decrypted_file_path}")
    except Exception as e:
        logging.error(f"Erro durante o processo de descriptografia: {e}")
        raise ValueError(f"Erro durante o processo de descriptografia: {e}")


    # Descriptografar a chave AES com a chave privada RSA
    try:
        decrypted_aes_key = private_key.decrypt(
            encrypted_data[:256],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug(f"Chave AES descriptografada: {decrypted_aes_key.hex()}")
    except Exception as e:
        logging.error(f"Erro ao descriptografar a chave AES: {e}")
        raise ValueError(f"Erro ao descriptografar a chave AES: {e}")


    # Extrair IV e dados cifrados
    iv = encrypted_data[256:272]
    cipher_data = encrypted_data[272:]

    logging.debug(f"IV extraído: {iv.hex()}")
    logging.debug(f"Dados criptografados (primeiros 64 bytes): {cipher_data[:64].hex()}")

    # Descriptografar os dados do arquivo usando o AES
    try:
        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()
    except Exception as e:
        logging.error(f"Erro durante a descriptografia do conteúdo do arquivo: {e}")
        raise ValueError(f"Erro durante a descriptografia do conteúdo do arquivo: {e}")

    # Salvar o arquivo descriptografado
    try:
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)
        logging.debug(f"Arquivo descriptografado salvo em: {decrypted_file_path}")
    except Exception as e:
        logging.error(f"Erro ao salvar o arquivo descriptografado: {e}")
        raise ValueError(f"Erro ao salvar o arquivo descriptografado: {e}")
