from flask import Flask, render_template, request, jsonify, send_file, session
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography_module.crypto import validate_key_pair
import os
import zipfile
import hashlib
import logging
from cryptography_module.keys import generate_rsa_keys, generate_aes_key, load_rsa_private_key, load_rsa_public_key
from cryptography_module.crypto import sign_file, encrypt_file, protect_aes_key, decrypt_file, verify_signature
import zipfile
from datetime import datetime
import glob

# Configuração de logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_DIR = "uploaded_files"
GENERATED_DIR = "generated_files"
app = Flask(__name__)

app.secret_key = 'sua_chave_secreta_para_sessao'  # Adicione esta linha

# Pastas para salvar os arquivos gerados e enviados
SAVE_DIR = "generated_files"
UPLOAD_DIR = "uploaded_files"
os.makedirs(SAVE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Funções Auxiliares
def save_uploaded_file(file, directory, filename):
    if not file:
        return None, "Nenhum arquivo foi enviado."
    filepath = os.path.join(directory, filename)
    try:
        file.save(filepath)
        return filepath, None
    except Exception as e:
        return None, f"Erro ao salvar o arquivo: {e}"

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Rotas de navegação
@app.route("/")
def index():
    return render_template("etapa1.html", current_step=1)

@app.route("/etapa2", methods=["GET", "POST"])
def etapa2():
    if request.method == "POST":
        # Recebe o arquivo enviado pelo usuário
        file = request.files.get("arquivo_envio")
        if file:
            filepath = os.path.join(UPLOAD_DIR, file.filename)
            file.save(filepath)  # Salva o arquivo no diretório
            session["uploaded_file"] = filepath  # Salva o caminho do arquivo na sessão
            return jsonify({"message": "Arquivo enviado e salvo com sucesso.", "next_step": "/etapa3"})
        else:
            return jsonify({"error": "Nenhum arquivo foi enviado."}), 400
    return render_template("etapa2.html", current_step=2)

@app.route("/etapa3", methods=["GET", "POST"])
def etapa3():
    if request.method == "POST":
        # Recupera o arquivo salvo na etapa 2
        filepath = session.get("uploaded_file")
        if not filepath or not os.path.exists(filepath):
            logging.error("Arquivo da etapa 2 não encontrado.")
            return jsonify({"error": "Arquivo da etapa 2 não encontrado."}), 400

        logging.info(f"Arquivo recebido na etapa 3: {filepath}")

        # Define caminhos para as chaves
        private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
        aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")

        if not os.path.exists(private_key_path):
            logging.error("Chave privada não encontrada.")
            return jsonify({"error": "Chave privada não encontrada."}), 400
        if not os.path.exists(aes_key_path):
            logging.error("Chave AES não encontrada.")
            return jsonify({"error": "Chave AES não encontrada."}), 400

        logging.info(f"Caminho da chave privada: {private_key_path}")
        logging.info(f"Caminho da chave AES: {aes_key_path}")

        # Caminhos para os arquivos gerados
        signed_file_path = os.path.join(SAVE_DIR, f"signed_{os.path.basename(filepath)}")
        encrypted_file_path = os.path.join(SAVE_DIR, f"encrypted_{os.path.basename(filepath)}")

        try:
            # Assina o arquivo
            logging.info(f"Iniciando assinatura do arquivo: {filepath}")
            sign_file(filepath, private_key_path, signed_file_path)
            logging.info(f"Arquivo assinado salvo em: {signed_file_path}")

            # Criptografa o arquivo assinado
            logging.info(f"Iniciando criptografia do arquivo assinado: {signed_file_path}")
            encrypt_file(signed_file_path, aes_key_path, encrypted_file_path)
            logging.info(f"Arquivo criptografado salvo em: {encrypted_file_path}")

            # Salva no session para uso futuro
            session["processed_file"] = encrypted_file_path
            logging.info(f"Arquivo processado armazenado na sessão: {encrypted_file_path}")

            return jsonify({
                "message": "Arquivo assinado e cifrado com sucesso.",
                "signed_file": f"/download/signed_{os.path.basename(filepath)}",
                "encrypted_file": f"/download/encrypted_{os.path.basename(filepath)}"
            })

        except Exception as e:
            logging.error(f"Erro ao processar o arquivo na etapa 3: {str(e)}")
            return jsonify({"error": f"Erro ao processar o arquivo: {str(e)}"}), 500

    return render_template("etapa3.html", current_step=3)

@app.route("/etapa4")
def etapa4():
    return render_template("etapa4.html", current_step=4)

@app.route("/etapa5")
def etapa5():
    # Recupera os nomes dos arquivos e os redefine na sessão, se necessário
    encrypted_file_name = session.get("encrypted_file_name")
    signature_file_name = session.get("signature_file_name")
    if not signature_file_name:
        # Define o nome padrão com base no arquivo processado
        signature_file_name = f"signed_{encrypted_file_name.split('_', 1)[1]}"
        session["signature_file_name"] = signature_file_name

    logging.debug(f"Arquivo assinado disponível na sessão: {signature_file_name}")
    return render_template("etapa5.html", current_step=5)


@app.route("/etapa6")
def etapa6():
    return render_template("etapa6.html", current_step=6)

# Gerar chaves RSA
@app.route("/generate_rsa", methods=["POST"])
def generate_rsa():
    private_key, public_key = generate_rsa_keys()
    private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
    public_key_path = os.path.join(SAVE_DIR, "public_key.pem")
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_key)
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_key)
    return jsonify({
        "private_key": private_key.decode("utf-8"),
        "public_key": public_key.decode("utf-8"),
        "private_key_file": "/download/private_key",
        "public_key_file": "/download/public_key"
    })

# Gerar chave AES
@app.route("/generate_aes", methods=["POST"])
def generate_aes():
    aes_key = generate_aes_key()
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")
    with open(aes_key_path, "wb") as aes_file:
        aes_file.write(aes_key)
    return jsonify({
        "aes_key": aes_key.hex(),
        "aes_key_file": "/download/aes_key"
    })

@app.route('/download/package_zip', methods=['GET'])
def download_package_zip():
    try:
        # Caminhos dos arquivos individuais
        encrypted_file_path = glob.glob("generated_files/encrypted_*.pdf")
        signed_file_path = glob.glob("generated_files/*.sig")
        protected_key_path = os.path.join("generated_files", "protected_aes_key.pem")
        public_key_path = os.path.join("generated_files", "public_key.pem")

        # Verificar se os arquivos foram encontrados
        if not encrypted_file_path:
            logging.error("Arquivo cifrado não encontrado.")
            return jsonify({"error": "Arquivo cifrado não encontrado."}), 500
        if not signed_file_path:
            logging.error("Arquivo de assinatura não encontrado.")
            return jsonify({"error": "Arquivo de assinatura não encontrado."}), 500
        if not os.path.exists(protected_key_path):
            logging.error("Chave AES protegida não encontrada.")
            return jsonify({"error": "Chave AES protegida não encontrada."}), 500
        if not os.path.exists(public_key_path):
            logging.error("Chave pública não encontrada.")
            return jsonify({"error": "Chave pública não encontrada."}), 500

        # Nome do arquivo ZIP
        zip_file_path = os.path.join("generated_files", "package.zip")

        # Criar o arquivo ZIP
        with zipfile.ZipFile(zip_file_path, 'w') as zipf:
            zipf.write(encrypted_file_path[0], arcname=os.path.basename(encrypted_file_path[0]))
            zipf.write(signed_file_path[0], arcname=os.path.basename(signed_file_path[0]))
            zipf.write(protected_key_path, arcname="protected_aes_key.pem")
            zipf.write(public_key_path, arcname="public_key.pem")

        # Enviar o arquivo ZIP para download
        logging.info(f"Pacote ZIP criado com sucesso: {zip_file_path}")
        return send_file(zip_file_path, as_attachment=True, download_name="package.zip")

    except Exception as e:
        logging.error(f"Erro ao gerar ou enviar o ZIP: {str(e)}")
        return jsonify({"error": f"Erro ao gerar ou enviar o ZIP: {str(e)}"}), 500

@app.route('/download/signed_file', methods=['GET']) 
def download_signed_file():
    try:
        # Verifica se o nome do arquivo de assinatura está na sessão
        logging.debug(f"Estado atual da sessão: {session}")
        signed_file_name = session.get("signature_file_name")
        if not signed_file_name:
            raise FileNotFoundError("Nome do arquivo assinado não encontrado na sessão.")

        # Caminho completo para o arquivo assinado
        signed_file_path = os.path.join(SAVE_DIR, signed_file_name)
        logging.info(f"Tentativa de download do arquivo assinado: {signed_file_path}")

        # Verifica se o arquivo existe
        if not os.path.exists(signed_file_path):
            raise FileNotFoundError(f"Arquivo assinado não encontrado no caminho: {signed_file_path}")

        # Retorna o arquivo para download
        return send_file(signed_file_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Erro ao baixar o arquivo assinado: {str(e)}")
        return jsonify({"error": str(e)}), 404

# Rota para download da chave AES
@app.route('/download/aes_key', methods=['GET'])
def download_aes_key():
    try:
        aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")
        
        # Verifica se o arquivo existe
        if not os.path.exists(aes_key_path):
            raise FileNotFoundError(f"Arquivo não encontrado: {aes_key_path}")
        
        # Retorna o arquivo para download
        return send_file(aes_key_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/download/private_key', methods=['GET'])
def download_private_key():
    try:
        # Caminho absoluto para a chave privada
        private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
        
        # Verifique se o arquivo existe
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Arquivo não encontrado: {private_key_path}")
        
        # Retorne o arquivo
        return send_file(private_key_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 404
    
@app.route('/download/encrypted_file', methods=['GET'])
def download_encrypted_file():
    try:
        encrypted_file_name = session.get("encrypted_file_name")
        if not encrypted_file_name:
            logging.error("Nome do arquivo criptografado não encontrado na sessão.")
            return jsonify({"error": "Nome do arquivo criptografado não encontrado na sessão."}), 404

        encrypted_file_path = os.path.join(SAVE_DIR, encrypted_file_name)
        if not os.path.exists(encrypted_file_path):
            logging.error(f"Arquivo criptografado não encontrado: {encrypted_file_path}")
            return jsonify({"error": "Arquivo criptografado não encontrado."}), 404

        return send_file(encrypted_file_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Erro ao baixar o arquivo criptografado: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/download/processed_file', methods=['GET'])
def download_processed_file():
    try:
        processed_file_path = session.get("processed_file")
        if not processed_file_path or not os.path.exists(processed_file_path):
            raise FileNotFoundError("Arquivo processado não encontrado.")
        return send_file(processed_file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route('/download/public_key', methods=['GET'])
def download_public_key():
    try:
        # Caminho absoluto para a chave pública
        public_key_path = os.path.join(SAVE_DIR, "public_key.pem")
        
        # Verifique se o arquivo existe
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Arquivo não encontrado: {public_key_path}")
        
        # Retorne o arquivo
        return send_file(public_key_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 404
@app.route("/send_package", methods=["POST"])
def send_package():
    try:
        # Receber os arquivos do formulário
        encrypted_file = request.files.get("encrypted_file")
        signature_file = request.files.get("signature_file")
        protected_aes_key = request.files.get("protected_aes_key")

        # Verificar se todos os arquivos foram enviados
        if not all([encrypted_file, signature_file, protected_aes_key]):
            logging.error("Faltam arquivos necessários para o envio do pacote.")
            return jsonify({"error": "Todos os arquivos (arquivo cifrado, assinatura e chave protegida) são necessários."}), 400

        # Remova ou comente as validações de extensão
        # Salvar os arquivos no diretório de uploads
        encrypted_file_path, error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)
        if error:
            logging.error(f"Erro ao salvar arquivo cifrado: {error}")
            return jsonify({"error": f"Erro ao salvar arquivo cifrado: {error}"}), 500
        logging.info(f"Arquivo cifrado salvo com sucesso: {encrypted_file_path}")

        signature_file_path, error = save_uploaded_file(signature_file, UPLOAD_DIR, signature_file.filename)
        if error:
            logging.error(f"Erro ao salvar assinatura: {error}")
            return jsonify({"error": f"Erro ao salvar assinatura: {error}"}), 500
        logging.info(f"Assinatura salva com sucesso: {signature_file_path}")

        protected_key_path, error = save_uploaded_file(protected_aes_key, UPLOAD_DIR, protected_aes_key.filename)
        if error:
            logging.error(f"Erro ao salvar chave protegida: {error}")
            return jsonify({"error": f"Erro ao salvar chave protegida: {error}"}), 500
        logging.info(f"Chave AES protegida salva com sucesso: {protected_key_path}")

        logging.info("Pacote enviado e armazenado com sucesso.")
        return jsonify({
            "message": "Pacote enviado e armazenado com sucesso.",
            "files": {
                "encrypted_file": encrypted_file.filename,
                "signature_file": signature_file.filename,
                "protected_aes_key": protected_aes_key.filename
            }
        })

    except Exception as e:
        logging.error(f"Erro ao enviar pacote: {str(e)}")
        return jsonify({"error": f"Erro ao enviar pacote: {str(e)}"}), 500

ALLOWED_ENCRYPTED_EXTENSIONS = [".pdf", ".enc", ".zip", ".pem", ".sig", ".pem.sig"]

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        # Caminho completo do arquivo
        file_path = os.path.join(SAVE_DIR, filename)

        # Verifica se o arquivo existe
        if not os.path.exists(file_path):
            logging.error(f"Arquivo {filename} não encontrado no servidor.")
            return jsonify({"error": f"Arquivo {filename} não encontrado no servidor."}), 404

        # Retorna o arquivo para download
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Erro ao tentar enviar o arquivo: {str(e)}")
        return jsonify({"error": f"Erro ao processar o download: {str(e)}"}), 500

# Upload de arquivos
@app.route("/upload_file", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "Nenhum arquivo foi enviado."}), 400

    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)

    return jsonify({
        "message": "Arquivo carregado com sucesso.",
        "filename": file.filename
    })
@app.route("/sign_and_encrypt", methods=["POST"])
def sign_and_encrypt():
    try:
        # Recebe as informações do arquivo enviadas pelo frontend
        file_info = request.json  # Frontend deve enviar dados em JSON contendo o nome do arquivo
        file_name = file_info.get("name")  # Obtém o nome do arquivo

        if not file_name:
            logging.error("Nome do arquivo não foi enviado pelo frontend.")
            return jsonify({"error": "Nome do arquivo não foi enviado pelo frontend."}), 400

        # Localiza o arquivo no diretório de uploads
        file_path = os.path.join(UPLOAD_DIR, file_name)
        if not os.path.exists(file_path):
            logging.error(f"Arquivo {file_name} não encontrado no diretório {UPLOAD_DIR}.")
            return jsonify({"error": f"Arquivo {file_name} não foi encontrado no servidor."}), 404

        # Caminhos para a chave privada e a chave AES
        private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
        aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")

        # Verifica se as chaves necessárias existem
        if not os.path.exists(private_key_path):
            logging.error("Chave privada não encontrada no servidor.")
            return jsonify({"error": "Chave privada não foi encontrada no servidor."}), 400
        if not os.path.exists(aes_key_path):
            logging.error("Chave AES não encontrada no servidor.")
            return jsonify({"error": "Chave AES não foi encontrada no servidor."}), 400

        # Define os caminhos para os arquivos assinados, cifrados e de assinatura
        signed_file_path = os.path.join(SAVE_DIR, f"signed_{file_name}")
        encrypted_file_path = os.path.join(SAVE_DIR, f"encrypted_{file_name}")
        signature_file_path = os.path.join(SAVE_DIR, f"{file_name}.sig")

        # Assina o arquivo
        logging.info(f"Iniciando assinatura do arquivo: {file_path}")
        sign_file(file_path, private_key_path, signature_file_path)  # Ajustado para salvar a assinatura separadamente
        logging.info(f"Assinatura gerada e salva em: {signature_file_path}")

        # Criptografa o arquivo original
        logging.info(f"Iniciando cifragem do arquivo: {file_path}")
        encrypt_file(file_path, aes_key_path, encrypted_file_path)
        logging.info(f"Arquivo cifrado salvo em: {encrypted_file_path}")

        # Armazena os nomes dos arquivos gerados na sessão
        session["encrypted_file_name"] = f"encrypted_{file_name}"
        session["signature_file_name"] = f"{file_name}.sig"
        logging.debug(f"Nome do arquivo de assinatura armazenado na sessão: {session['signature_file_name']}")

        # Retorna os caminhos para download
        return jsonify({
            "message": "Arquivo assinado e cifrado com sucesso.",
            "signature_file": f"/download/{file_name}.sig",  # Caminho para download do arquivo de assinatura
            "encrypted_file": f"/download/encrypted_{file_name}"  # Caminho para download do arquivo cifrado
        })

    except Exception as e:
        # Registra o erro e retorna uma mensagem ao frontend
        logging.error(f"Erro durante o processo de assinatura ou cifragem: {str(e)}")
        return jsonify({"error": f"Erro durante o processo de assinatura ou cifragem: {str(e)}"}), 500



@app.route("/get_file_names", methods=["GET"])
def get_file_names():
    try:
        # Recupera os nomes dos arquivos da sessão
        encrypted_file_name = session.get("encrypted_file_name")
        signed_file_name = session.get("signed_file_name")
        protected_aes_key = "protected_aes_key.pem"  # Nome fixo do arquivo de chave protegida

        # Verifica se os nomes existem na sessão
        if not encrypted_file_name or not signed_file_name:
            raise FileNotFoundError("Nomes dos arquivos não encontrados na sessão.")

        return jsonify({
            "encrypted_file_name": encrypted_file_name,
            "signed_file_name": signed_file_name,
            "protected_aes_key": protected_aes_key
        })

    except Exception as e:
        logging.error(f"Erro ao obter nomes dos arquivos: {e}")
        return jsonify({"error": str(e)}), 500


# Proteger chave AES com chave pública
@app.route("/protect_aes_key", methods=["POST"])
def protect_aes_key_route():
    public_key_path = os.path.join(SAVE_DIR, "public_key.pem")  # Ajuste aqui para o caminho correto
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")  # Chave AES gerada na etapa anterior
    protected_aes_key_path = os.path.join(SAVE_DIR, "protected_aes_key.pem")  # Saída da chave protegida

    if not os.path.exists(public_key_path):
        logging.error(f"Chave pública não encontrada em {public_key_path}")
        return jsonify({"error": "Chave pública não encontrada."}), 400
    if not os.path.exists(aes_key_path):
        logging.error(f"Chave AES não encontrada em {aes_key_path}")
        return jsonify({"error": "Chave AES não encontrada."}), 400

    try:
        protect_aes_key(aes_key_path, public_key_path, protected_aes_key_path)
        return jsonify({
            "message": "Chave AES protegida com sucesso.",
            "protected_key_file": f"/download/protected_aes_key.pem"
        })
    except Exception as e:
        logging.error(f"Erro ao proteger a chave AES: {e}")
        return jsonify({"error": f"Erro ao proteger a chave AES: {e}"}), 500



# Endpoint para descriptografar um arquivo
@app.route("/decrypt_file", methods=["POST"])
def handle_decrypt_file():
    try:
        logging.debug("Recebendo arquivos para descriptografia.")
        private_key_file = request.files.get("private_key_file")
        encrypted_file = request.files.get("encrypted_file")

        if not private_key_file or not encrypted_file:
            logging.error("Arquivos necessários não foram enviados.")
            return jsonify({"error": "Os arquivos da chave privada e do arquivo criptografado são obrigatórios."}), 400

        # Salvar os arquivos recebidos
        private_key_path, private_key_error = save_uploaded_file(private_key_file, UPLOAD_DIR, "private_key.pem")
        encrypted_file_path, encrypted_file_error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)

        if private_key_error or encrypted_file_error:
            logging.error(f"Erro ao salvar arquivos enviados: {private_key_error or encrypted_file_error}")
            return jsonify({"error": private_key_error or encrypted_file_error}), 500

        # Criar diretório para arquivos extraídos
        extracted_dir = os.path.join(UPLOAD_DIR, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        # Verificar se o arquivo é um ZIP válido
        if not zipfile.is_zipfile(encrypted_file_path):
            logging.error("O arquivo enviado não é um pacote ZIP válido.")
            return jsonify({"error": "O arquivo enviado não é um pacote ZIP válido."}), 400

        # Extrair os arquivos do ZIP
        with zipfile.ZipFile(encrypted_file_path, "r") as zip_ref:
            zip_ref.extractall(extracted_dir)

        extracted_files = os.listdir(extracted_dir)
        logging.info(f"Arquivos extraídos: {extracted_files}")

        # Inicializar variáveis para os arquivos esperados
        protected_key_file, encrypted_data_file, signature_file, public_key_file = None, None, None, None

        # Identificar os arquivos extraídos
        for file in extracted_files:
            if file.startswith("encrypted_") and file.endswith(".pdf"):
                encrypted_data_file = os.path.join(extracted_dir, file)
            elif file.endswith(".pem") and "aes" in file:
                protected_key_file = os.path.join(extracted_dir, file)
            elif file.startswith("signed_") and file.endswith(".pdf"):
                signature_file = os.path.join(extracted_dir, file)
            elif file.endswith(".pem") and "public" in file:
                public_key_file = os.path.join(extracted_dir, file)

        # Verificar se todos os arquivos necessários foram encontrados
        if not protected_key_file or not encrypted_data_file or not signature_file or not public_key_file:
            logging.error("Arquivos necessários ausentes no pacote.")
            return jsonify({"error": "Arquivos necessários ausentes no pacote."}), 400

        # Validar correspondência das chaves pública e privada
        logging.debug("Validando correspondência das chaves pública e privada.")
        validate_key_pair(private_key_path, public_key_file)

        # Descriptografar a chave AES protegida
        with open(protected_key_file, "rb") as pk_file, open(private_key_path, "rb") as private_key:
            protected_aes_key = pk_file.read()
            private_key_data = serialization.load_pem_private_key(private_key.read(), password=None)
            aes_key = private_key_data.decrypt(
                protected_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.debug(f"Chave AES descriptografada: {aes_key.hex()}")

        # Descriptografar o arquivo de dados
        with open(encrypted_data_file, "rb") as enc_file:
            encrypted_data = enc_file.read()
            iv = encrypted_data[:16]
            cipher_data = encrypted_data[16:]
            logging.debug(f"IV extraído: {iv.hex()}")
            logging.debug(f"Tamanho dos dados cifrados: {len(cipher_data)} bytes")

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB8(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()
            logging.debug(f"Tamanho dos dados descriptografados: {len(decrypted_data)} bytes")
            logging.debug(f"Dados descriptografados (primeiros 100 bytes): {decrypted_data[:100].hex()}")

        # Verificar a assinatura digital
        with open(signature_file, "rb") as sig_file, open(public_key_file, "rb") as pub_key_file:
            signature = sig_file.read()
            public_key = serialization.load_pem_public_key(pub_key_file.read())
            logging.debug(f"Tamanho da assinatura: {len(signature)} bytes")
            logging.debug(f"Assinatura (hex): {signature[:100].hex()}")

            try:
                logging.debug("Iniciando verificação da assinatura.")
                public_key.verify(
                    signature,
                    decrypted_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                logging.info("Assinatura verificada com sucesso.")
            except Exception as e:
                logging.error(f"Erro ao verificar a assinatura: {e}")
                logging.error("Verifique se os dados descriptografados e a assinatura correspondem.")
                logging.error(f"Assinatura (hex): {signature.hex()}")
                logging.error(f"Dados descriptografados (hex): {decrypted_data.hex()}")
                return jsonify({"error": "Erro ao verificar a assinatura"}), 400

        # Salvar o arquivo descriptografado
        decrypted_file_path = os.path.join(SAVE_DIR, f"decrypted_{os.path.basename(encrypted_data_file)}")
        with open(decrypted_file_path, "wb") as dec_file:
            dec_file.write(decrypted_data)
        logging.info(f"Arquivo descriptografado salvo em: {decrypted_file_path}")

        # Retornar o caminho para o cliente
        return jsonify({
            "message": "Arquivo descriptografado e assinatura verificada com sucesso.",
            "decrypted_file": f"/download/{os.path.basename(decrypted_file_path)}"
        }), 200

    except Exception as e:
        logging.error(f"Erro durante o processo de descriptografia: {e}")
        return jsonify({"error": "Erro interno no servidor."}), 500


# Validar arquivo e assinatura
@app.route("/validate_file", methods=["POST"])
def validate_file():
    try:
        # Receber os arquivos enviados
        encrypted_file = request.files.get("encrypted_file")
        signature_file = request.files.get("signature_file")
        public_key_file = request.files.get("public_key_file")
        private_key_file = request.files.get("private_key_file")

        if not all([encrypted_file, signature_file, public_key_file, private_key_file]):
            return jsonify({"error": "Todos os arquivos devem ser enviados."}), 400

        # Salvar os arquivos
        encrypted_file_path, enc_error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)
        signature_file_path, sig_error = save_uploaded_file(signature_file, UPLOAD_DIR, signature_file.filename)
        public_key_path, pub_error = save_uploaded_file(public_key_file, UPLOAD_DIR, public_key_file.filename)
        private_key_path, priv_error = save_uploaded_file(private_key_file, UPLOAD_DIR, private_key_file.filename)

        # Verificar erros individuais
        if any([enc_error, sig_error, pub_error, priv_error]):
            return jsonify({"error": enc_error or sig_error or pub_error or priv_error}), 400

        # Verificar a assinatura
        logging.info("Validando assinatura...")
        is_signature_valid = verify_signature(encrypted_file_path, signature_file_path, public_key_path)
        if not is_signature_valid:
            logging.error("A assinatura é inválida.")
            return jsonify({"error": "A assinatura é inválida."}), 400

        # Descriptografar o arquivo
        decrypted_file_path = os.path.join(SAVE_DIR, f"decrypted_{encrypted_file.filename}")
        decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path)
        logging.info(f"Arquivo descriptografado salvo em: {decrypted_file_path}")

        # Retornar o caminho do arquivo descriptografado
        return jsonify({
            "message": "Arquivo validado com sucesso!",
            "decrypted_file": f"/download/{os.path.basename(decrypted_file_path)}"
        })
    except Exception as e:
        logging.error(f"Erro durante a validação do arquivo: {e}")
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
