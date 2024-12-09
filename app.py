from flask import Flask, render_template, request, jsonify, send_file, session
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import zipfile
import hashlib
import logging
from cryptography_module.keys import generate_rsa_keys, generate_aes_key, load_rsa_private_key, load_rsa_public_key
from cryptography_module.crypto import sign_file, encrypt_file, protect_aes_key, decrypt_file, verify_signature
import zipfile



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
        # Diretório onde os arquivos são armazenados
        generated_dir = "generated_files"

        # Procurar pelos arquivos dinamicamente (substitua pelo critério adequado)
        encrypted_file_path = os.path.join(generated_dir, next(
            (f for f in os.listdir(generated_dir) if f.startswith("encrypted_")), None))
        signed_file_path = os.path.join(generated_dir, next(
            (f for f in os.listdir(generated_dir) if f.startswith("signed_")), None))
        protected_key_path = os.path.join(generated_dir, "protected_aes_key.pem")  # Este parece ser fixo

        # Verificar se todos os arquivos foram encontrados
        if not encrypted_file_path or not os.path.exists(encrypted_file_path):
            app.logger.error(f"Arquivo não encontrado: {encrypted_file_path}")
            return jsonify({"error": f"Arquivo não encontrado: {encrypted_file_path}"}), 404
        if not signed_file_path or not os.path.exists(signed_file_path):
            app.logger.error(f"Arquivo não encontrado: {signed_file_path}")
            return jsonify({"error": f"Arquivo não encontrado: {signed_file_path}"}), 404
        if not os.path.exists(protected_key_path):
            app.logger.error(f"Arquivo não encontrado: {protected_key_path}")
            return jsonify({"error": f"Arquivo não encontrado: {protected_key_path}"}), 404

        app.logger.info("Todos os arquivos necessários foram encontrados.")

        # Nome do arquivo ZIP
        zip_file_path = os.path.join(generated_dir, "package.zip")

        # Criar o arquivo ZIP
        app.logger.info("Iniciando a criação do arquivo ZIP...")
        with zipfile.ZipFile(zip_file_path, 'w') as zipf:
            zipf.write(encrypted_file_path, arcname=os.path.basename(encrypted_file_path))
            zipf.write(signed_file_path, arcname=os.path.basename(signed_file_path))
            zipf.write(protected_key_path, arcname=os.path.basename(protected_key_path))

        # Verificar se o arquivo ZIP foi criado
        if not os.path.exists(zip_file_path):
            app.logger.error("Falha ao criar o arquivo ZIP.")
            return jsonify({"error": "Falha ao criar o arquivo ZIP."}), 500

        app.logger.info(f"Arquivo ZIP criado com sucesso: {zip_file_path}")

        # Enviar o arquivo ZIP para download
        return send_file(zip_file_path, mimetype='application/zip', as_attachment=True, download_name="package.zip")

    except Exception as e:
        # Log do erro para depuração
        app.logger.error(f"Erro ao gerar ou enviar o ZIP: {str(e)}")
        return jsonify({"error": f"Erro ao gerar ou enviar o ZIP: {str(e)}"}), 500



@app.route('/download/signed_file', methods=['GET'])
def download_signed_file():
    try:
        # Busca o nome do arquivo assinado armazenado na sessão
        signed_file_name = session.get("signed_file_name")
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
        # Busca o nome do arquivo cifrado armazenado na sessão
        encrypted_file_name = session.get("encrypted_file_name")
        if not encrypted_file_name:
            raise FileNotFoundError("Nome do arquivo cifrado não encontrado na sessão.")

        # Caminho completo para o arquivo cifrado
        encrypted_file_path = os.path.join(SAVE_DIR, encrypted_file_name)
        logging.info(f"Tentativa de download do arquivo cifrado: {encrypted_file_path}")

        # Verifica se o arquivo existe
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"Arquivo cifrado não encontrado no caminho: {encrypted_file_path}")

        # Retorna o arquivo para download
        return send_file(encrypted_file_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Erro ao baixar o arquivo cifrado: {str(e)}")
        return jsonify({"error": str(e)}), 404


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

        # Salvar os arquivos no diretório de uploads
        encrypted_file_path, error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)
        if error:
            logging.error(f"Erro ao salvar arquivo cifrado: {error}")
            return jsonify({"error": f"Erro ao salvar arquivo cifrado: {error}"}), 400
        logging.info(f"Arquivo cifrado salvo com sucesso: {encrypted_file_path}")

        signature_file_path, error = save_uploaded_file(signature_file, UPLOAD_DIR, signature_file.filename)
        if error:
            logging.error(f"Erro ao salvar assinatura: {error}")
            return jsonify({"error": f"Erro ao salvar assinatura: {error}"}), 400
        logging.info(f"Assinatura salva com sucesso: {signature_file_path}")

        protected_key_path, error = save_uploaded_file(protected_aes_key, UPLOAD_DIR, protected_aes_key.filename)
        if error:
            logging.error(f"Erro ao salvar chave protegida: {error}")
            return jsonify({"error": f"Erro ao salvar chave protegida: {error}"}), 400
        logging.info(f"Chave AES protegida salva com sucesso: {protected_key_path}")

        # Responder sucesso com os nomes dos arquivos salvos
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
@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    try:
        # Obter arquivos enviados
        private_key_file = request.files.get('private_key_file')
        encrypted_file = request.files.get('encrypted_file')

        # Validar se os arquivos foram enviados
        if not private_key_file:
            return jsonify({"error": "Arquivo de chave privada não enviado."}), 400
        if not encrypted_file:
            return jsonify({"error": "Arquivo criptografado não enviado."}), 400

        # Salvar arquivos no diretório temporário
        private_key_path = os.path.join("uploaded_files", "private_key.pem")
        encrypted_file_path = os.path.join("uploaded_files", encrypted_file.filename)

        private_key_file.save(private_key_path)
        encrypted_file.save(encrypted_file_path)

        # Verificar se o arquivo criptografado é um ZIP
        extracted_dir = os.path.join("uploaded_files", "extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        if zipfile.is_zipfile(encrypted_file_path):
            with zipfile.ZipFile(encrypted_file_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)

            # Verificar dinamicamente os arquivos extraídos
            extracted_files = os.listdir(extracted_dir)
            protected_key_file = None
            encrypted_data_file = None
            signature_file = None

            # Identificar arquivos baseados em extensões ou padrões
            for file in extracted_files:
                if file.endswith('.pem') and 'aes' in file:
                    protected_key_file = os.path.join(extracted_dir, file)
                elif file.endswith('.pdf') or file.endswith('.enc'):
                    encrypted_data_file = os.path.join(extracted_dir, file)
                elif file.endswith('.sig') or file.startswith('signed'):
                    signature_file = os.path.join(extracted_dir, file)

            # Validar se todos os arquivos necessários foram encontrados
            if not protected_key_file:
                return jsonify({"error": "Arquivo de chave AES protegida não encontrado no pacote."}), 400
            if not encrypted_data_file:
                return jsonify({"error": "Arquivo criptografado não encontrado no pacote."}), 400
            if not signature_file:
                return jsonify({"error": "Arquivo de assinatura não encontrado no pacote."}), 400

            # Continue com o processamento usando os arquivos identificados
            # Exemplo: descriptografar, verificar assinatura, etc.
            # ...

            return jsonify({"message": "Arquivos processados com sucesso!"}), 200
        else:
            return jsonify({"error": "O arquivo enviado não é um pacote ZIP válido."}), 400

    except Exception as e:
        logging.error(f"Erro durante a descriptografia: {e}")
        return jsonify({"error": "Erro interno no servidor. Verifique os logs para mais detalhes."}), 500


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
    # Recebe as informações do arquivo enviadas pelo frontend
    file_info = request.json  # Frontend deve enviar dados em JSON contendo o nome do arquivo
    file_name = file_info.get("name")  # Obtém o nome do arquivo

    if not file_name:
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

    # Define os caminhos para os arquivos assinados e cifrados
    signed_file_path = os.path.join(SAVE_DIR, f"signed_{file_name}")
    encrypted_file_path = os.path.join(SAVE_DIR, f"encrypted_{file_name}")

    try:
        # Assina o arquivo
        logging.info(f"Iniciando assinatura do arquivo: {file_path}")
        sign_file(file_path, private_key_path, signed_file_path)
        logging.info(f"Arquivo assinado salvo em: {signed_file_path}")

        # Criptografa o arquivo assinado
        logging.info(f"Iniciando cifragem do arquivo: {signed_file_path}")
        encrypt_file(signed_file_path, aes_key_path, encrypted_file_path)
        logging.info(f"Arquivo cifrado salvo em: {encrypted_file_path}")

        # Armazena os nomes dos arquivos gerados na sessão
        session["encrypted_file_name"] = f"encrypted_{file_name}"
        session["signed_file_name"] = f"signed_{file_name}"

        return jsonify({
            "message": "Arquivo assinado e cifrado com sucesso.",
            "signed_file": f"/download/signed_{file_name}",  # Caminho para download do arquivo assinado
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
def decrypt_file_route():
    private_key_file = request.files.get("private_key_file")
    encrypted_file = request.files.get("encrypted_file")

    # Validate uploaded files
    if not private_key_file or not encrypted_file:
        return jsonify({"error": "Os arquivos da chave privada e do arquivo criptografado são obrigatórios."}), 400

    # Save uploaded files
    private_key_path, private_key_error = save_uploaded_file(private_key_file, UPLOAD_DIR, private_key_file.filename)
    encrypted_file_path, encrypted_file_error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)

    if private_key_error or encrypted_file_error:
        return jsonify({"error": private_key_error or encrypted_file_error}), 500

    # Path for the decrypted file
    decrypted_file_path = os.path.join(SAVE_DIR, f"decrypted_{encrypted_file.filename}")

    try:
        # Read private key content
        with open(private_key_path, "rb") as key_file:
            private_key_content = key_file.read()

        # Perform decryption
        decrypt_file(encrypted_file_path, private_key_content, decrypted_file_path)
    except Exception as e:
        logging.error(f"Erro durante a descriptografia: {e}")
        return jsonify({"error": str(e)}), 500

    # Return success
    return jsonify({
        "message": "Arquivo descriptografado com sucesso.",
        "decrypted_file": f"/download/{os.path.basename(decrypted_file_path)}"
    })


# Validar arquivo e assinatura
@app.route("/validate_file", methods=["POST"])
def validate_file():
    encrypted_file = request.files.get("encrypted_file")
    signature_file = request.files.get("signature_file")
    public_key_file = request.files.get("public_key_file")
    private_key_file = request.files.get("private_key_file")

    if not all([encrypted_file, signature_file, public_key_file, private_key_file]):
        return jsonify({"error": "Todos os arquivos devem ser enviados."}), 400

    # Salvar arquivos
    encrypted_file_path, error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)
    if error:
        return jsonify({"error": error}), 400

    signature_file_path, error = save_uploaded_file(signature_file, UPLOAD_DIR, signature_file.filename)
    public_key_path, error = save_uploaded_file(public_key_file, UPLOAD_DIR, public_key_file.filename)
    private_key_path, error = save_uploaded_file(private_key_file, UPLOAD_DIR, private_key_file.filename)

    if error:
        return jsonify({"error": error}), 400

    is_signature_valid = verify_signature(encrypted_file_path, signature_file_path, public_key_path)
    if not is_signature_valid:
        return jsonify({"error": "A assinatura é inválida."}), 400

    decrypted_file_path = os.path.join(SAVE_DIR, f"decrypted_{encrypted_file.filename}")
    decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path)

    return jsonify({
        "message": "Arquivo validado com sucesso!",
        "decrypted_file": f"/download/{os.path.basename(decrypted_file_path)}"
    })

if __name__ == "__main__":
    app.run(debug=True)
