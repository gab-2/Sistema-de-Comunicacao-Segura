from flask import Flask, render_template, request, jsonify, send_file
from cryptography_module.keys import generate_rsa_keys, generate_aes_key, load_rsa_private_key, load_rsa_public_key
from cryptography_module.crypto import sign_file, encrypt_file, protect_aes_key, decrypt_file, verify_signature
import os
import hashlib
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuração de logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

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

@app.route("/etapa2")
def etapa2():
    return render_template("etapa2.html", current_step=2)

@app.route("/etapa3")
def etapa3():
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


# Upload de arquivos
@app.route("/upload_file", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    filepath, error = save_uploaded_file(file, UPLOAD_DIR, file.filename)
    if error:
        return jsonify({"error": error}), 400

    file_hash = calculate_sha256(filepath)
    return jsonify({
        "message": "Arquivo carregado com sucesso.",
        "filename": file.filename,
        "filesize": os.path.getsize(filepath),
        "hash": file_hash
    })

# Assinar e criptografar arquivo
@app.route("/sign_and_encrypt", methods=["POST"])
def sign_and_encrypt():
    file = request.files.get("file")
    original_file_path, error = save_uploaded_file(file, UPLOAD_DIR, file.filename)
    if error:
        return jsonify({"error": error}), 400

    private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")

    if not os.path.exists(private_key_path):
        return jsonify({"error": "Chave privada não encontrada."}), 400
    if not os.path.exists(aes_key_path):
        return jsonify({"error": "Chave AES não encontrada."}), 400

    signed_file_path = os.path.join(SAVE_DIR, f"signed_{file.filename}")
    sign_file(original_file_path, private_key_path, signed_file_path)

    encrypted_file_path = os.path.join(SAVE_DIR, f"encrypted_{file.filename}")
    encrypt_file(signed_file_path, aes_key_path, encrypted_file_path)

    return jsonify({
        "message": "Arquivo assinado e cifrado com sucesso.",
        "signed_file": f"/download/signed_{file.filename}",
        "encrypted_file": f"/download/encrypted_{file.filename}"
    })

# Proteger chave AES com chave pública
@app.route("/protect_aes_key", methods=["POST"])
def protect_aes_key_route():
    public_key_path = os.path.join(UPLOAD_DIR, "public_key.pem")
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")
    protected_aes_key_path = os.path.join(SAVE_DIR, "protected_aes_key.pem")

    if not os.path.exists(public_key_path):
        return jsonify({"error": "Chave pública não encontrada."}), 400
    if not os.path.exists(aes_key_path):
        return jsonify({"error": "Chave AES não encontrada."}), 400

    protect_aes_key(aes_key_path, public_key_path, protected_aes_key_path)
    return jsonify({
        "message": "Chave AES protegida com sucesso.",
        "protected_key_file": f"/download/protected_aes_key.pem"
    })

# Endpoint para descriptografar um arquivo
@app.route("/decrypt_file", methods=["POST"])
def decrypt_file_route():
    encrypted_file = request.files.get("encrypted_file")
    signature_file = request.files.get("signature_file")
    private_key_file = request.files.get("private_key_file")

    # Verifica se todos os arquivos necessários foram enviados
    if not all([encrypted_file, signature_file, private_key_file]):
        return jsonify({"error": "Todos os arquivos (arquivo criptografado, assinatura e chave privada) são necessários."}), 400

    # Salvar os arquivos enviados
    encrypted_file_path, error = save_uploaded_file(encrypted_file, UPLOAD_DIR, encrypted_file.filename)
    if error:
        return jsonify({"error": error}), 400

    signature_file_path, error = save_uploaded_file(signature_file, UPLOAD_DIR, signature_file.filename)
    if error:
        return jsonify({"error": error}), 400

    private_key_path, error = save_uploaded_file(private_key_file, UPLOAD_DIR, private_key_file.filename)
    if error:
        return jsonify({"error": error}), 400

    # Verificar assinatura do arquivo
    public_key_path = os.path.join(SAVE_DIR, "public_key.pem")
    if not os.path.exists(public_key_path):
        return jsonify({"error": "Chave pública não encontrada para validar a assinatura."}), 400

    is_signature_valid = verify_signature(encrypted_file_path, signature_file_path, public_key_path)
    if not is_signature_valid:
        return jsonify({"error": "A assinatura é inválida."}), 400

    # Descriptografar o arquivo
    decrypted_file_path = os.path.join(SAVE_DIR, f"decrypted_{encrypted_file.filename}")
    try:
        decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path)
    except Exception as e:
        logging.error(f"Erro durante a descriptografia: {e}")
        return jsonify({"error": f"Erro durante a descriptografia: {e}"}), 500

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
