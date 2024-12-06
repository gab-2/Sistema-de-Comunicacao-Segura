from flask import Flask, render_template, request, jsonify, send_file
from cryptography_module.keys import generate_rsa_keys, generate_aes_key, load_rsa_private_key, load_rsa_public_key
from cryptography_module.crypto import sign_file, encrypt_file, protect_aes_key, decrypt_file, verify_signature
import os
import hashlib

app = Flask(__name__)

# Pastas para salvar os arquivos gerados e enviados
SAVE_DIR = "generated_files"
UPLOAD_DIR = "uploaded_files"
os.makedirs(SAVE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


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


@app.route("/generate_rsa", methods=["POST"])
def generate_rsa():
    private_key, public_key = generate_rsa_keys()
    # Salvar as chaves em arquivos
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


@app.route("/upload_public_key", methods=["POST"])
def upload_public_key():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if file:
        filepath = os.path.join(UPLOAD_DIR, file.filename)
        file.save(filepath)
        return jsonify({"message": "File uploaded successfully", "filename": file.filename})


@app.route("/upload_file", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if file:
        filepath = os.path.join(UPLOAD_DIR, file.filename)
        file.save(filepath)

        # Calcula o hash SHA-256 do arquivo
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return jsonify({
            "message": "File uploaded successfully",
            "filename": file.filename,
            "filesize": os.path.getsize(filepath),
            "hash": sha256_hash.hexdigest()
        })


@app.route("/sign_and_encrypt", methods=["POST"])
def sign_and_encrypt():
    # Verifica se o arquivo e a chave privada estão presentes
    file = request.files.get("file")
    private_key_path = os.path.join(SAVE_DIR, "private_key.pem")
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")

    if not file:
        return jsonify({"error": "No file provided"}), 400
    if not os.path.exists(private_key_path):
        return jsonify({"error": "Private key not found"}), 400
    if not os.path.exists(aes_key_path):
        return jsonify({"error": "AES key not found"}), 400

    # Salva o arquivo enviado
    original_file_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(original_file_path)

    # Assina o arquivo
    signed_file_path = os.path.join(SAVE_DIR, f"signed_{file.filename}")
    sign_file(original_file_path, private_key_path, signed_file_path)

    # Cifra o arquivo
    encrypted_file_path = os.path.join(SAVE_DIR, f"encrypted_{file.filename}")
    encrypt_file(signed_file_path, aes_key_path, encrypted_file_path)

    return jsonify({
        "message": "File signed and encrypted successfully",
        "signed_file": f"/download/signed_{file.filename}",
        "encrypted_file": f"/download/encrypted_{file.filename}"
    })


@app.route("/protect_aes_key", methods=["POST"])
def protect_aes_key_route():
    public_key_path = os.path.join(UPLOAD_DIR, "public_key.pem")
    aes_key_path = os.path.join(SAVE_DIR, "aes_key.key")
    protected_aes_key_path = os.path.join(SAVE_DIR, "protected_aes_key.pem")

    if not os.path.exists(public_key_path):
        return jsonify({"error": "Public key not found"}), 400
    if not os.path.exists(aes_key_path):
        return jsonify({"error": "AES key not found"}), 400

    # Protege a chave AES
    protect_aes_key(aes_key_path, public_key_path, protected_aes_key_path)

    return jsonify({
        "message": "AES key protected successfully",
        "protected_key_file": f"/download/protected_aes_key.pem"
    })


@app.route("/decrypt_file", methods=["POST"])
def decrypt_file_route():
    # Carregar os arquivos
    encrypted_file = request.files.get("encrypted_file")
    signature_file = request.files.get("signature_file")
    private_key_file = request.files.get("private_key_file")

    if not encrypted_file or not signature_file or not private_key_file:
        return jsonify({"error": "Missing files for decryption"}), 400

    # Salvar os arquivos carregados
    encrypted_file_path = os.path.join(UPLOAD_DIR, encrypted_file.filename)
    signature_file_path = os.path.join(UPLOAD_DIR, signature_file.filename)
    private_key_path = os.path.join(UPLOAD_DIR, private_key_file.filename)

    encrypted_file.save(encrypted_file_path)
    signature_file.save(signature_file_path)
    private_key_path.save(private_key_path)

    # Verificar a assinatura
    if not verify_signature(encrypted_file_path, signature_file_path, private_key_path):
        return jsonify({"error": "Signature verification failed"}), 400

    # Descriptografar o arquivo
    decrypted_file_path = os.path.join(
        SAVE_DIR, f"decrypted_{encrypted_file.filename}")
    decrypt_file(encrypted_file_path, private_key_path, decrypted_file_path)

    return jsonify({
        "message": "File decrypted successfully",
        "decrypted_file": f"/download/decrypted_{encrypted_file.filename}"
    })


@app.route("/download/<filename>")
def download_file(filename):
    file_path = os.path.join(SAVE_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True)
