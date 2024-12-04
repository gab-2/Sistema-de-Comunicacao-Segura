from flask import Flask, render_template, request, jsonify, send_file
from cryptography_module.keys import generate_rsa_keys, generate_aes_key
import os
import hashlib

app = Flask(__name__)

# Pasta para salvar os arquivos gerados
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


@app.route("/download/<key_type>")
def download_key(key_type):
    file_map = {
        "private_key": "private_key.pem",
        "public_key": "public_key.pem",
        "aes_key": "aes_key.key"
    }
    file_path = os.path.join(SAVE_DIR, file_map.get(key_type, ""))
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True)
