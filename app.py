from flask import Flask, render_template, request, jsonify, send_file
from cryptography_module.keys import generate_rsa_keys, generate_aes_key
import os

app = Flask(__name__)

# Pasta para salvar os arquivos gerados
SAVE_DIR = "generated_files"
os.makedirs(SAVE_DIR, exist_ok=True)


@app.route("/")
def index():
    return render_template("etapa1.html")


@app.route("/etapa2")
def etapa2():
    return render_template("etapa2.html")


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
