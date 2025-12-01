from flask import Flask, render_template, request, send_file, flash, redirect
from io import BytesIO
import os
import secrets
import hashlib

# Import your embedding and extracting functions
from embed import embedFunc, calculate_capacity
from extract import safe_extract  # This should return (decrypted_text, error_message)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Needed for flash messages


# ================= SHA-256 key generator =================
@app.route("/generate_key", methods=["GET"])
def generate_key():
    random_bytes = secrets.token_bytes(32)
    sha256_key = hashlib.sha256(random_bytes).hexdigest()
    return {"key": sha256_key}


# ================== HOME PAGE ============================
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# ================== HIDE / ENCODE =======================
def encrypt_message(message, key_hex):
    # AES encryption using SHA-256 hex key (32 bytes)
    key_bytes = bytes.fromhex(key_hex[:64])  # take first 64 hex chars = 32 bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    iv = cipher.iv.hex()
    ciphertext = ct_bytes.hex()
    return f"{iv}:{ciphertext}"  # store IV with ciphertext


@app.route("/hide", methods=["POST"])
def hide():
    try:
        secret = request.form["sec_msg"]
        cover = request.form["cvr_msg"]
        key_hex = request.form["psw"]

        # Encrypt secret
        encrypted = encrypt_message(secret, key_hex)

        # Embed encrypted secret into cover message
        stego = embedFunc(encrypted, cover)

        return render_template("index.html", result=stego)

    except Exception as e:
        print("Error in /hide:", e)
        flash(f"Error encoding message: {e}", "danger")
        return render_template("index.html")


# ================== REVEAL / DECODE ======================
@app.route("/reveal", methods=["POST"])
def reveal():
    try:
        key_hex = request.form.get("psw_rev")
        uploaded_file = request.files.get("uploaded_file")

        if uploaded_file and uploaded_file.filename != "":
            stego_text = uploaded_file.read().decode("utf-8")
        else:
            stego_text = request.form.get("steg_msg", "")

        decrypted, error = safe_extract(stego_text, key_hex)
        if error:
            flash(error, "danger")
            return render_template("index.html")

        flash("Message decoded successfully!", "success")
        return render_template("index.html", result_reveal=decrypted)

    except Exception as e:
        print("Error in /reveal:", e)
        flash(f"Error decoding message: {e}", "danger")
        return render_template("index.html")


# ================== DOWNLOAD STEGO =======================
@app.route("/download", methods=["POST"])
def download():
    try:
        stego_text = request.form.get("stego_text", "")
        if not stego_text:
            flash("No stego message to download!", "danger")
            return redirect("/")

        # Send as .txt file
        file_stream = BytesIO()
        file_stream.write(stego_text.encode("utf-8"))
        file_stream.seek(0)
        return send_file(file_stream, as_attachment=True, download_name="stego.txt", mimetype="text/plain")

    except Exception as e:
        print("Error in /download:", e)
        flash(f"Error downloading file: {e}", "danger")
        return redirect("/")


# ================= RUN SERVER ============================
if __name__ == "__main__":
    app.run(debug=True)
