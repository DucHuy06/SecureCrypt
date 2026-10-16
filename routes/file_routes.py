
import io

from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename

from crypto.aes_crypto import AESCrypto
from crypto.md5_hash import MD5Hash
from crypto.sha256_hash import SHA256Hash


file_bp = Blueprint("file_api", __name__)


def error_response(message, status=400):
    return jsonify({
        "status": "error",
        "message": message
    }), status


def get_uploaded_file():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return None, None

    safe_name = secure_filename(uploaded_file.filename)

    if not safe_name:
        return None, None

    return uploaded_file, safe_name


# ---------------------------------------------------------------------
# AES FILE ENCRYPTION
# ---------------------------------------------------------------------

@file_bp.route("/file/aes/encrypt", methods=["POST"])
def aes_file_encrypt():
    uploaded_file, filename = get_uploaded_file()
    key_hex = request.form.get("key", "")

    if uploaded_file is None or not key_hex:
        return error_response("Thiếu tập tin hoặc khóa mã hóa.")

    try:
        key_bytes = bytes.fromhex(key_hex)

        file_data = uploaded_file.read()

        if not file_data:
            return error_response("Tập tin không có dữ liệu.")

        encrypted_data = AESCrypto.encrypt_bytes(
            file_data,
            key_bytes
        )

        return send_file(
            io.BytesIO(encrypted_data),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"encrypted_{filename}.enc"
        )

    except ValueError:
        return error_response("Khóa mã hóa không đúng định dạng HEX.")

    except Exception:
        return error_response("Không thể mã hóa tập tin.", 500)


# ---------------------------------------------------------------------
# AES FILE DECRYPTION
# ---------------------------------------------------------------------

@file_bp.route("/file/aes/decrypt", methods=["POST"])
def aes_file_decrypt():
    uploaded_file, filename = get_uploaded_file()
    key_hex = request.form.get("key", "")

    if uploaded_file is None or not key_hex:
        return error_response("Thiếu tập tin hoặc khóa giải mã.")

    try:
        key_bytes = bytes.fromhex(key_hex)

        file_data = uploaded_file.read()

        if not file_data:
            return error_response("Tập tin không có dữ liệu.")

        decrypted_data = AESCrypto.decrypt_bytes(
            file_data,
            key_bytes
        )

        # Loại bỏ hậu tố do chức năng mã hóa tạo ra.
        out_name = filename

        if out_name.startswith("encrypted_"):
            out_name = out_name[len("encrypted_"):]

        if out_name.endswith(".enc"):
            out_name = out_name[:-4]

        return send_file(
            io.BytesIO(decrypted_data),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"decrypted_{out_name}"
        )

    except ValueError:
        return error_response("Khóa giải mã không đúng định dạng HEX.")

    except Exception:
        return error_response(
            "Không thể giải mã tập tin. Hãy kiểm tra khóa và dữ liệu đầu vào.",
            400
        )


# ---------------------------------------------------------------------
# FILE INTEGRITY CHECK — MD5 AND SHA-256
# ---------------------------------------------------------------------

@file_bp.route("/integrity/hash-file", methods=["POST"])
def integrity_hash_file():
    uploaded_file, filename = get_uploaded_file()

    if uploaded_file is None:
        return error_response("Vui lòng chọn tập tin hợp lệ.")

    try:
        file_bytes = uploaded_file.read()

        if not file_bytes:
            return error_response("Tập tin không có dữ liệu.")

        return jsonify({
            "status": "success",
            "filename": filename,
            "md5": MD5Hash.hash_bytes(file_bytes),
            "sha256": SHA256Hash.hash_bytes(file_bytes)
        })

    except Exception:
        return error_response(
            "Không thể tính mã băm của tập tin.",
            500
        )
