import io
from flask import Blueprint, request, jsonify, send_file
from crypto.aes_crypto import AESCrypto
from crypto.md5_hash import MD5Hash
from crypto.sha256_hash import SHA256Hash

file_bp = Blueprint('file_api', __name__)

@file_bp.route('/file/aes/encrypt', methods=['POST'])
def aes_file_encrypt():
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({"status": "error", "message": "Thiếu tập tin hoặc khóa."})
    
    file = request.files['file']
    key_hex = request.form['key']
    try:
        key_bytes = bytes.fromhex(key_hex)
        encrypted_data = AESCrypto.encrypt_bytes(file.read(), key_bytes)
        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f"encrypted_{file.filename}.enc"
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"Lỗi mã hóa file: {str(e)}"})

@file_bp.route('/file/aes/decrypt', methods=['POST'])
def aes_file_decrypt():
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({"status": "error", "message": "Thiếu tập tin hoặc khóa."})
    
    file = request.files['file']
    key_hex = request.form['key']
    try:
        key_bytes = bytes.fromhex(key_hex)
        decrypted_data = AESCrypto.decrypt_bytes(file.read(), key_bytes)
        out_name = file.filename.replace('.enc', '').replace('encrypted_', '')
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f"decrypted_{out_name}"
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"Lỗi giải mã file: {str(e)}"})

@file_bp.route('/integrity/hash-file', methods=['POST'])
def integrity_hash_file():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Chưa chọn file."})
    
    file_bytes = request.files['file'].read()
    return jsonify({
        "status": "success",
        "filename": request.files['file'].filename,
        "md5": MD5Hash.hash_bytes(file_bytes),
        "sha256": SHA256Hash.hash_bytes(file_bytes)
    })