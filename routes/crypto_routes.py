from flask import Blueprint, request, jsonify
from crypto.des_crypto import DESCrypto
from crypto.aes_crypto import AESCrypto
from crypto.md5_hash import MD5Hash
from crypto.sha256_hash import SHA256Hash
from crypto.rsa_crypto import RSACrypto
from crypto.elgamal_crypto import ElGamalCrypto

crypto_bp = Blueprint('crypto_api', __name__)

@crypto_bp.route('/des/generate-key', methods=['GET'])
def des_gen_key():
    return jsonify({"status": "success", "key": DESCrypto.generate_key()})

@crypto_bp.route('/des/encrypt', methods=['POST'])
def des_encrypt():
    data = request.get_json() or {}
    return jsonify(DESCrypto.encrypt(data.get('plaintext', ''), data.get('key', '')))

@crypto_bp.route('/des/decrypt', methods=['POST'])
def des_decrypt():
    data = request.get_json() or {}
    return jsonify(DESCrypto.decrypt(data.get('ciphertext', ''), data.get('key', '')))

@crypto_bp.route('/aes/generate-key', methods=['POST'])
def aes_gen_key():
    data = request.get_json() or {}
    bits = data.get('bits', 256)
    return jsonify({"status": "success", "key": AESCrypto.generate_key(bits)})

@crypto_bp.route('/aes/encrypt', methods=['POST'])
def aes_encrypt():
    data = request.get_json() or {}
    return jsonify(AESCrypto.encrypt_text(data.get('plaintext', ''), data.get('key', '')))

@crypto_bp.route('/aes/decrypt', methods=['POST'])
def aes_decrypt():
    data = request.get_json() or {}
    return jsonify(AESCrypto.decrypt_text(data.get('ciphertext', ''), data.get('key', '')))

@crypto_bp.route('/md5/hash', methods=['POST'])
def md5_hash():
    data = request.get_json() or {}
    return jsonify(MD5Hash.hash_text(data.get('plaintext', '')))

@crypto_bp.route('/md5/compare', methods=['POST'])
def md5_compare():
    data = request.get_json() or {}
    return jsonify(MD5Hash.verify_integrity(data.get('input1', ''), data.get('input2', '')))

@crypto_bp.route('/sha256/hash', methods=['POST'])
def sha256_hash():
    data = request.get_json() or {}
    return jsonify(SHA256Hash.hash_text(data.get('plaintext', '')))

@crypto_bp.route('/sha256/compare', methods=['POST'])
def sha256_compare():
    data = request.get_json() or {}
    return jsonify(SHA256Hash.verify_integrity(data.get('input1', ''), data.get('input2', '')))

@crypto_bp.route('/rsa/generate-keys', methods=['POST'])
def rsa_gen_keys():
    data = request.get_json() or {}
    bits = data.get('bits', 2048)
    return jsonify(RSACrypto.generate_keypair(bits))

@crypto_bp.route('/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.get_json() or {}
    return jsonify(RSACrypto.encrypt(data.get('plaintext', ''), data.get('public_key', '')))

@crypto_bp.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.get_json() or {}
    return jsonify(RSACrypto.decrypt(data.get('ciphertext', ''), data.get('private_key', '')))

@crypto_bp.route('/elgamal/generate-keys', methods=['POST'])
def elgamal_gen_keys():
    data = request.get_json() or {}
    bits = data.get('bits', 512)
    return jsonify(ElGamalCrypto.generate_keypair(bits))

@crypto_bp.route('/elgamal/encrypt', methods=['POST'])
def elgamal_encrypt():
    data = request.get_json() or {}
    return jsonify(ElGamalCrypto.encrypt(data.get('plaintext', ''), data.get('public_key', '')))

@crypto_bp.route('/elgamal/decrypt', methods=['POST'])
def elgamal_decrypt():
    data = request.get_json() or {}
    return jsonify(ElGamalCrypto.decrypt(data.get('ciphertext', ''), data.get('private_key', '')))