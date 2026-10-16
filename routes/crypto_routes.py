from flask import Blueprint, request, jsonify, render_template

from crypto.des_crypto import DESCrypto
from crypto.aes_crypto import AESCrypto
from crypto.md5_hash import MD5Hash
from crypto.sha256_hash import SHA256Hash
from crypto.rsa_crypto import RSACrypto
from crypto.elgamal_crypto import ElGamalCrypto

crypto_bp = Blueprint("crypto_api", __name__)


# =========================
# ROUTES HIỂN THỊ GIAO DIỆN
# =========================

@crypto_bp.route("/des", methods=["GET"])
def des_page():
    return render_template("des.html")


@crypto_bp.route("/aes", methods=["GET"])
def aes_page():
    return render_template("aes.html")


@crypto_bp.route("/md5", methods=["GET"])
def md5_page():
    return render_template("md5.html")


@crypto_bp.route("/sha256", methods=["GET"])
def sha256_page():
    return render_template("sha256.html")


@crypto_bp.route("/rsa", methods=["GET"])
def rsa_page():
    return render_template("rsa.html")


@crypto_bp.route("/elgamal", methods=["GET"])
def elgamal_page():
    return render_template("elgamal.html")


@crypto_bp.route("/about", methods=["GET"])
def learn_page():
    return render_template("about.html")


# =========================
# DES API
# =========================

@crypto_bp.route("/api/des/generate-key", methods=["GET"])
def des_gen_key():
    return jsonify({
        "status": "success",
        "key": DESCrypto.generate_key()
    })


@crypto_bp.route("/api/des/encrypt", methods=["POST"])
def des_encrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        DESCrypto.encrypt(
            data.get("plaintext", ""),
            data.get("key", "")
        )
    )


@crypto_bp.route("/api/des/decrypt", methods=["POST"])
def des_decrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        DESCrypto.decrypt(
            data.get("ciphertext", ""),
            data.get("key", "")
        )
    )


# =========================
# AES API
# =========================

@crypto_bp.route("/api/aes/generate-key", methods=["POST"])
def aes_gen_key():
    data = request.get_json(silent=True) or {}
    bits = data.get("bits", 256)

    return jsonify({
        "status": "success",
        "key": AESCrypto.generate_key(bits)
    })


@crypto_bp.route("/api/aes/encrypt", methods=["POST"])
def aes_encrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        AESCrypto.encrypt_text(
            data.get("plaintext", ""),
            data.get("key", "")
        )
    )


@crypto_bp.route("/api/aes/decrypt", methods=["POST"])
def aes_decrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        AESCrypto.decrypt_text(
            data.get("ciphertext", ""),
            data.get("key", "")
        )
    )


# =========================
# MD5 API
# =========================

@crypto_bp.route("/api/md5/hash", methods=["POST"])
def md5_hash():
    data = request.get_json(silent=True) or {}
    return jsonify(
        MD5Hash.hash_text(data.get("plaintext", ""))
    )


@crypto_bp.route("/api/md5/compare", methods=["POST"])
def md5_compare():
    data = request.get_json(silent=True) or {}
    return jsonify(
        MD5Hash.verify_integrity(
            data.get("input1", ""),
            data.get("input2", "")
        )
    )


# =========================
# SHA-256 API
# =========================

@crypto_bp.route("/api/sha256/hash", methods=["POST"])
def sha256_hash():
    data = request.get_json(silent=True) or {}
    return jsonify(
        SHA256Hash.hash_text(data.get("plaintext", ""))
    )


@crypto_bp.route("/api/sha256/compare", methods=["POST"])
def sha256_compare():
    data = request.get_json(silent=True) or {}
    return jsonify(
        SHA256Hash.verify_integrity(
            data.get("input1", ""),
            data.get("input2", "")
        )
    )


# =========================
# RSA API
# =========================

@crypto_bp.route("/api/rsa/generate-keys", methods=["POST"])
def rsa_gen_keys():
    data = request.get_json(silent=True) or {}
    bits = data.get("bits", 2048)

    return jsonify(RSACrypto.generate_keypair(bits))


@crypto_bp.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        RSACrypto.encrypt(
            data.get("plaintext", ""),
            data.get("public_key", "")
        )
    )


@crypto_bp.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        RSACrypto.decrypt(
            data.get("ciphertext", ""),
            data.get("private_key", "")
        )
    )


# =========================
# ELGAMAL API
# =========================

@crypto_bp.route("/api/elgamal/generate-keys", methods=["POST"])
def elgamal_gen_keys():
    data = request.get_json(silent=True) or {}
    bits = data.get("bits", 512)

    return jsonify(ElGamalCrypto.generate_keypair(bits))


@crypto_bp.route("/api/elgamal/encrypt", methods=["POST"])
def elgamal_encrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        ElGamalCrypto.encrypt(
            data.get("plaintext", ""),
            data.get("public_key", "")
        )
    )


@crypto_bp.route("/api/elgamal/decrypt", methods=["POST"])
def elgamal_decrypt():
    data = request.get_json(silent=True) or {}
    return jsonify(
        ElGamalCrypto.decrypt(
            data.get("ciphertext", ""),
            data.get("private_key", "")
        )
    )