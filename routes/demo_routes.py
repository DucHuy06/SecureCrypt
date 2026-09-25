from flask import Blueprint, request, jsonify
from crypto.hybrid_crypto import HybridCrypto

demo_bp = Blueprint('demo_api', __name__)

@demo_bp.route('/demo/full', methods=['POST'])
def full_demo():
    data = request.get_json() or {}
    plaintext = data.get('plaintext', 'SecureCrypt Academic Demo 2026')
    return jsonify(HybridCrypto.execute_full_demo(plaintext))