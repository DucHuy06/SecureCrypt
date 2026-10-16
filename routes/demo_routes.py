from flask import Blueprint, request, jsonify, render_template
from crypto.hybrid_crypto import HybridCrypto

demo_bp = Blueprint("demo_api", __name__)


# ---------------------------------------------------------------------
# Giao diện trang Demo chính (GET /demo)
# ---------------------------------------------------------------------
@demo_bp.route("/demo", methods=["GET"])
def demo_page():
    return render_template("demo.html")


# ---------------------------------------------------------------------
# Demo mật mã tổng hợp — tạm giữ để không ảnh hưởng chức năng cũ
# ---------------------------------------------------------------------

@demo_bp.route("/demo/full", methods=["POST"])
def full_demo():
    data = request.get_json(silent=True) or {}

    plaintext = data.get(
        "plaintext",
        "SecureCrypt Academic Demo 2026"
    )

    if not isinstance(plaintext, str):
        return jsonify({
            "success": False,
            "message": "Nội dung đầu vào phải là chuỗi văn bản."
        }), 400

    try:
        result = HybridCrypto.execute_full_demo(plaintext)
        return jsonify(result)

    except Exception:
        return jsonify({
            "success": False,
            "message": "Không thể thực hiện demo mật mã."
        }), 500


# ---------------------------------------------------------------------
# Khu vực chữ ký số PDF
# Các API ký và xác minh sẽ được bổ sung tại đây.
# ---------------------------------------------------------------------