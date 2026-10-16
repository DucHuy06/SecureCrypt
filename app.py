
import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash

from routes.crypto_routes import crypto_bp
from routes.file_routes import file_bp
from routes.signature_routes import signature_bp
from routes.demo_routes import demo_bp


# ==================== KHỞI TẠO FLASK ====================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-this-secret"
)

# Giới hạn tổng dung lượng request.
# File PDF có giới hạn riêng trong signature_routes.py.
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024


# ==================== CƠ SỞ DỮ LIỆU ====================

DATABASE = BASE_DIR / "database.db"


def get_db_connection():
    conn = sqlite3.connect(str(DATABASE))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Tạo bảng người dùng nếu bảng chưa tồn tại."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT
            )
        """)


init_db()


# ==================== ĐĂNG KÝ TÀI KHOẢN ====================

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(
            success=False,
            message="Dữ liệu tài khoản không hợp lệ."
        ), 400

    username = username.strip()

    if not username or not password:
        return jsonify(
            success=False,
            message="Vui lòng nhập tên tài khoản và mật khẩu."
        ), 400

    if len(username) > 100:
        return jsonify(
            success=False,
            message="Tên tài khoản không được dài quá 100 ký tự."
        ), 400

    if len(password) < 8:
        return jsonify(
            success=False,
            message="Mật khẩu phải có ít nhất 8 ký tự."
        ), 400

    hashed_password = generate_password_hash(password)

    try:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """,
                (username, hashed_password)
            )

        return jsonify(
            success=True,
            message="Đăng ký tài khoản thành công."
        ), 201

    except sqlite3.IntegrityError:
        return jsonify(
            success=False,
            message="Tên tài khoản đã tồn tại."
        ), 409


# ==================== ĐĂNG NHẬP ====================

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(
            success=False,
            message="Dữ liệu đăng nhập không hợp lệ."
        ), 400

    username = username.strip()

    with get_db_connection() as conn:
        user = conn.execute(
            """
            SELECT username, password
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

    if user and check_password_hash(user["password"], password):
        session.clear()
        session["username"] = user["username"]

        return jsonify(
            success=True,
            message="Đăng nhập thành công."
        )

    return jsonify(
        success=False,
        message="Tên tài khoản hoặc mật khẩu không chính xác."
    ), 401


# ==================== ĐĂNG XUẤT ====================

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()

    return jsonify(
        success=True,
        message="Đăng xuất thành công."
    )


# ==================== KIỂM TRA TÀI KHOẢN ====================

@app.route("/api/current_user", methods=["GET"])
def api_current_user():
    username = session.get("username")

    if not username:
        return jsonify(logged_in=False), 401

    return jsonify(
        logged_in=True,
        username=username
    )


# ==================== KIỂM TRA ROUTE CHỮ KÝ ====================

@app.route("/signature/health", methods=["GET"])
def signature_health():
    return jsonify(
        success=True,
        message="Signature route is active"
    ), 200


# ==================== KIỂM TRA DANH SÁCH ROUTE ====================

@app.route("/debug/routes", methods=["GET"])
def debug_routes():
    routes = []

    for rule in app.url_map.iter_rules():
        routes.append({
            "path": rule.rule,
            "methods": sorted(
                rule.methods - {"HEAD", "OPTIONS"}
            ),
            "endpoint": rule.endpoint,
        })

    return jsonify(
        routes=sorted(routes, key=lambda item: item["path"])
    )


# ==================== ĐĂNG KÝ BLUEPRINT ====================

app.register_blueprint(crypto_bp)
app.register_blueprint(file_bp)
app.register_blueprint(signature_bp)
app.register_blueprint(demo_bp)


# ==================== XỬ LÝ LỖI UPLOAD ====================

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify(
        success=False,
        message="Dung lượng dữ liệu tải lên vượt quá giới hạn 32 MB."
    ), 413


# ==================== CHẠY ỨNG DỤNG ====================

if __name__ == "__main__":
    app.run(debug=True)
