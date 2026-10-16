
import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, request, jsonify, session, current_app
from crypto.hybrid_crypto import HybridCrypto

demo_bp = Blueprint("demo_api", __name__)

# Dùng cơ sở dữ liệu riêng để tránh ảnh hưởng các bảng khác của dự án.
DB_PATH = Path(__file__).resolve().parent.parent / "instance" / "securechat.sqlite3"

# Thông số PBKDF2 để băm mật khẩu.
PASSWORD_ITERATIONS = 310_000
MAX_USERNAME_LENGTH = 40
MAX_PASSWORD_LENGTH = 256
MAX_MESSAGE_LENGTH = 4000


def get_db():
    """Mở kết nối SQLite; mỗi request dùng một kết nối riêng."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Tạo bảng nếu chưa tồn tại; không xóa dữ liệu cũ."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL COLLATE NOCASE,
                recipient TEXT NOT NULL COLLATE NOCASE,
                ciphertext TEXT NOT NULL,
                iv TEXT,
                algorithm TEXT NOT NULL DEFAULT 'plaintext-demo',
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender) REFERENCES chat_users(username)
                    ON UPDATE CASCADE ON DELETE CASCADE,
                FOREIGN KEY(recipient) REFERENCES chat_users(username)
                    ON UPDATE CASCADE ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_chat_conversation
            ON chat_messages(sender, recipient, id)
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_username(value):
    if not isinstance(value, str):
        return None

    username = value.strip()

    if not username or len(username) > MAX_USERNAME_LENGTH:
        return None

    # Chỉ cho phép tên tài khoản dễ đọc và an toàn khi hiển thị.
    if not all(ch.isalnum() or ch in "._-" for ch in username):
        return None

    return username


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS
    )
    return digest.hex(), salt.hex()


def login_required():
    username = session.get("chat_username")
    if not username:
        return None
    return username


def error(message, status=400):
    return jsonify({"success": False, "message": message}), status


# Khởi tạo bảng khi module được nạp.
init_db()


# ---------------------------------------------------------------------
# API demo mật mã gốc — được giữ lại
# ---------------------------------------------------------------------

@demo_bp.route("/demo/full", methods=["POST"])
def full_demo():
    data = request.get_json(silent=True) or {}
    plaintext = data.get(
        "plaintext",
        "SecureCrypt Academic Demo 2026"
    )
    return jsonify(HybridCrypto.execute_full_demo(plaintext))


# ---------------------------------------------------------------------
# Đăng ký và xác thực tài khoản
# ---------------------------------------------------------------------

@demo_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = normalize_username(data.get("username"))
    password = data.get("password")

    if not username:
        return error(
            "Tên tài khoản không hợp lệ. Hãy dùng chữ, số, dấu chấm, gạch ngang hoặc gạch dưới."
        )

    if not isinstance(password, str) or not password:
        return error("Vui lòng nhập mật khẩu.")

    if len(password) > MAX_PASSWORD_LENGTH:
        return error("Mật khẩu quá dài.")

    password_hash, salt = hash_password(password)

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO chat_users
                    (username, password_hash, password_salt, created_at)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, salt, now_iso()))

        return jsonify({
            "success": True,
            "message": "Đăng ký thành công. Hãy đăng nhập."
        }), 201

    except sqlite3.IntegrityError:
        return error("Tên tài khoản đã tồn tại.", 409)


@demo_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = normalize_username(data.get("username"))
    password = data.get("password")

    if not username or not isinstance(password, str):
        return error("Tên tài khoản hoặc mật khẩu không đúng.", 401)

    with get_db() as conn:
        user = conn.execute("""
            SELECT username, password_hash, password_salt
            FROM chat_users
            WHERE username = ?
        """, (username,)).fetchone()

    # Thông báo chung để không tiết lộ tài khoản có tồn tại hay không.
    if not user:
        return error("Tên tài khoản hoặc mật khẩu không đúng.", 401)

    calculated_hash, _ = hash_password(password, user["password_salt"])

    if not hmac.compare_digest(calculated_hash, user["password_hash"]):
        return error("Tên tài khoản hoặc mật khẩu không đúng.", 401)

    # Xóa dữ liệu session cũ trước khi tạo phiên đăng nhập mới.
    session.clear()
    session["chat_username"] = user["username"]

    return jsonify({
        "success": True,
        "username": user["username"],
        "message": "Đăng nhập thành công."
    })


@demo_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("chat_username", None)
    return jsonify({"success": True, "message": "Đã đăng xuất."})


@demo_bp.route("/current_user", methods=["GET"])
def current_user():
    username = login_required()

    if not username:
        return jsonify({
            "logged_in": False,
            "username": None
        }), 200

    return jsonify({
        "logged_in": True,
        "username": username
    })


# ---------------------------------------------------------------------
# Danh sách tài khoản
# ---------------------------------------------------------------------

@demo_bp.route("/users", methods=["GET"])
def list_users():
    username = login_required()
    if not username:
        return error("Bạn cần đăng nhập để xem danh sách tài khoản.", 401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT username
            FROM chat_users
            WHERE username != ?
            ORDER BY username COLLATE NOCASE ASC
        """, (username,)).fetchall()

    return jsonify([row["username"] for row in rows])


# ---------------------------------------------------------------------
# Gửi và nhận tin nhắn
# ---------------------------------------------------------------------

@demo_bp.route("/messages/send", methods=["POST"])
def send_message():
    sender = login_required()
    if not sender:
        return error("Phiên đăng nhập đã hết hạn. Hãy đăng nhập lại.", 401)

    data = request.get_json(silent=True) or {}
    recipient = normalize_username(data.get("recipient"))
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")
    algorithm = data.get("algorithm", "plaintext-demo")

    if not recipient:
        return error("Người nhận không hợp lệ.")

    if recipient.casefold() == sender.casefold():
        return error("Bạn không thể gửi tin nhắn cho chính mình.")

    if not isinstance(ciphertext, str) or not ciphertext:
        return error("Nội dung tin nhắn không hợp lệ.")

    if len(ciphertext) > 200_000:
        return error("Dữ liệu tin nhắn quá lớn.")

    if not isinstance(algorithm, str) or len(algorithm) > 40:
        return error("Tên thuật toán không hợp lệ.")

    if iv is not None and (not isinstance(iv, str) or len(iv) > 256):
        return error("Nonce/IV không hợp lệ.")

    with get_db() as conn:
        target = conn.execute("""
            SELECT username FROM chat_users WHERE username = ?
        """, (recipient,)).fetchone()

        if not target:
            return error("Tài khoản người nhận không tồn tại.", 404)

        cursor = conn.execute("""
            INSERT INTO chat_messages
                (sender, recipient, ciphertext, iv, algorithm, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            sender,
            target["username"],
            ciphertext,
            iv,
            algorithm,
            now_iso()
        ))

        message_id = cursor.lastrowid

    return jsonify({
        "success": True,
        "message": "Đã gửi tin nhắn.",
        "id": message_id
    }), 201


@demo_bp.route("/messages/poll", methods=["GET"])
def poll_messages():
    username = login_required()
    if not username:
        return error("Phiên đăng nhập đã hết hạn. Hãy đăng nhập lại.", 401)

    partner = normalize_username(request.args.get("partner", ""))

    if not partner:
        return error("Tài khoản trò chuyện không hợp lệ.")

    with get_db() as conn:
        target = conn.execute("""
            SELECT username FROM chat_users WHERE username = ?
        """, (partner,)).fetchone()

        if not target:
            return error("Tài khoản trò chuyện không tồn tại.", 404)

        rows = conn.execute("""
            SELECT id, sender, recipient, ciphertext, iv, algorithm, created_at
            FROM chat_messages
            WHERE
                (sender = ? AND recipient = ?)
                OR
                (sender = ? AND recipient = ?)
            ORDER BY id ASC
            LIMIT 500
        """, (
            username, target["username"],
            target["username"], username
        )).fetchall()

    messages = [{
        "id": row["id"],
        "sender": row["sender"],
        "recipient": row["recipient"],
        "ciphertext": row["ciphertext"],
        "iv": row["iv"],
        "algorithm": row["algorithm"],
        "timestamp": row["created_at"]
    } for row in rows]

    return jsonify({
        "success": True,
        "messages": messages
    })
