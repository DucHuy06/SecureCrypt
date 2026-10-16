import os
import sqlite3
import json
from flask import Flask, render_template, request, jsonify, session

# (Giữ nguyên các blueprint hiện có của bạn)
from routes.crypto_routes import crypto_bp
from routes.file_routes import file_bp
from routes.demo_routes import demo_bp

app = Flask(__name__)
app.secret_key = 'securespace_secret_key_production_2026'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Tối đa 32MB

# Khởi tạo Database SQLite cho SecureChat
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Bảng lưu thông tin tài khoản và Public Key RSA
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    public_key TEXT
                )''')
    # Bảng lưu gói tin nhắn mã hóa đầu cuối (E2EE)
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    wrapped_key TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

init_db()

app.register_blueprint(crypto_bp, url_prefix='/api')
app.register_blueprint(file_bp, url_prefix='/api')
app.register_blueprint(demo_bp, url_prefix='/api')

# --- API Xác thực tài khoản ---
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    public_key = data.get('public_key')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ tên tài khoản và mật khẩu!"})
    
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)", 
                  (username, password, public_key))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Đăng ký tài khoản thành công!"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Tên tài khoản này đã tồn tại!"})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    
    if user:
        session['username'] = username
        return jsonify({"success": True, "message": "Đăng nhập thành công!"})
    return jsonify({"success": False, "message": "Sai tên tài khoản hoặc mật khẩu!"})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('username', None)
    return jsonify({"success": True})

@app.route('/api/users', methods=['GET'])
def api_get_users():
    current_user = session.get('username')
    if not current_user:
        return jsonify([]), 401
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT username, public_key FROM users")
    users = [{"username": row[0], "public_key": row[1]} for row in c.fetchall() if row[0] != current_user]
    conn.close()
    return jsonify(users)

# --- API Nhắn tin mã hóa E2EE ---
@app.route('/api/messages/send', methods=['POST'])
def api_send_message():
    sender = session.get('username')
    if not sender:
        return jsonify({"success": False, "message": "Chưa đăng nhập!"}), 401
    
    data = request.json
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    wrapped_key = data.get('wrapped_key')
    
    if not recipient or not ciphertext:
        return jsonify({"success": False, "message": "Thiếu thông tin tin nhắn!"}), 400

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, recipient, ciphertext, iv, wrapped_key) VALUES (?, ?, ?, ?, ?)",
              (sender, recipient, json.dumps(ciphertext), json.dumps(iv), json.dumps(wrapped_key)))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/messages/poll', methods=['GET'])
def api_poll_messages():
    sender = session.get('username')
    partner = request.args.get('partner')
    if not sender or not partner:
        return jsonify([])
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Chỉ cho phép truy vấn tin nhắn thuộc về cuộc hội thoại giữa 2 người (Bảo mật phân quyền)
    c.execute("""SELECT sender, recipient, ciphertext, iv, wrapped_key, timestamp 
                 FROM messages 
                 WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) 
                 ORDER BY id ASC""", (sender, partner, partner, sender))
    
    msgs = []
    for r in c.fetchall():
        try:
            ct = json.loads(r[2])
            iv_val = json.loads(r[3])
            wk = json.loads(r[4])
        except:
            ct, iv_val, wk = r[2], r[3], r[4]

        msgs.append({
            "sender": r[0], 
            "recipient": r[1], 
            "ciphertext": ct, 
            "iv": iv_val, 
            "wrapped_key": wk, 
            "timestamp": r[5]
        })
    conn.close()
    return jsonify(msgs)

# Các định nghĩa route trang HTML giữ nguyên như cũ...