import os
from flask import Flask, render_template, request, jsonify
import google.generativeai as genai

from routes.crypto_routes import crypto_bp
from routes.file_routes import file_bp
from routes.demo_routes import demo_bp

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Tối đa 32MB file upload

# Cấu hình Gemini API Key từ biến môi trường
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Đăng ký API routes
app.register_blueprint(crypto_bp, url_prefix='/api')
app.register_blueprint(file_bp, url_prefix='/api')
app.register_blueprint(demo_bp, url_prefix='/api')

# HTML Page routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/des')
def des_page():
    return render_template('des.html')

@app.route('/aes')
def aes_page():
    return render_template('aes.html')

@app.route('/md5')
def md5_page():
    return render_template('md5.html')

@app.route('/sha256')
def sha256_page():
    return render_template('sha256.html')

@app.route('/rsa')
def rsa_page():
    return render_template('rsa.html')

@app.route('/elgamal')
def elgamal_page():
    return render_template('elgamal.html')

@app.route('/integrity')
def integrity_page():
    return render_template('integrity.html')

@app.route('/demo')
@app.route('/demos')
def demo_page():
    return render_template('demo.html')

@app.route('/about')
def about_page():
    return render_template('about.html')

@app.route('/ai-chat')
def ai_chat():
    return render_template('ai_chat.html')

# API Route cho Crypto AI Chatbot (Tự động tìm model thích hợp)
@app.route('/api/chat', methods=['POST'])
def chat_api():
    data = request.get_json() or {}
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'reply': 'Vui lòng nhập câu hỏi.'})
        
    if not os.environ.get('GEMINI_API_KEY'):
        return jsonify({'reply': 'Chưa cấu hình GEMINI_API_KEY trên Render Environment Variables.'})
        
    prompt = f"Bạn là Trợ lý AI chuyên gia về Mật mã học (Cryptography) cho ứng dụng SecureCrypt. Hãy giải đáp ngắn gọn, dễ hiểu và chính xác bằng tiếng Việt câu hỏi sau: {user_message}"
    
    try:
        # 1. Tự động lấy danh sách model hỗ trợ sinh nội dung từ Google API
        available_models = []
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                available_models.append(m.name)
        
        # 2. Thử gọi từng model khả dụng
        for model_name in available_models:
            try:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                if response and response.text:
                    return jsonify({'reply': response.text})
            except Exception:
                continue

        # 3. Fallback danh sách tên chuẩn nếu list_models không trả về
        fallback_models = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro']
        for m_name in fallback_models:
            try:
                model = genai.GenerativeModel(m_name)
                response = model.generate_content(prompt)
                if response and response.text:
                    return jsonify({'reply': response.text})
            except Exception:
                continue

        return jsonify({'reply': 'API Key hợp lệ nhưng không thể khởi tạo Model. Vui lòng kiểm tra lại quyền API Key.'})
    except Exception as e:
        return jsonify({'reply': f'Lỗi kết nối Gemini API: {str(e)}'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)