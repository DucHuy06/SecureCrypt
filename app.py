import os
from flask import Flask, render_template
from routes.crypto_routes import crypto_bp
from routes.file_routes import file_bp
from routes.demo_routes import demo_bp

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Tối đa 32MB file upload

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
def demo_page():
    return render_template('demo.html')

@app.route('/about')
def about_page():
    return render_template('about.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  
    @app.route('/ai-chat')
def ai_chat():
    return render_template('ai_chat.html')