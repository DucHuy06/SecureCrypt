import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESCrypto:
    @staticmethod
    def generate_key(key_size_bits: int = 256) -> str:
        bytes_len = 16 if key_size_bits == 128 else 32
        return get_random_bytes(bytes_len).hex()

    @staticmethod
    def encrypt_text(plaintext: str, key_hex: str) -> dict:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) not in (16, 32):
                return {"status": "error", "message": "Độ dài khóa AES phải là 16 bytes (128-bit) hoặc 32 bytes (256-bit)."}
            
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
            
            packed = nonce + tag + ciphertext
            return {
                "status": "success",
                "ciphertext": base64.b64encode(packed).decode('utf-8'),
                "nonce": nonce.hex(),
                "tag": tag.hex()
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa AES: {str(e)}"}

    @staticmethod
    def decrypt_text(ciphertext_b64: str, key_hex: str) -> dict:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) not in (16, 32):
                return {"status": "error", "message": "Độ dài khóa AES phải là 16 bytes hoặc 32 bytes."}
            
            packed = base64.b64decode(ciphertext_b64)
            if len(packed) < 28:
                return {"status": "error", "message": "Dữ liệu Ciphertext AES không hợp lệ."}
            
            nonce = packed[:12]
            tag = packed[12:28]
            ciphertext = packed[28:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            
            return {"status": "success", "plaintext": plaintext_bytes.decode('utf-8')}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã AES thất bại: Khóa sai hoặc dữ liệu hỏng ({str(e)})."}

    @staticmethod
    def encrypt_bytes(data_bytes: bytes, key_bytes: bytes) -> bytes:
        nonce = get_random_bytes(12)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        return nonce + tag + ciphertext

    @staticmethod
    def decrypt_bytes(encrypted_bytes: bytes, key_bytes: bytes) -> bytes:
        if len(encrypted_bytes) < 28:
            raise ValueError("File mã hóa không hợp lệ.")
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[12:28]
        ciphertext = encrypted_bytes[28:]
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)