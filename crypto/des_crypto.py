import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class DESCrypto:
    @staticmethod
    def generate_key() -> str:
        return get_random_bytes(8).hex()

    @staticmethod
    def encrypt(plaintext: str, key_hex: str) -> dict:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 8:
                return {"status": "error", "message": "Khóa DES phải đúng 8 bytes (16 ký tự Hex)."}
            
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            result = base64.b64encode(iv + ciphertext).decode('utf-8')
            return {"status": "success", "ciphertext": result, "iv": iv.hex()}
        except ValueError as e:
            return {"status": "error", "message": f"Khóa Hex không hợp lệ: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa DES: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, key_hex: str) -> dict:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 8:
                return {"status": "error", "message": "Khóa DES phải đúng 8 bytes (16 ký tự Hex)."}
            
            raw_data = base64.b64decode(ciphertext_b64)
            if len(raw_data) < 16:
                return {"status": "error", "message": "Dữ liệu Ciphertext không hợp lệ."}
            
            iv = raw_data[:8]
            ciphertext = raw_data[8:]
            
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
            
            return {"status": "success", "plaintext": plaintext}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã DES thất bại: {str(e)}"}
    