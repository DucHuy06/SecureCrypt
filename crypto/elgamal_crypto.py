import random
import json
import base64
from Crypto.Util import number

class ElGamalCrypto:
    @staticmethod
    def generate_keypair(bits: int = 256) -> dict:
        """
        Sinh cặp khóa ElGamal. 
        Mặc định để số bit = 256 để cân bằng giữa tốc độ xử lý trên web và tính bảo mật mô phỏng.
        """
        try:
            p = number.getPrime(bits)
            g = random.randint(2, p - 1)
            x = random.randint(2, p - 2)
            y = pow(g, x, p)

            public_key = {"p": str(p), "g": str(g), "y": str(y)}
            private_key = {"p": str(p), "x": str(x)}

            return {
                "status": "success",
                "public_key": json.dumps(public_key),
                "private_key": json.dumps(private_key),
                "bits": bits
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi sinh khóa ElGamal: {str(e)}"}

    @staticmethod
    def encrypt(plaintext: str, public_key_json: str) -> dict:
        try:
            # Giới hạn độ dài chuỗi đầu vào để tránh việc sinh mảng cặp số quá lớn gây nặng web
            if len(plaintext) > 100:
                return {
                    "status": "error", 
                    "message": "Do đặc thù của thuật toán ElGamal mô phỏng trên web, vui lòng nhập văn bản ngắn hơn 100 ký tự."
                }

            pub_key = json.loads(public_key_json)
            p, g, y = int(pub_key["p"]), int(pub_key["g"]), int(pub_key["y"])

            cipher_pairs = []
            for b in plaintext.encode('utf-8'):
                m = int(b)
                # Kiểm tra an toàn: giá trị byte phải nhỏ hơn p
                if m >= p:
                    return {"status": "error", "message": "Ký tự vượt quá giới hạn của số nguyên tố p."}
                
                k = random.randint(2, p - 2)
                c1 = pow(g, k, p)
                c2 = (m * pow(y, k, p)) % p
                cipher_pairs.append((str(c1), str(c2)))

            json_str = json.dumps(cipher_pairs)
            b64_cipher = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            return {"status": "success", "ciphertext": b64_cipher}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa ElGamal: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, private_key_json: str) -> dict:
        try:
            priv_key = json.loads(private_key_json)
            p, x = int(priv_key["p"]), int(priv_key["x"])

            json_str = base64.b64decode(ciphertext_b64).decode('utf-8')
            cipher_pairs = json.loads(json_str)

            decrypted_bytes = bytearray()
            for pair in cipher_pairs:
                c1, c2 = int(pair[0]), int(pair[1])
                s = pow(c1, x, p)
                s_inv = number.inverse(s, p)
                decrypted_bytes.append((c2 * s_inv) % p)

            return {"status": "success", "plaintext": decrypted_bytes.decode('utf-8')}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã ElGamal thất bại: Khóa sai hoặc dữ liệu hỏng ({str(e)})."}