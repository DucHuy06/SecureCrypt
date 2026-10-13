import random
import json
import base64
from Crypto.Util import number

class ElGamalCrypto:
    @staticmethod
    def generate_keypair(bits: int = 256) -> dict:
        """
        Sinh cặp khóa ElGamal chuẩn số nguyên.
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
            pub_key = json.loads(public_key_json)
            p, g, y = int(pub_key["p"]), int(pub_key["g"]), int(pub_key["y"])

            # Tách chuỗi theo khoảng trắng hoặc dấu phẩy để xử lý từng số nguyên M
            import re
            parts = [p.strip() for p in re.split(r'[\s,]+', plaintext.strip()) if p.strip()]
            
            cipher_pairs = []
            for part in parts:
                m = int(part)
                if m >= p:
                    return {"status": "error", "message": f"Lỗi: Thông điệp M = {m} phải nhỏ hơn số nguyên tố p ({p})."}
                
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

            # Giải mã chuỗi base64 thành danh sách cặp bản mã
            try:
                json_str = base64.b64decode(ciphertext_b64).decode('utf-8')
                cipher_pairs = json.loads(json_str)
            except Exception:
                # Fallback nếu truyền trực tiếp dạng chuỗi cặp thô
                import re
                matches = re.findall(r'\(\s*(\d+)\s*٬,\s*(\d+)\s*\)', ciphertext_b64)
                if not matches:
                    matches = re.findall(r'(\d+)\s*,\s*(\d+)', ciphertext_b64)
                cipher_pairs = matches

            plain_results = []
            for pair in cipher_pairs:
                c1, c2 = int(pair[0]), int(pair[1])
                s = pow(c1, x, p)
                s_inv = number.inverse(s, p)
                m = (c2 * s_inv) % p
                plain_results.append(str(m))

            # Trả về các thông điệp số nguyên phân tách bằng khoảng trắng
            return {"status": "success", "plaintext": " ".join(plain_results)}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã ElGamal thất bại: Khóa sai hoặc dữ liệu hỏng ({str(e)})."}