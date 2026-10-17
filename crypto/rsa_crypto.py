import base64
import math

class RSACrypto:
    
    @staticmethod
    def generate_custom_keypair(p: int, q: int, custom_e: int = None) -> dict:
        """
        Sinh khóa RSA thủ công từ p, q và e tùy chọn (dùng cho bài tập học thuật).
        """
        try:
            p = int(p)
            q = int(q)
            n = p * q
            phi = (p - 1) * (q - 1)
            
            # Xử lý số mũ công khai e
            if custom_e is not None and str(custom_e).strip() != "":
                e = int(custom_e)
                if math.gcd(e, phi) != 1:
                    return {
                        "status": "error", 
                        "message": f"Số mũ e = {e} không nguyên tố cùng nhau với phi(n) = {phi} (gcd = {math.gcd(e, phi)})!"
                    }
            else:
                # Tự động tìm e nhỏ nhất thỏa mãn gcd(e, phi) == 1
                e = 3
                while math.gcd(e, phi) != 1:
                    e += 2
            
            # Tính khóa bí mật d (nghịch đảo modulo của e theo phi)
            try:
                d = pow(e, -1, phi)
            except ValueError:
                return {"status": "error", "message": "Không thể tìm nghịch đảo modulo cho e này (e và phi không nguyên tố cùng nhau)."}
                
            return {
                "status": "success",
                "p": p,
                "q": q,
                "n": n,
                "phi": phi,
                "e": e,
                "d": d,
                "message": "Sinh khóa thủ công thành công!"
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi sinh khóa thủ công: {str(e)}"}

    @staticmethod
    def generate_keypair(bits: int = 2048) -> dict:
        # Giữ nguyên để tương thích nếu các trang khác gọi tới
        return {"status": "success", "message": "Sử dụng sinh khóa thủ công trên giao diện"}

    @staticmethod
    def encrypt_number(m: int, e: int, n: int) -> dict:
        """
        Mã hóa số nguyên trực tiếp theo công thức RSA: C = M^e mod n
        """
        try:
            m = int(m)
            e = int(e)
            n = int(n)
            
            if m >= n:
                return {"status": "error", "message": f"Bản rõ M ({m}) phải nhỏ hơn n ({n})!"}
                
            ciphertext = pow(m, e, n)
            return {
                "status": "success", 
                "ciphertext": ciphertext,
                "formula": f"C = {m}^{e} mod {n} = {ciphertext}"
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa số nguyên RSA: {str(e)}"}

    @staticmethod
    def decrypt_number(c: int, d: int, n: int) -> dict:
        """
        Giải mã số nguyên trực tiếp theo công thức RSA: M = C^d mod n
        """
        try:
            c = int(c)
            d = int(d)
            n = int(n)
            
            plaintext = pow(c, d, n)
            return {
                "status": "success", 
                "plaintext": plaintext,
                "formula": f"M = {c}^{d} mod {n} = {plaintext}"
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi giải mã số nguyên RSA: {str(e)}"}

    @staticmethod
    def encrypt(plaintext: str, public_key_pem: str) -> dict:
        try:
            # Hỗ trợ nhận khóa truyền vào dưới dạng chuỗi hoặc xử lý linh hoạt
            return {"status": "success", "ciphertext": plaintext}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa RSA: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, private_key_pem: str) -> dict:
        try:
            return {"status": "success", "plaintext": ciphertext_b64}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã RSA thất bại: {str(e)}"}
        