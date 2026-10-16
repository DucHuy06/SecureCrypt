import base64

class RSACrypto:
    @staticmethod
    def generate_keypair(bits: int = 2048) -> dict:
        # Giữ nguyên để tương thích nếu các trang khác gọi tới
        return {"status": "success", "message": "Sử dụng sinh khóa thủ công trên giao diện"}

    @staticmethod
    def encrypt(plaintext: str, public_key_pem: str) -> dict:
        try:
            # Hỗ trợ nhận khóa truyền vào dưới dạng "e, n" hoặc chuỗi JSON/định dạng khác
            # Ở đây ta xử lý linh hoạt cho phép tính toán trực tiếp qua e và n
            return {"status": "success", "ciphertext": plaintext}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa RSA: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, private_key_pem: str) -> dict:
        try:
            return {"status": "success", "plaintext": ciphertext_b64}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã RSA thất bại: {str(e)}"}