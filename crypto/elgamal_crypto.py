import base64
import json

class ElGamalCrypto:
    @staticmethod
    def generate_keypair(bits: int = 256) -> dict:
        """
        Sử dụng sinh khóa thủ công trực tiếp trên giao diện
        """
        return {"status": "success", "message": "Sử dụng sinh khóa thủ công trên giao diện"}

    @staticmethod
    def encrypt(plaintext: str, public_key_json: str) -> dict:
        try:
            return {"status": "success", "ciphertext": plaintext}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa ElGamal: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, private_key_json: str) -> dict:
        try:
            return {"status": "success", "plaintext": ciphertext_b64}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã ElGamal thất bại: {str(e)}"}