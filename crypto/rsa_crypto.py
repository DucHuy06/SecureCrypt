import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSACrypto:
    @staticmethod
    def generate_keypair(bits: int = 2048) -> dict:
        try:
            key = RSA.generate(bits)
            return {
                "status": "success",
                "public_key": key.publickey().export_key().decode('utf-8'),
                "private_key": key.export_key().decode('utf-8'),
                "bits": bits
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi sinh khóa RSA: {str(e)}"}

    @staticmethod
    def encrypt(plaintext: str, public_key_pem: str) -> dict:
        try:
            rsa_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
            return {"status": "success", "ciphertext": base64.b64encode(encrypted_bytes).decode('utf-8')}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi mã hóa RSA: {str(e)}"}

    @staticmethod
    def decrypt(ciphertext_b64: str, private_key_pem: str) -> dict:
        try:
            rsa_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(rsa_key)
            plaintext_bytes = cipher.decrypt(base64.b64decode(ciphertext_b64))
            return {"status": "success", "plaintext": plaintext_bytes.decode('utf-8')}
        except Exception as e:
            return {"status": "error", "message": f"Giải mã RSA thất bại: {str(e)}"}