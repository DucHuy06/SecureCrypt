import hashlib
from crypto.aes_crypto import AESCrypto
from crypto.rsa_crypto import RSACrypto
from crypto.elgamal_crypto import ElGamalCrypto

class HybridCrypto:
    @staticmethod
    def execute_full_demo(plaintext: str) -> dict:
        try:
            # Bước 1: Mã hóa AES (Khóa phiên)
            aes_key_hex = AESCrypto.generate_key(256)
            aes_res = AESCrypto.encrypt_text(plaintext, aes_key_hex)
            if aes_res.get("status") == "error":
                return aes_res

            # Bước 2: Mã hóa khóa AES bằng RSA
            rsa_keys = RSACrypto.generate_keypair(2048)
            if rsa_keys.get("status") == "error":
                return rsa_keys
                
            rsa_enc_key = RSACrypto.encrypt(aes_key_hex, rsa_keys["public_key"])
            if rsa_enc_key.get("status") == "error":
                return rsa_enc_key

            # Bước 3: Mã hóa khóa AES bằng ElGamal
            elgamal_keys = ElGamalCrypto.generate_keypair(256) # Để 256 hoặc 512 bit cho nhanh
            if elgamal_keys.get("status") == "error":
                return elgamal_keys
                
            elgamal_enc_key = ElGamalCrypto.encrypt(aes_key_hex, elgamal_keys["public_key"])
            if elgamal_enc_key.get("status") == "error":
                return elgamal_enc_key

            # Bước 4 & 5: Tính toán hàm băm (MD5 & SHA-256)
            md5_hash = hashlib.md5(plaintext.encode('utf-8')).hexdigest()
            sha256_hash = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()

            return {
                "status": "success",
                "original_plaintext": plaintext,
                "step1_aes": {
                    "session_key_hex": aes_key_hex,
                    "ciphertext": aes_res["ciphertext"]
                },
                "step2_rsa": {
                    "public_key": rsa_keys["public_key"],
                    "private_key": rsa_keys["private_key"],
                    "encrypted_session_key": rsa_enc_key["ciphertext"]
                },
                "step3_elgamal": {
                    "public_key": elgamal_keys["public_key"],
                    "private_key": elgamal_keys["private_key"],
                    "encrypted_session_key": elgamal_enc_key["ciphertext"]
                },
                "step4_md5": md5_hash,
                "step5_sha256": sha256_hash
            }
        except Exception as e:
            return {"status": "error", "message": f"Lỗi Full Demo Hybrid: {str(e)}"}