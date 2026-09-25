import hashlib
from crypto.aes_crypto import AESCrypto
from crypto.rsa_crypto import RSACrypto
from crypto.elgamal_crypto import ElGamalCrypto

class HybridCrypto:
    @staticmethod
    def execute_full_demo(plaintext: str) -> dict:
        try:
            aes_key_hex = AESCrypto.generate_key(256)
            aes_res = AESCrypto.encrypt_text(plaintext, aes_key_hex)
            
            rsa_keys = RSACrypto.generate_keypair(2048)
            rsa_enc_key = RSACrypto.encrypt(aes_key_hex, rsa_keys["public_key"])
            
            elgamal_keys = ElGamalCrypto.generate_keypair(512)
            elgamal_enc_key = ElGamalCrypto.encrypt(aes_key_hex, elgamal_keys["public_key"])
            
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
            return {"status": "error", "message": f"Lỗi Full Demo: {str(e)}"}