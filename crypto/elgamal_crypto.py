import random
import json
import base64
from Crypto.Util import number

class ElGamalCrypto:
    @staticmethod
    def generate_keypair(bits: int = 512) -> dict:
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

            cipher_pairs = []
            for b in plaintext.encode('utf-8'):
                m = int(b)
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
            return {"status": "error", "message": f"Giải mã ElGamal thất bại: {str(e)}"}