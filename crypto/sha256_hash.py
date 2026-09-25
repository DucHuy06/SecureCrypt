import hashlib

class SHA256Hash:
    @staticmethod
    def hash_text(text: str) -> dict:
        try:
            digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
            return {"status": "success", "hash": digest, "algorithm": "SHA-256"}
        except Exception as e:
            return {"status": "error", "message": f"Lỗi tính băm SHA-256: {str(e)}"}

    @staticmethod
    def hash_bytes(data_bytes: bytes) -> str:
        return hashlib.sha256(data_bytes).hexdigest()

    @staticmethod
    def verify_integrity(text_or_hash1: str, hash2: str) -> dict:
        h1 = text_or_hash1.strip().lower()
        h2 = hash2.strip().lower()
        if len(h1) != 64 or any(c not in '0123456789abcdef' for c in h1):
            h1 = hashlib.sha256(text_or_hash1.encode('utf-8')).hexdigest()

        is_valid = (h1 == h2)
        return {
            "status": "success",
            "match": is_valid,
            "message": "Data integrity verified (Matched)." if is_valid else "Data has been modified or hashes do not match."
        }