
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_certificate():
    # Tao thu muc luu khoa va chung thu
    output_dir = Path("certificates")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Tao khoa RSA 2048 bit
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Thong tin chu the cua chung thu thu nghiem
    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME, "SecureCrypt Test User"
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "SecureCrypt"
        ),
    ])

    now = datetime.now(timezone.utc)

    # Tao chung thu tu ky
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Luu khoa rieng
    key_path = output_dir / "private_key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Luu chung thu so
    cert_path = output_dir / "certificate.pem"
    cert_path.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )

    print("Da tao khoa va chung thu thu nghiem thanh cong!")
    print(f"Khoa rieng: {key_path.resolve()}")
    print(f"Chung thu: {cert_path.resolve()}")


if __name__ == "__main__":
    generate_certificate()
