from pathlib import Path
from io import BytesIO
import logging

from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename

from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, ValidationContext


signature_bp = Blueprint(
    "signature",
    __name__,
    url_prefix="/signature"
)

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CERT_DIR = BASE_DIR / "certificates"
PRIVATE_KEY = CERT_DIR / "private_key.pem"
CERTIFICATE = CERT_DIR / "certificate.pem"

MAX_PDF_SIZE = 20 * 1024 * 1024


def read_pdf_upload(uploaded):
    if not uploaded or not uploaded.filename:
        return None, "Vui lòng chọn file PDF."

    if not uploaded.filename.lower().endswith(".pdf"):
        return None, "Chỉ chấp nhận file PDF."

    data = uploaded.read(MAX_PDF_SIZE + 1)

    if len(data) > MAX_PDF_SIZE:
        return None, "File vượt quá giới hạn 20 MB."

    if not data.startswith(b"%PDF-"):
        return None, "File không phải PDF hợp lệ."

    return data, None


# ==================== KÝ PDF ====================

@signature_bp.route("/pdf/sign", methods=["POST"])
def sign_pdf():
    uploaded = request.files.get("file")
    pdf_data, error = read_pdf_upload(uploaded)

    if error:
        return jsonify(
            success=False,
            message=error
        ), 400

    if not PRIVATE_KEY.is_file() or not CERTIFICATE.is_file():
        logger.error(
            "PDF signing: private key or certificate not found. "
            "Key exists=%s, certificate exists=%s",
            PRIVATE_KEY.is_file(),
            CERTIFICATE.is_file(),
        )

        return jsonify(
            success=False,
            message="Không tìm thấy file private_key.pem hoặc certificate.pem trong thư mục certificates."
        ), 500

    try:
        signer = signers.SimpleSigner.load(
            key_file=str(PRIVATE_KEY),
            cert_file=str(CERTIFICATE),
        )

        if signer is None:
            return jsonify(
                success=False,
                message="pyHanko không thể tải được khóa riêng hoặc chứng thư."
            ), 500

        with BytesIO(pdf_data) as source:
            writer = IncrementalPdfFileWriter(source)
            output = BytesIO()

            metadata = PdfSignatureMetadata(
                field_name="SecureCryptSignature",
                md_algorithm="sha256",
            )

            signers.sign_pdf(
                writer,
                signature_meta=metadata,
                signer=signer,
                output=output,
                new_field_spec=SigFieldSpec(
                    sig_field_name="SecureCryptSignature",
                    on_page=0,
                    box=(36, 36, 250, 100),
                ),
            )

            output.seek(0)

            original_name = secure_filename(
                uploaded.filename or "document.pdf"
            )
            stem = Path(original_name).stem or "document"

            return send_file(
                output,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"{stem}_signed.pdf",
            )

    except Exception as e:
        logger.exception("PDF signing failed")
        return jsonify(
            success=False,
            message=f"Lỗi ký PDF: {str(e)}"
        ), 500


# ==================== XÁC MINH PDF ====================

@signature_bp.route("/pdf/verify", methods=["POST"])
def verify_pdf():
    uploaded = request.files.get("file")
    pdf_data, error = read_pdf_upload(uploaded)

    if error:
        return jsonify(
            success=False,
            message=error
        ), 400

    try:
        with BytesIO(pdf_data) as fd:
            reader = PdfFileReader(fd)
            sig_fields = reader.embedded_signatures

            if not sig_fields:
                return jsonify(
                    success=True,
                    valid=False,
                    trusted=False,
                    message="Tài liệu PDF không chứa chữ ký số nào.",
                    details="Không tìm thấy trường chữ ký trong file PDF."
                )

            trust_roots = []
            if CERTIFICATE.is_file():
                try:
                    from asn1crypto import x509
                    cert_bytes = CERTIFICATE.read_bytes()
                    trust_roots.append(x509.Certificate.load(cert_bytes))
                except Exception:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_bytes = CERTIFICATE.read_bytes()
                        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                        # Fallback nếu dùng pyHanko chuẩn
                        trust_roots = [CERTIFICATE]
                    except Exception:
                        trust_roots = [CERTIFICATE]

            vc = ValidationContext(trust_roots=trust_roots) if trust_roots else ValidationContext()

            report_lines = []
            all_valid = True

            for sig_field in sig_fields:
                try:
                    status = validate_pdf_signature(
                        reader,
                        sig_field,
                        validation_context=vc
                    )
                    intact = status.intact
                    valid = status.valid
                    
                    report_lines.append(f"Chữ ký '{sig_field}': Toàn vẹn (intact)={intact}, Hợp lệ (valid)={valid}")
                    
                    if not (intact and valid):
                        all_valid = False
                except Exception as ex:
                    all_valid = False
                    report_lines.append(f"Chữ ký '{sig_field}' lỗi xác minh: {str(ex)}")

            report_text = "\n".join(report_lines)

            return jsonify(
                success=True,
                valid=all_valid,
                trusted=all_valid,
                message="Đã hoàn tất kiểm tra chữ ký tài liệu." if all_valid else "Chữ ký không hợp lệ hoặc không đáng tin cậy.",
                details=report_text,
            )

    except Exception as e:
        logger.exception("PDF verification failed")
        return jsonify(
            success=False,
            message=f"Lỗi xác minh PDF: {str(e)}"
        ), 500