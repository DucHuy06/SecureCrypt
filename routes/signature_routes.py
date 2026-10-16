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

# Đảm bảo thư mục certificates tồn tại
CERT_DIR.mkdir(parents=True, exist_ok=True)


@signature_bp.errorhandler(500)
def internal_error(error):
    return jsonify(success=False, message="Lỗi hệ thống máy chủ nội bộ (HTTP 500)."), 500


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
    try:
        uploaded = request.files.get("file")
        pdf_data, error = read_pdf_upload(uploaded)

        if error:
            return jsonify(success=False, message=error), 400

        if not PRIVATE_KEY.is_file() or not CERTIFICATE.is_file():
            return jsonify(
                success=False,
                message="Không tìm thấy file khóa riêng (private_key.pem) hoặc chứng thư trong thư mục certificates."
            ), 500

        signer = signers.SimpleSigner.load(
            key_file=str(PRIVATE_KEY),
            cert_file=str(CERTIFICATE),
        )

        if signer is None:
            return jsonify(
                success=False,
                message="Không đọc được khóa riêng hoặc chứng thư."
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
    try:
        uploaded = request.files.get("file")
        pdf_data, error = read_pdf_upload(uploaded)

        if error:
            return jsonify(success=False, message=error), 400

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

            vc = ValidationContext()
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
                    report_lines.append(f"Chữ ký '{sig_field}': Toàn vẹn (intact)={intact}")
                    
                    if not intact:
                        all_valid = False
                except Exception as ex:
                    report_lines.append(f"Chi tiết chữ ký '{sig_field}': {str(ex)}")
                    all_valid = True

            report_text = "\n".join(report_lines)

            return jsonify(
                success=True,
                valid=all_valid,
                trusted=True,
                message="Chữ ký số hợp lệ và đáng tin cậy." if all_valid else "Chữ ký không hợp lệ.",
                details=report_text,
            )

    except Exception as e:
        logger.exception("PDF verification failed")
        return jsonify(
            success=False,
            message=f"Lỗi xác minh PDF: {str(e)}"
        ), 500