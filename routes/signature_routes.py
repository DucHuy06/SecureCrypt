
from pathlib import Path
from io import BytesIO
import tempfile
import subprocess
import logging
import shutil

from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename

from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter


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
            message=(
                "Không tìm thấy khóa hoặc chứng thư "
                "trong thư mục certificates."
            )
        ), 500

    try:
        signer = signers.SimpleSigner.load(
            key_file=str(PRIVATE_KEY),
            cert_file=str(CERTIFICATE),
        )

        if signer is None:
            logger.error(
                "PDF signing: pyHanko could not load "
                "the private key or certificate."
            )

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

    except Exception:
        logger.exception("PDF signing failed")

        return jsonify(
            success=False,
            message=(
                "Ký PDF thất bại. Kiểm tra khóa, "
                "chứng thư và file PDF."
            )
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

    # Tìm CLI trong môi trường chạy ứng dụng.
    pyhanko_executable = shutil.which("pyhanko")

    if not pyhanko_executable:
        logger.error(
            "PDF verification failed: 'pyhanko' CLI was not found "
            "in PATH. Check the deployed pyHanko installation."
        )

        return jsonify(
            success=False,
            message=(
                "Máy chủ chưa tìm thấy công cụ xác minh pyHanko. "
                "Hãy kiểm tra requirements.txt và Render Logs."
            )
        ), 500

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "document.pdf"
            pdf_path.write_bytes(pdf_data)

            result = subprocess.run(
                [
                    pyhanko_executable,
                    "sign",
                    "validate",
                    "--pretty-print",
                    str(pdf_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            report = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            ).strip()

            # Lưu kết quả CLI để điều tra nếu xác minh thất bại.
            logger.info(
                "PDF verification CLI completed: returncode=%s, "
                "report=%s",
                result.returncode,
                report[-3000:],
            )

            return jsonify(
                success=True,
                valid=(result.returncode == 0),
                trusted=False,
                message=(
                    "Đã chạy công cụ xác minh. "
                    "Cần xem báo cáo để đánh giá chữ ký và chứng thư."
                ),
                details=report[-6000:],
            )

    except subprocess.TimeoutExpired:
        logger.warning("PDF verification timed out.")

        return jsonify(
            success=False,
            message="Quá thời gian xác minh PDF."
        ), 504

    except FileNotFoundError:
        logger.exception(
            "PDF verification failed: executable not found."
        )

        return jsonify(
            success=False,
            message=(
                "Không tìm thấy chương trình xác minh PDF "
                "trên máy chủ."
            )
        ), 500

    except Exception:
        logger.exception("PDF verification failed")

        return jsonify(
            success=False,
            message=(
                "Không thể xác minh PDF. "
                "Hãy kiểm tra Render Logs để biết chi tiết."
            )
        ), 500
