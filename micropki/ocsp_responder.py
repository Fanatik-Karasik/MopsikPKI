from flask import Flask, request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
import datetime
from .database import PKIDatabase
from .logger import setup_logger

logger = setup_logger()
app = Flask(__name__)
db = None

def init_ocsp(db_path="pki/micropki.db"):
    global db
    db = PKIDatabase(db_path)

@app.route('/ocsp', methods=['POST'])
def ocsp_handler():
    try:
        ocsp_request = request.data
        req = x509.load_der_x509_ocsp_request(ocsp_request)

        responses = []
        for single_req in req.request_list:
            serial = single_req.serial_number
            cert_info = db.get_cert_by_serial(format(serial, 'X'))

            if cert_info and cert_info['status'] == 'revoked':
                status = x509.ocsp.OCSPResponseStatus.REVOKED
                revocation_time = datetime.datetime.fromisoformat(cert_info['revocation_date'])
                reason = cert_info.get('revocation_reason', 'unspecified')
            elif cert_info:
                status = x509.ocsp.OCSPResponseStatus.GOOD
            else:
                status = x509.ocsp.OCSPResponseStatus.UNKNOWN

            builder = x509.ocsp.OCSPResponseBuilder()
            builder = builder.cert_status(status)
            if status == x509.ocsp.OCSPResponseStatus.REVOKED:
                builder = builder.revocation_time(revocation_time)
                builder = builder.revocation_reason(reason)

            responses.append(builder)

        ocsp_response = x509.ocsp.OCSPResponseBuilder().build(responses)
        return Response(ocsp_response.public_bytes(), mimetype="application/ocsp-response")

    except Exception as e:
        logger.error(f"OCSP error: {e}")
        return Response(b"", status=400)

def run_ocsp_server(host="127.0.0.1", port=8081, db_path="pki/micropki.db"):
    global db
    init_ocsp(db_path)
    print(f"OCSP Responder started at http://{host}:{port}/ocsp")
    app.run(host=host, port=port, debug=False)