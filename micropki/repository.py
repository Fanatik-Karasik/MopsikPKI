from flask import Flask, Response, request
from pathlib import Path
from cryptography import x509
from .database import PKIDatabase
from .ca import CertificateAuthority
from .logger import setup_logger

logger = setup_logger()

app = Flask(__name__)
cert_dir = None


def init_repository(db_path="pki/micropki.db", cert_directory="pki/certs"):
    global cert_dir
    cert_dir = Path(cert_directory)


@app.route('/')
def index():
    return """
    <h1>MopsikPKI Repository — Sprint 6</h1>
    <p>Client + CSR support</p>
    """


@app.route('/request-cert', methods=['POST'])
def request_cert():
    if 'csr' not in request.files:
        return Response("No CSR provided", status=400)

    csr_file = request.files['csr']
    template = request.form.get('template', 'server')

    try:
        csr = x509.load_pem_x509_csr(csr_file.read())
    except Exception:
        return Response("Invalid CSR", status=400)

    try:
        ca = CertificateAuthority()
        ca_pass = open("secrets/intermediate.pass", "rb").read().strip()

        subject_str = csr.subject.rfc4514_string()
        san_list = []

        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"dns:{name.value}")
        except:
            pass

        ca.issue_end_entity_cert(
            ca_cert_path="pki/certs/intermediate.cert.pem",
            ca_key_path="pki/private/intermediate.key.pem",
            ca_passphrase=ca_pass,
            template=template,
            subject_str=subject_str,
            san_list=san_list,
            validity_days=365,
            db=PKIDatabase()
        )
        return Response("Certificate issued successfully", status=201)

    except Exception as e:
        logger.error(f"Certificate issuance failed: {e}")
        return Response(f"Failed to issue certificate: {str(e)}", status=500)


@app.route('/certificate/<serial>')
def get_certificate(serial):
    db = PKIDatabase()
    cert_record = db.get_cert_by_serial(serial)
    db.close()
    if cert_record:
        return Response(cert_record["cert_pem"], mimetype="application/x-pem-file")
    return Response("Certificate not found", status=404)


@app.route('/ca/<level>')
def get_ca(level):
    if level == "root":
        path = cert_dir / "ca.cert.pem"
    elif level == "intermediate":
        path = cert_dir / "intermediate.cert.pem"
    else:
        return Response("Invalid CA level", status=400)

    if path.exists():
        return Response(path.read_text(encoding="utf-8"), mimetype="application/x-pem-file")
    return Response("CA certificate not found", status=404)


def run_server(host="127.0.0.1", port=8080):
    init_repository()
    print(f"Repository started at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)