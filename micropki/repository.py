from flask import Flask, Response, request, jsonify
from pathlib import Path
from .database import PKIDatabase
from .logger import setup_logger

logger = setup_logger()

app = Flask(__name__)
db = None
cert_dir = None


def init_repository(db_path="pki/micropki.db", cert_directory="pki/certs"):
    global db, cert_dir
    db = PKIDatabase(db_path)
    cert_dir = Path(cert_directory)


@app.route('/')
def index():
    return """
    <h1>MopsikPKI Repository</h1>
    <p><strong>Sprint 3</strong> — HTTP Repository работает </p>
    <hr>
    <h3>Доступные эндпоинты:</h3>
    <ul>
        <li><a href="/ca/root">/ca/root</a> — Корневой сертификат</li>
        <li><a href="/ca/intermediate">/ca/intermediate</a> — Промежуточный сертификат</li>
        <li><a href="/certificate/46C490873BAB706F6D1A276C3E8A77C3D1224F60">/certificate/&lt;serial&gt;</a> — Пример сертификата</li>
        <li><a href="/crl">/crl</a> — CRL (пока заглушка)</li>
    </ul>
    <p>Используйте <code>curl</code> или браузер для скачивания сертификатов.</p>
    """


@app.route('/certificate/<serial>')
def get_certificate(serial):
    cert_record = db.get_cert_by_serial(serial)
    if cert_record:
        logger.info(f"Запрошен сертификат {serial} от {request.remote_addr}")
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


@app.route('/crl')
def get_crl():
    return Response("CRL generation will be implemented in Sprint 4", status=501)


def run_server(host="127.0.0.1", port=8080, db_path="pki/micropki.db", cert_dir="pki/certs"):
    init_repository(db_path, cert_dir)
    print(f" Repository HTTP server started at http://{host}:{port}")
    print("Открывай в браузере: http://127.0.0.1:8080")
    app.run(host=host, port=port, debug=False)