from pathlib import Path
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from .database import PKIDatabase
from .logger import setup_logger

logger = setup_logger()

class CRLManager:
    def __init__(self, out_dir: Path = Path("pki")):
        self.out_dir = out_dir
        self.crl_dir = out_dir / "crl"
        self.crl_dir.mkdir(parents=True, exist_ok=True)
        self.db = PKIDatabase(out_dir / "micropki.db")

    def revoke(self, serial_hex: str, reason: str = "unspecified"):
        self.db.revoke_cert(serial_hex, reason)
        logger.info(f"Certificate {serial_hex} revoked with reason: {reason}")

    def generate_crl(self, ca_level: str = "intermediate", next_update_days: int = 7):
        if ca_level == "root":
            cert_path = self.out_dir / "certs" / "ca.cert.pem"
            key_path = self.out_dir / "private" / "ca.key.pem"
            crl_path = self.crl_dir / "root.crl.pem"
        else:
            cert_path = self.out_dir / "certs" / "intermediate.cert.pem"
            key_path = self.out_dir / "private" / "intermediate.key.pem"
            crl_path = self.crl_dir / "intermediate.crl.pem"

        ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        private_key = rsa.generate_private_key(65537, 2048, default_backend())

        revoked_list = []
        rows = self.db.conn.execute(
            "SELECT serial_hex, revocation_date FROM certificates WHERE status = 'revoked'"
        ).fetchall()

        for row in rows:
            serial = int(row['serial_hex'], 16)
            rev_date = datetime.datetime.fromisoformat(row['revocation_date'])
            revoked_cert = x509.RevokedCertificateBuilder() \
                .serial_number(serial) \
                .revocation_date(rev_date) \
                .build()
            revoked_list.append(revoked_cert)

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime.now(datetime.timezone.utc))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=next_update_days))
        )

        for rc in revoked_list:
            builder = builder.add_revoked_certificate(rc)

        crl = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        crl_path.write_bytes(crl.public_bytes(Encoding.PEM))
        logger.info(f"CRL generated and saved: {crl_path}")
        print(f"CRL успешно создан: {crl_path}")
        return crl_path