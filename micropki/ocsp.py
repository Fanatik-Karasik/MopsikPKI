from pathlib import Path
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID
from .database import PKIDatabase
from .logger import setup_logger

logger = setup_logger()

class OCSPResponder:
    def __init__(self, db_path="pki/micropki.db", responder_cert=None, responder_key=None, ca_cert=None):
        self.db = PKIDatabase(db_path)
        self.responder_cert = x509.load_pem_x509_certificate(Path(responder_cert).read_bytes()) if responder_cert else None
        self.responder_key = None
        if responder_key:
            self.responder_key = rsa.generate_private_key(65537, 2048, default_backend())  # placeholder
        self.ca_cert = x509.load_pem_x509_certificate(Path(ca_cert).read_bytes()) if ca_cert else None

    def issue_ocsp_cert(self, ca_cert_path, ca_key_path, ca_passphrase, subject_str, san_list=None, validity_days=365):
        from .ca import CertificateAuthority
        ca = CertificateAuthority()
        ca.issue_end_entity_cert(
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_passphrase=ca_passphrase,
            template="server",
            subject_str=subject_str,
            san_list=san_list or [],
            validity_days=validity_days,
            db=self.db
        )
        print("OCSP Responder certificate issued")