from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from .database import PKIDatabase


class PathValidator:
    def __init__(self, trusted_root_path):
        self.trusted_root = x509.load_pem_x509_certificate(Path(trusted_root_path).read_bytes())

    def validate_chain(self, cert_path, untrusted_paths=None):
        leaf = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        intermediates = []

        if untrusted_paths:
            for p in untrusted_paths:
                intermediates.append(x509.load_pem_x509_certificate(Path(p).read_bytes()))

        current = leaf
        for inter in intermediates:
            if not self._verify_signature(current, inter.public_key()):
                return False, "Signature verification failed"
            current = inter

        if not self._verify_signature(current, self.trusted_root.public_key()):
            return False, "Root signature verification failed"

        return True, "Chain validation successful"

    def _verify_signature(self, cert, public_key):
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters or hashes.SHA256(),
                cert.signature_algorithm
            )
            return True
        except InvalidSignature:
            return False