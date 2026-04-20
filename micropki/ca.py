from pathlib import Path
from datetime import datetime, timedelta, timezone
from venv import logger

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend  

from .crypto_utils import (
    generate_key_pair,
    save_private_key,
    load_private_key,
    generate_serial_number,
    load_passphrase,
)
from .certificates import (
    parse_subject,
    parse_san,
    get_template_extensions,
    save_cert_pem,
)
from .database import PKIDatabase
from .logger import setup_logger

class CertificateAuthority:
    def __init__(self, out_dir: str | Path = "./pki", log_file=None):
        self.out_dir = Path(out_dir)
        self.certs_dir = self.out_dir / "certs"
        self.private_dir = self.out_dir / "private"
        
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.private_dir.mkdir(parents=True, exist_ok=True)

        setup_logger(log_file)
        logger.info(f"CA инициализирован, out_dir={self.out_dir}")

    def init_root_ca(
        self,
        subject_str: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        validity_days: int,
    ):
        private_key = generate_key_pair(key_type, key_size)

        subject = parse_subject(subject_str)

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # self-signed
            .public_key(private_key.public_key())
            .serial_number(generate_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
                critical=False,
            )
        )

        cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA384(),
        )

        save_private_key(private_key, self.private_dir / "ca.key.pem", passphrase)
        save_cert_pem(cert, self.certs_dir / "ca.cert.pem")

        print(f"Корневой УЦ создан:")
        print(f"  Сертификат: {self.certs_dir / 'ca.cert.pem'}")
        print(f"  Ключ      : {self.private_dir / 'ca.key.pem'} (зашифрован)")

    def issue_intermediate_ca(
        self,
        root_cert_path: str | Path,
        root_key_path: str | Path,
        root_passphrase: bytes,
        subject_str: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        validity_days: int,
        pathlen: int = 0,
    ):
        root_cert = x509.load_pem_x509_certificate(Path(root_cert_path).read_bytes())
        root_key = load_private_key(Path(root_key_path), root_passphrase)

        intermediate_key = generate_key_pair(key_type, key_size)

        subject = parse_subject(subject_str)

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_cert.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(generate_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=pathlen),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
                critical=False,
            )
        )

        cert = builder.sign(
            private_key=root_key,
            algorithm=hashes.SHA384(),
        )

        save_private_key(intermediate_key, self.private_dir / "intermediate.key.pem", passphrase)
        save_cert_pem(cert, self.certs_dir / "intermediate.cert.pem")

        print(f"Промежуточный УЦ создан:")
        print(f"  Сертификат: {self.certs_dir / 'intermediate.cert.pem'}")
        print(f"  Ключ      : {self.private_dir / 'intermediate.key.pem'} (зашифрован)")

    def issue_end_entity_cert(
        self,
        ca_cert_path: str | Path,
        ca_key_path: str | Path,
        ca_passphrase: bytes,
        template: str,
        subject_str: str,
        san_list: list[str],
        validity_days: int,
        db: PKIDatabase = None
    ):
        from cryptography.hazmat.primitives import serialization 

        ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
        ca_key = load_private_key(Path(ca_key_path), ca_passphrase)

        subject = parse_subject(subject_str)
        sans = parse_san(san_list) if san_list else []

        end_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        key_filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in cn)
        
        key_path = self.certs_dir / f"{key_filename}.key.pem"
        cert_path = self.certs_dir / f"{key_filename}.cert.pem"

        save_private_key(end_key, key_path, passphrase=None)
        print(f"ВНИМАНИЕ: закрытый ключ конечного субъекта сохранён БЕЗ шифрования: {key_path}")

        ku, eku = get_template_extensions(template)

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(end_key.public_key())
            .serial_number(generate_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(ku, critical=True)
        )

        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        save_cert_pem(cert, cert_path)

        if db is not None:
            db.insert_certificate(cert, cert_pem, ca_cert.subject.rfc4514_string())

        print(f"   Сертификат ({template}) успешно создан:")
        print(f"   Сертификат: {cert_path}")
        print(f"   Ключ      : {key_path}")