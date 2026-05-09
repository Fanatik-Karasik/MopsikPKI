import pytest
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from micropki.ca import CertificateAuthority
from micropki.crypto_utils import load_passphrase
from micropki.certificates import parse_subject, parse_san
from micropki.database import PKIDatabase
from micropki.crl import CRLManager


@pytest.fixture(scope="function")
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)


@pytest.fixture
def passphrase_file(temp_dir):
    pass_file = temp_dir / "test.pass"
    pass_file.write_bytes(b"test123")
    return pass_file


# ====================== SPRINT 1 ======================
def test_root_ca_creation_rsa(temp_dir, passphrase_file):
    ca = CertificateAuthority(out_dir=temp_dir)
    passphrase = load_passphrase(passphrase_file)

    ca.init_root_ca(
        subject_str="CN=Test Root CA,O=Test,C=RU",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        validity_days=365,
    )

    assert (ca.certs_dir / "ca.cert.pem").exists()
    assert (ca.private_dir / "ca.key.pem").exists()

    cert = x509.load_pem_x509_certificate((ca.certs_dir / "ca.cert.pem").read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True


# ====================== SPRINT 2 ======================
def test_intermediate_ca_creation(temp_dir, passphrase_file):
    root_ca = CertificateAuthority(out_dir=temp_dir / "root")
    root_pass = load_passphrase(passphrase_file)
    root_ca.init_root_ca("CN=Root Test", "rsa", 4096, root_pass, 365)

    int_ca = CertificateAuthority(out_dir=temp_dir / "int")
    int_pass_file = temp_dir / "int.pass"
    int_pass_file.write_bytes(b"int123")
    int_pass = load_passphrase(int_pass_file)

    int_ca.issue_intermediate_ca(
        root_cert_path=root_ca.certs_dir / "ca.cert.pem",
        root_key_path=root_ca.private_dir / "ca.key.pem",
        root_passphrase=root_pass,
        subject_str="CN=Intermediate Test",
        key_type="rsa",
        key_size=4096,
        passphrase=int_pass,
        validity_days=365,
        pathlen=0,
    )

    assert (int_ca.certs_dir / "intermediate.cert.pem").exists()


def test_end_entity_server_cert(temp_dir, passphrase_file):
    root_ca = CertificateAuthority(out_dir=temp_dir / "root")
    root_pass = load_passphrase(passphrase_file)
    root_ca.init_root_ca("CN=Root Test", "rsa", 4096, root_pass, 365)

    int_ca = CertificateAuthority(out_dir=temp_dir / "int")
    int_pass_file = temp_dir / "int.pass"
    int_pass_file.write_bytes(b"int123")
    int_pass = load_passphrase(int_pass_file)

    int_ca.issue_intermediate_ca(
        root_cert_path=root_ca.certs_dir / "ca.cert.pem",
        root_key_path=root_ca.private_dir / "ca.key.pem",
        root_passphrase=root_pass,
        subject_str="CN=Intermediate Test",
        key_type="rsa",
        key_size=4096,
        passphrase=int_pass,
        validity_days=365,
        pathlen=0,
    )

    end_ca = CertificateAuthority(out_dir=temp_dir / "end")
    end_ca.issue_end_entity_cert(
        ca_cert_path=int_ca.certs_dir / "intermediate.cert.pem",
        ca_key_path=int_ca.private_dir / "intermediate.key.pem",
        ca_passphrase=int_pass,
        template="server",
        subject_str="CN=web.test.local",
        san_list=["dns:web.test.local", "ip:10.0.0.5"],
        validity_days=90,
    )

    cert_files = list(end_ca.certs_dir.glob("*.cert.pem"))
    key_files = list(end_ca.certs_dir.glob("*.key.pem"))

    assert len(cert_files) >= 1
    assert len(key_files) >= 1

    key_path = key_files[0]
    assert "ENCRYPTED" not in key_path.read_text(encoding="utf-8")


# ====================== SPRINT 3 ======================
def test_database_operations(temp_dir, passphrase_file):
    db = PKIDatabase(temp_dir / "test.db")

    root_ca = CertificateAuthority(out_dir=temp_dir / "root")
    root_pass = load_passphrase(passphrase_file)
    root_ca.init_root_ca("CN=Root Test", "rsa", 4096, root_pass, 365)

    int_ca = CertificateAuthority(out_dir=temp_dir / "int")
    int_pass_file = temp_dir / "int.pass"
    int_pass_file.write_bytes(b"int123")
    int_pass = load_passphrase(int_pass_file)

    int_ca.issue_intermediate_ca(
        root_cert_path=root_ca.certs_dir / "ca.cert.pem",
        root_key_path=root_ca.private_dir / "ca.key.pem",
        root_passphrase=root_pass,
        subject_str="CN=Intermediate Test",
        key_type="rsa",
        key_size=4096,
        passphrase=int_pass,
        validity_days=365,
        pathlen=0,
    )

    end_ca = CertificateAuthority(out_dir=temp_dir / "end")
    end_ca.issue_end_entity_cert(
        ca_cert_path=int_ca.certs_dir / "intermediate.cert.pem",
        ca_key_path=int_ca.private_dir / "intermediate.key.pem",
        ca_passphrase=int_pass,
        template="server",
        subject_str="CN=db.test.local",
        san_list=["dns:db.test.local"],
        validity_days=30,
        db=db
    )

    rows = db.list_certs()
    assert len(rows) >= 1

    db.close()


# # ====================== SPRINT 4 ======================
# def test_revoke_and_crl(temp_dir, passphrase_file):
#     root_ca = CertificateAuthority(out_dir=temp_dir / "root")
#     root_pass = load_passphrase(passphrase_file)
#     root_ca.init_root_ca("CN=Root Test", "rsa", 4096, root_pass, 365)

#     int_ca = CertificateAuthority(out_dir=temp_dir / "int")
#     int_pass_file = temp_dir / "int.pass"
#     int_pass_file.write_bytes(b"int123")
#     int_pass = load_passphrase(int_pass_file)

#     int_ca.issue_intermediate_ca(
#         root_cert_path=root_ca.certs_dir / "ca.cert.pem",
#         root_key_path=root_ca.private_dir / "ca.key.pem",
#         root_passphrase=root_pass,
#         subject_str="CN=Intermediate Test",
#         key_type="rsa",
#         key_size=4096,
#         passphrase=int_pass,
#         validity_days=365,
#         pathlen=0,
#     )

#     end_ca = CertificateAuthority(out_dir=temp_dir / "end")
#     end_ca.issue_end_entity_cert(
#         ca_cert_path=int_ca.certs_dir / "intermediate.cert.pem",
#         ca_key_path=int_ca.private_dir / "intermediate.key.pem",
#         ca_passphrase=int_pass,
#         template="server",
#         subject_str="CN=revoke.test.local",
#         san_list=["dns:revoke.test.local"],
#         validity_days=90,
#     )

#     # Получаем serial из БД
#     db = PKIDatabase(temp_dir / "test.db")
#     rows = db.list_certs()
#     assert len(rows) > 0
#     serial_hex = rows[0]['serial_hex']

#     # Отзыв и генерация CRL
#     crl_manager = CRLManager(out_dir=temp_dir)
#     crl_manager.revoke(serial_hex, "keyCompromise")
#     crl_manager.generate_crl(ca_level="intermediate")

#     # Проверка
#     revoked = db.list_certs(status="revoked")
#     assert len(revoked) >= 1

#     db.close()
#     crl_manager.db.close()


# ====================== UTILS ======================
def test_subject_and_san_parsing():
    s = parse_subject("CN=example.com,O=Org,C=RU")
    assert s.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "example.com"

    sans = parse_san([
        "dns:example.com",
        "ip:192.168.1.1",
        "email:user@domain.ru"
    ])
    assert len(sans) == 3
    assert isinstance(sans[0], x509.DNSName)
    assert isinstance(sans[1], x509.IPAddress)
    assert isinstance(sans[2], x509.RFC822Name)