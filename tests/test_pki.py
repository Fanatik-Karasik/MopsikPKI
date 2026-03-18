import pytest
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from micropki.ca import CertificateAuthority
from micropki.crypto_utils import load_passphrase
from micropki.certificates import parse_subject, parse_san


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)


@pytest.fixture
def passphrase_file(temp_dir):
    pass_file = temp_dir / "test.pass"
    pass_file.write_bytes(b"test123")
    return pass_file


def test_root_ca_creation_rsa(temp_dir, passphrase_file):
    """Проверяем создание корневого CA на RSA"""
    ca = CertificateAuthority(out_dir=temp_dir)
    passphrase = load_passphrase(passphrase_file)

    ca.init_root_ca(
        subject_str="CN=Test Root,O=Test,C=RU",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        validity_days=365,
    )

    cert_path = ca.certs_dir / "ca.cert.pem"
    key_path = ca.private_dir / "ca.key.pem"

    assert cert_path.exists(), "Сертификат root не создан"
    assert key_path.exists(), "Ключ root не создан"

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True, "Root должен быть CA"


def test_intermediate_ca_creation(temp_dir, passphrase_file):
    """Проверяем создание промежуточного CA"""
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

    cert_path = int_ca.certs_dir / "intermediate.cert.pem"
    assert cert_path.exists()

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    assert bc.value.path_length == 0


def test_end_entity_server_cert(temp_dir, passphrase_file):
    """Проверяем выпуск серверного сертификата"""
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

    assert len(cert_files) >= 1, "Сертификат конечного субъекта не найден"
    assert len(key_files) >= 1, "Ключ конечного субъекта не найден"

    cert_path = cert_files[0]
    key_path = key_files[0]

    assert "ENCRYPTED" not in key_path.read_text(encoding="utf-8"), "Ключ конечного субъекта зашифрован"

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.digital_signature is True
    assert ku.value.key_encipherment is True


def test_subject_parsing_basic():
    """Простая проверка парсинга DN без emailAddress"""
    s = parse_subject("CN=example.com,O=Org,C=RU")
    cn = s.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn) == 1
    assert cn[0].value == "example.com"


def test_san_parsing():
    """Проверка парсинга SAN"""
    sans = parse_san([
        "dns:example.com",
        "ip:192.168.1.1",
        "email:user@domain.ru",
        "uri:https://test.ru"
    ])
    assert len(sans) == 4
    assert isinstance(sans[0], x509.DNSName)
    assert isinstance(sans[1], x509.IPAddress)
    assert isinstance(sans[2], x509.RFC822Name)
    assert isinstance(sans[3], x509.UniformResourceIdentifier)