import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from micropki.ca import CertificateAuthority
from micropki.crypto_utils import load_passphrase
from micropki.certificates import parse_subject

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)

@pytest.fixture
def passphrase_file(temp_dir):
    pass_file = temp_dir / "test.pass"
    pass_file.write_bytes(b"test-passphrase-123")
    return pass_file

def test_ca_init_rsa(temp_dir, passphrase_file):
    ca = CertificateAuthority(temp_dir / "test_rsa")
    passphrase = load_passphrase(passphrase_file)
    ca.init_root_ca(
        subject_str="/CN=Test RSA CA",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        validity_days=365
    )
    assert (ca.private_dir / "ca.key.pem").exists()
    assert (ca.certs_dir / "ca.cert.pem").exists()
    assert (ca.out_dir / "policy.txt").exists()
    cert_pem = (ca.certs_dir / "ca.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca

def test_ca_init_ecc(temp_dir, passphrase_file):
    ca = CertificateAuthority(temp_dir / "test_ecc")
    passphrase = load_passphrase(passphrase_file)
    ca.init_root_ca(
        subject_str="CN=Test ECC CA,O=Test",
        key_type="ecc",
        key_size=384,
        passphrase=passphrase,
        validity_days=365
    )
    assert (ca.private_dir / "ca.key.pem").exists()
    assert (ca.certs_dir / "ca.cert.pem").exists()
    assert (ca.out_dir / "policy.txt").exists()

def test_invalid_args(temp_dir, passphrase_file):
    ca = CertificateAuthority(temp_dir / "test_invalid")
    passphrase = load_passphrase(passphrase_file)
    with pytest.raises(ValueError):
        ca.init_root_ca(
            subject_str="/CN=Test",
            key_type="rsa",
            key_size=2048,
            passphrase=passphrase,
            validity_days=365
        )
    with pytest.raises(ValueError):
        ca.init_root_ca(
            subject_str="/CN=Test",
            key_type="ecc",
            key_size=256,
            passphrase=passphrase,
            validity_days=365
        )

def test_subject_parsing():
    subject1 = parse_subject("/CN=Test CA/O=Demo")
    assert subject1.rfc4514_string() in ["CN=Test CA,O=Demo", "O=Demo,CN=Test CA"]
    subject2 = parse_subject("CN=Test CA,O=Demo")
    assert subject2.rfc4514_string() in ["CN=Test CA,O=Demo", "O=Demo,CN=Test CA"]