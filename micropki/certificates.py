import datetime
import secrets
import logging
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import ipaddress

logger = logging.getLogger(__name__)

def generate_serial_number():
    random_bytes = secrets.token_bytes(19)
    serial = int.from_bytes(random_bytes, byteorder='big')
    logger.debug(f"Сгенерирован серийный номер: {hex(serial)}")
    return serial

def parse_subject(subject_str):
    attributes = []
    if subject_str.startswith('/'):
        parts = subject_str[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes.append(_create_name_attribute(key.strip(), value.strip()))
    else:
        parts = subject_str.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes.append(_create_name_attribute(key.strip(), value.strip()))
    if not attributes:
        raise ValueError(f"Не удалось распарсить subject: {subject_str}")
    return x509.Name(attributes)

def _create_name_attribute(key, value):
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'STREET': NameOID.STREET_ADDRESS,
        'EMAIL': NameOID.EMAIL_ADDRESS
    }
    oid = oid_map.get(key.upper())
    if not oid:
        raise ValueError(f"Неизвестный атрибут subject: {key}")
    return x509.NameAttribute(oid, value)

def calculate_ski(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    return digest.finalize()

def generate_self_signed_cert(private_key, subject_name, validity_days, key_type):
    logger.info("Начало генерации самоподписанного сертификата")
    public_key = private_key.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    if key_type == 'rsa':
        signature_algorithm = hashes.SHA256()
        logger.info("Используется алгоритм подписи SHA256 с RSA")
    else:
        signature_algorithm = hashes.SHA384()
        logger.info("Используется алгоритм подписи SHA384 с ECDSA")
    ski = calculate_ski(public_key)
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject_name)
    cert_builder = cert_builder.issuer_name(subject_name)
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + datetime.timedelta(days=validity_days))
    cert_builder = cert_builder.serial_number(generate_serial_number())
    cert_builder = cert_builder.public_key(public_key)
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier(digest=ski),
        critical=False
    )
    cert_builder = cert_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier(digest=ski)
        ),
        critical=False
    )
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )
    logger.info("Сертификат успешно подписан")
    return certificate

def cert_to_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)

def load_pem_certificate(cert_path: Path):
    """Загрузить сертификат из PEM"""
    return x509.load_pem_x509_certificate(cert_path.read_bytes())

def save_cert_pem(certificate, path: Path):
    """Сохранить сертификат в PEM"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Сертификат сохранён: {path}")

def parse_san_list(san_strings):
    """dns:example.com, ip:1.2.3.4, email:user@example.com"""
    sans = []
    for item in san_strings:
        if ":" not in item:
            continue
        typ, value = item.split(":", 1)
        typ = typ.lower().strip()
        if typ == "dns":
            sans.append(x509.DNSName(value))
        elif typ == "ip":
            sans.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif typ == "email":
            sans.append(x509.RFC822Name(value))
        elif typ == "uri":
            sans.append(x509.UniformResourceIdentifier(value))
    return sans

def get_template_extensions(template: str):
    """Возвращает KeyUsage + ExtendedKeyUsage для шаблона"""
    if template == "server":
        return (
            x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                          crl_sign=False, content_commitment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            [ExtendedKeyUsageOID.SERVER_AUTH]
        )
    elif template == "client":
        return (
            x509.KeyUsage(digital_signature=True, key_encipherment=False, key_agreement=True,
                          key_cert_sign=False, crl_sign=False, content_commitment=False,
                          data_encipherment=False, encipher_only=False, decipher_only=False),
            [ExtendedKeyUsageOID.CLIENT_AUTH]
        )
    elif template == "code_signing":
        return (
            x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                          crl_sign=False, content_commitment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            [ExtendedKeyUsageOID.CODE_SIGNING]
        )
    raise ValueError(f"Неизвестный шаблон: {template}")