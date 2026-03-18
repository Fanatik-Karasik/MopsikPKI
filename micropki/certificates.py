import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.hazmat.primitives.asymmetric import padding
import ipaddress


def parse_subject(subject_str: str) -> x509.Name:
    attrs = []
    parts = [p.strip() for p in subject_str.split(",") if p.strip()]
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Неверный формат атрибута: {part}")
        k, v = part.split("=", 1)
        k = k.strip().upper()
        v = v.strip()
        if k == "CN":
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, v))
        elif k == "O":
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, v))
        elif k == "OU":
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, v))
        elif k == "C":
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, v))
        elif k == "ST":
            attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, v))
        elif k == "L":
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, v))
        elif k == "EMAIL":
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, v))
        else:
            raise ValueError(f"Неизвестный атрибут DN: {k}")
    return x509.Name(attrs)


def parse_san(san_list: list[str]) -> list[x509.GeneralName]:
    names = []
    for item in san_list:
        if ":" not in item:
            raise ValueError(f"Неверный формат SAN: {item}")
        typ, value = item.split(":", 1)
        typ = typ.lower().strip()
        value = value.strip()
        if typ == "dns":
            names.append(x509.DNSName(value))
        elif typ == "ip":
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif typ == "email":
            names.append(x509.RFC822Name(value))
        elif typ == "uri":
            names.append(x509.UniformResourceIdentifier(value))
        else:
            raise ValueError(f"Неизвестный тип SAN: {typ}")
    return names


def get_template_extensions(template: str):
    if template == "server":
        return (
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            [ExtendedKeyUsageOID.SERVER_AUTH]
        )
    elif template == "client":
        return (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                data_encipherment=False,
                key_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            [ExtendedKeyUsageOID.CLIENT_AUTH]
        )
    elif template == "code_signing":
        return (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                data_encipherment=False,
                key_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            [ExtendedKeyUsageOID.CODE_SIGNING]
        )
    raise ValueError(f"Неизвестный шаблон: {template}")


def save_cert_pem(cert: x509.Certificate, path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))