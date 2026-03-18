from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import os
import secrets

def load_passphrase(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"Файл с паролем не найден: {path}")
    content = path.read_bytes().strip()
    if not content:
        raise ValueError("Файл с паролем пустой")
    return content


def generate_serial_number() -> int:
    return secrets.randbelow(2**159)  # достаточно большой и уникальный


def generate_key_pair(key_type: str, key_size: int = None):
    if key_type == "rsa":
        if key_size is None:
            key_size = 2048 
        if key_size not in [2048, 3072, 4096]:
            raise ValueError("Для RSA key-size должен быть 2048, 3072 или 4096")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    elif key_type == "ecc":
        if key_size is None or key_size == 384:
            return ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        else:
            raise ValueError("Для ECC поддерживается только key-size=384 (P-384)")
    else:
        raise ValueError(f"Неизвестный тип ключа: {key_type}")


def save_private_key(key, path: Path, passphrase: bytes = None):
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase else
        serialization.NoEncryption()
    )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def load_private_key(path: Path, passphrase: bytes) -> object:
    data = path.read_bytes()
    return serialization.load_pem_private_key(
        data,
        password=passphrase,
        backend=default_backend()
    )