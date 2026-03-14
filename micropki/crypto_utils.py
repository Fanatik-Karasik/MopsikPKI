from pathlib import Path
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def load_passphrase(passphrase_file):
    if not passphrase_file.is_file():
        raise FileNotFoundError(f"Файл с парольной фразой не найден: {passphrase_file}")
    try:
        passphrase = passphrase_file.read_bytes()
        return passphrase.strip()
    except IOError as e:
        raise IOError(f"Ошибка чтения файла с парольной фразой {passphrase_file}: {e}")

def generate_rsa_key(key_size=4096):
    logger.info(f"Генерация RSA ключа размером {key_size} бит")
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

def generate_ecc_key():
    logger.info("Генерация ECC ключа на кривой secp384r1 (P-384)")
    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )

def encrypt_private_key(private_key, passphrase, key_type):
    logger.info("Шифрование закрытого ключа с использованием парольной фразы")
    encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    return pem_data

def save_pem_data(data, file_path, description="файл"):
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(data)
        logger.info(f"Сохранен {description}: {file_path}")
    except IOError as e:
        raise IOError(f"Ошибка при сохранении {description} {file_path}: {e}")

def set_file_permissions_warning(file_path):
    logger.warning(
        f"Настройка прав доступа 0o600 для {file_path} не поддерживается на Windows. "
        "Убедитесь, что файл хранится в безопасном месте."
    )

def load_private_key(key_path: Path, passphrase: bytes = None):
    """Загрузить ключ с паролем или без"""
    data = key_path.read_bytes()
    return serialization.load_pem_private_key(
        data,
        password=passphrase,
        backend=default_backend()
    )

def save_private_key(private_key, key_path: Path, passphrase: bytes = None):
    """Сохранить ключ (с паролем или без)"""
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    save_pem_data(pem_data, key_path, "закрытый ключ")
