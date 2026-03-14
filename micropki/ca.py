from pathlib import Path
import logging
from . import certificates
from . import crypto_utils
from .logger import setup_logger

logger = logging.getLogger(__name__)

class CertificateAuthority:
    def __init__(self, out_dir, log_file=None):
        self.out_dir = Path(out_dir)
        self.private_dir = self.out_dir / "private"
        self.certs_dir = self.out_dir / "certs"
        setup_logger(log_file)
        logger.info(f"CA инициализирован, out_dir={self.out_dir}")

    def _create_directory_structure(self):
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Структура директорий создана: {self.out_dir}")

    def init_root_ca(self, subject_str, key_type, key_size, passphrase, validity_days):
        if not subject_str or not subject_str.strip():
            raise ValueError("Параметр subject_str обязателен и не может быть пустым")
        if key_type not in ['rsa', 'ecc']:
            raise ValueError(f"key_type должен быть 'rsa' или 'ecc', получен: {key_type}")
        if key_type == 'rsa' and key_size != 4096:
            raise ValueError(f"Для RSA ключа key_size должен быть 4096, получен: {key_size}")
        if key_type == 'ecc' and key_size != 384:
            raise ValueError(f"Для ECC ключа key_size должен быть 384, получен: {key_size}")
        if validity_days <= 0:
            raise ValueError(f"validity_days должен быть положительным числом, получен: {validity_days}")
        try:
            self._create_directory_structure()
            logger.info(f"Начало генерации ключей (тип: {key_type}, размер: {key_size})")
            if key_type == 'rsa':
                private_key = crypto_utils.generate_rsa_key(key_size)
            else:
                private_key = crypto_utils.generate_ecc_key()
            logger.info("Генерация ключей успешно завершена")
            subject = certificates.parse_subject(subject_str)
            logger.info(f"Subject распарсен: {subject.rfc4514_string()}")
            logger.info("Начало подписания сертификата")
            certificate = certificates.generate_self_signed_cert(
                private_key=private_key,
                subject_name=subject,
                validity_days=validity_days,
                key_type=key_type
            )
            logger.info("Подписание сертификата успешно завершено")
            key_path = self.private_dir / "ca.key.pem"
            encrypted_key = crypto_utils.encrypt_private_key(
                private_key,
                passphrase,
                key_type
            )
            crypto_utils.save_pem_data(encrypted_key, key_path, "закрытый ключ")
            try:
                key_path.chmod(0o600)
                logger.info(f"Установлены права доступа 0o600 для {key_path}")
            except NotImplementedError:
                crypto_utils.set_file_permissions_warning(key_path)
            cert_path = self.certs_dir / "ca.cert.pem"
            cert_pem = certificates.cert_to_pem(certificate)
            crypto_utils.save_pem_data(cert_pem, cert_path, "сертификат")
            self._generate_policy_file(
                subject_str=subject_str,
                certificate=certificate,
                key_type=key_type,
                key_size=key_size,
                validity_days=validity_days
            )
            logger.info("Корневой УЦ успешно инициализирован")
        except Exception as e:
            logger.error(f"Ошибка при инициализации корневого УЦ: {e}")
            raise

    def _create_directory_structure(self):
        logger.info(f"Создание структуры каталогов в {self.out_dir}")
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.private_dir.chmod(0o700)
        except NotImplementedError:
            logger.warning(f"Установка прав 0o700 для {self.private_dir} не поддерживается на Windows")
        logger.info(f"Директория для ключей: {self.private_dir}")
        logger.info(f"Директория для сертификатов: {self.certs_dir}")

    def _generate_policy_file(self, subject_str, certificate, key_type, key_size, validity_days):
        policy_path = self.out_dir / "policy.txt"
        content = f"""ПОЛИТИКА СЕРТИФИКАЦИИ (CERTIFICATE POLICY)
============================================

Имя УЦ (субъект DN): {subject_str}

Детали сертификата:
------------------
Серийный номер: {hex(certificate.serial_number)}
NotBefore: {certificate.not_valid_before_utc.isoformat()}
NotAfter: {certificate.not_valid_after_utc.isoformat()}
Срок действия: {validity_days} дней

Параметры ключа:
---------------
Тип ключа: {key_type.upper()}
Размер ключа: {key_size} бит

Описание:
--------
Корневой УЦ для демонстрации MicroPKI (MopsikPKI).
Предназначен для образовательных целей и тестирования.

Версия политики: 1.0
Дата создания: {certificate.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
        try:
            policy_path.write_text(content, encoding='utf-8')
            logger.info(f"Сгенерирован файл политики: {policy_path}")
        except IOError as e:
            logger.error(f"Ошибка при сохранении policy.txt: {e}")
            raise

    def issue_intermediate_ca(self, root_cert_path, root_key_path, root_passphrase,
                              subject_str, key_type, key_size, passphrase,
                              validity_days, pathlen=0):
        self._create_directory_structure()

        root_cert = certificates.load_pem_certificate(root_cert_path)
        root_key = crypto_utils.load_private_key(root_key_path, root_passphrase)

        # Генерируем ключ промежуточного УЦ
        if key_type == "rsa":
            private_key = crypto_utils.generate_rsa_key(key_size)
        else:
            private_key = crypto_utils.generate_ecc_key()

        # Сохраняем зашифрованный ключ
        key_path = self.private_dir / "intermediate.key.pem"
        crypto_utils.save_private_key(private_key, key_path, passphrase)

        subject = certificates.parse_subject(subject_str)

        # Строим сертификат
        now = certificates.datetime.datetime.now(certificates.datetime.timezone.utc)
        builder = certificates.x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(root_cert.subject) \
            .public_key(private_key.public_key()) \
            .serial_number(certificates.generate_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + certificates.datetime.timedelta(days=validity_days)) \
            .add_extension(
                certificates.x509.BasicConstraints(ca=True, path_length=pathlen),
                critical=True
            ) \
            .add_extension(
                certificates.x509.KeyUsage(
                    digital_signature=False, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, data_encipherment=False,
                    key_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False
                ),
                critical=True
            ) \
            .add_extension(
                certificates.x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            ) \
            .add_extension(
                certificates.x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
                critical=False
            )

        cert = builder.sign(private_key=root_key, algorithm=certificates.hashes.SHA256())

        cert_path = self.certs_dir / "intermediate.cert.pem"
        certificates.save_cert_pem(cert, cert_path)          # новая функция ниже

        logger.info(f"✅ Промежуточный УЦ создан")
        logger.info(f"   Сертификат: {cert_path}")
        logger.info(f"   Ключ:       {key_path}")

    # === Sprint 2: issue-cert ===
    def issue_end_entity_cert(self, ca_cert_path, ca_key_path, ca_passphrase,
                              template, subject_str, san_list, validity_days):
        self._create_directory_structure()

        ca_cert = certificates.load_pem_certificate(ca_cert_path)
        ca_key = crypto_utils.load_private_key(ca_key_path, ca_passphrase)

        subject = certificates.parse_subject(subject_str)
        public_key = None

        # Генерируем ключ конечного сертификата (без пароля!)
        private_key = crypto_utils.generate_rsa_key(2048)
        key_path = self.certs_dir / f"{subject.get_attributes_for_oid(certificates.NameOID.COMMON_NAME)[0].value.replace(' ', '_')}.key.pem"
        crypto_utils.save_private_key(private_key, key_path, passphrase=None)

        # SAN
        sans = certificates.parse_san_list(san_list)

        # Шаблон
        key_usage, eku = certificates.get_template_extensions(template)

        now = certificates.datetime.datetime.now(certificates.datetime.timezone.utc)
        builder = certificates.x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(ca_cert.subject) \
            .public_key(private_key.public_key()) \
            .serial_number(certificates.generate_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + certificates.datetime.timedelta(days=validity_days)) \
            .add_extension(certificates.x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .add_extension(key_usage, critical=True)

        if eku:
            builder = builder.add_extension(
                certificates.x509.ExtendedKeyUsage(eku), critical=False
            )
        if sans:
            builder = builder.add_extension(
                certificates.x509.SubjectAlternativeName(sans), critical=False
            )

        cert = builder.sign(private_key=ca_key, algorithm=certificates.hashes.SHA256())

        cn = subject.get_attributes_for_oid(certificates.NameOID.COMMON_NAME)[0].value
        cert_path = self.certs_dir / f"{cn.replace(' ', '_').replace('/', '_')}.cert.pem"
        certificates.save_cert_pem(cert, cert_path)

        logger.info(f"✅ Сертификат выдан ({template})")
        logger.info(f"   Сертификат: {cert_path}")
        logger.info(f"   Ключ:       {key_path}")