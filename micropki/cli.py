import argparse
import sys
from pathlib import Path
import os
import logging
from .ca import CertificateAuthority
from .crypto_utils import load_passphrase

logger = logging.getLogger(__name__)

def validate_args(args):
    if not args.subject or not args.subject.strip():
        raise ValueError("Параметр --subject обязателен и не может быть пустым")
    if args.key_type not in ['rsa', 'ecc']:
        raise ValueError("--key-type должен быть 'rsa' или 'ecc'")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("Для RSA ключа --key-size должен быть 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("Для ECC ключа --key-size должен быть 384")
    passphrase_file = Path(args.passphrase_file)
    if not passphrase_file.exists():
        raise ValueError(f"Файл с парольной фразой не существует: {passphrase_file}")
    if not passphrase_file.is_file():
        raise ValueError(f"Указанный путь не является файлом: {passphrase_file}")
    out_dir = Path(args.out_dir)
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"Путь существует, но не является директорией: {out_dir}")
    if args.validity_days <= 0:
        raise ValueError("--validity-days должен быть положительным числом")
    if out_dir.exists():
        if not os.access(out_dir, os.W_OK):
            raise ValueError(f"Нет прав на запись в директорию: {out_dir}")
    else:
        parent = out_dir.parent
        if parent.exists() and not os.access(parent, os.W_OK):
            raise ValueError(f"Нет прав на создание директории в: {parent}")

def main():
    parser = argparse.ArgumentParser(
        description="MopsikPKI - инструмент для создания инфраструктуры открытых ключей"
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды", required=True)
    ca_parser = subparsers.add_parser("ca", help="Операции с Удостоверяющим Центром")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command", help="Команды CA", required=True)
    init_parser = ca_subparsers.add_parser("init", help="Инициализировать корневой УЦ")
    init_parser.add_argument("--subject", required=True, help="Отличительное имя (DN)")
    init_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="Тип ключа")
    init_parser.add_argument("--key-size", type=int, default=4096, help="Размер ключа в битах")
    init_parser.add_argument("--passphrase-file", required=True, help="Путь к файлу с парольной фразой")
    init_parser.add_argument("--out-dir", default="./pki", help="Выходной каталог")
    init_parser.add_argument("--validity-days", type=int, default=3650, help="Срок действия в днях")
    init_parser.add_argument("--log-file", help="Путь к файлу журнала")
    args = parser.parse_args()
    try:
        validate_args(args)
        passphrase = load_passphrase(Path(args.passphrase_file))
        ca = CertificateAuthority(out_dir=Path(args.out_dir), log_file=args.log_file)
        ca.init_root_ca(
            subject_str=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            validity_days=args.validity_days
        )
        logger.info("Команда успешно выполнена")
        sys.exit(0)
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        logger.error(f"Ошибка выполнения команды: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()