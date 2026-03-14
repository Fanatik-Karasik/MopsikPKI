import argparse
import sys
from pathlib import Path
import logging
from .ca import CertificateAuthority
from .crypto_utils import load_passphrase

logger = logging.getLogger(__name__)

def validate_init_args(args):
    if not args.subject or not args.subject.strip():
        raise ValueError("Параметр --subject обязателен")
    if args.key_type not in ['rsa', 'ecc']:
        raise ValueError("--key-type должен быть 'rsa' или 'ecc'")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("Для RSA --key-size должен быть 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("Для ECC --key-size должен быть 384")
    if not Path(args.passphrase_file).is_file():
        raise ValueError(f"Файл с паролем не найден: {args.passphrase_file}")
    if args.validity_days <= 0:
        raise ValueError("--validity-days должен быть > 0")

def main():
    parser = argparse.ArgumentParser(
        description="MopsikPKI - простая инфраструктура открытых ключей"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="Операции с УЦ")
    ca_sub = ca_parser.add_subparsers(dest="ca_command", required=True)

    init_p = ca_sub.add_parser("init", help="Создать корневой УЦ")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=4096)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file", default=None)

    int_p = ca_sub.add_parser("issue-intermediate", help="Выпустить промежуточный УЦ")
    int_p.add_argument("--root-cert", required=True)
    int_p.add_argument("--root-key", required=True)
    int_p.add_argument("--root-pass-file", required=True)
    int_p.add_argument("--subject", required=True)
    int_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    int_p.add_argument("--key-size", type=int, default=4096)
    int_p.add_argument("--passphrase-file", required=True)
    int_p.add_argument("--out-dir", default="./pki")
    int_p.add_argument("--validity-days", type=int, default=1825)
    int_p.add_argument("--pathlen", type=int, default=0)
    int_p.add_argument("--log-file", default=None)

    cert_p = ca_sub.add_parser("issue-cert", help="Выпустить конечный сертификат")
    cert_p.add_argument("--ca-cert", required=True)
    cert_p.add_argument("--ca-key", required=True)
    cert_p.add_argument("--ca-pass-file", required=True)
    cert_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    cert_p.add_argument("--subject", required=True)
    cert_p.add_argument("--san", action="append", default=[])
    cert_p.add_argument("--out-dir", default="./pki/certs")
    cert_p.add_argument("--validity-days", type=int, default=365)
    cert_p.add_argument("--log-file", default=None)

    args = parser.parse_args()

    try:
        if args.command == "ca":
            ca = CertificateAuthority(out_dir=Path(args.out_dir), log_file=args.log_file)

            if args.ca_command == "init":
                validate_init_args(args)
                passphrase = load_passphrase(Path(args.passphrase_file))
                ca.init_root_ca(
                    subject_str=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=passphrase,
                    validity_days=args.validity_days
                )

            elif args.ca_command == "issue-intermediate":
                root_pass = load_passphrase(Path(args.root_pass_file))
                new_pass = load_passphrase(Path(args.passphrase_file))
                ca.issue_intermediate_ca(
                    root_cert_path=Path(args.root_cert),
                    root_key_path=Path(args.root_key),
                    root_passphrase=root_pass,
                    subject_str=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=new_pass,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen
                )

            elif args.ca_command == "issue-cert":
                ca_pass = load_passphrase(Path(args.ca_pass_file))
                ca.issue_end_entity_cert(
                    ca_cert_path=Path(args.ca_cert),
                    ca_key_path=Path(args.ca_key),
                    ca_passphrase=ca_pass,
                    template=args.template,
                    subject_str=args.subject,
                    san_list=args.san,
                    validity_days=args.validity_days
                )

        logger.info("Команда выполнена успешно")
        sys.exit(0)

    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        logger.error(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()