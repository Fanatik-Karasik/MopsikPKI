import argparse
import sys
from pathlib import Path

from .ca import CertificateAuthority
from .crypto_utils import load_passphrase
from .database import PKIDatabase
from .repository import run_server
from .logger import setup_logger


def main():
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MopsikPKI — простая инфраструктура открытых ключей (Sprint 3)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="Операции с УЦ")
    ca_sub = ca_parser.add_subparsers(dest="ca_subcommand", required=True)

    init_p = ca_sub.add_parser("init", help="Создать корневой УЦ")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=4096)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)

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

    cert_p = ca_sub.add_parser("issue-cert", help="Выпустить конечный сертификат")
    cert_p.add_argument("--ca-cert", required=True)
    cert_p.add_argument("--ca-key", required=True)
    cert_p.add_argument("--ca-pass-file", required=True)
    cert_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    cert_p.add_argument("--subject", required=True)
    cert_p.add_argument("--san", action="append", default=[])
    cert_p.add_argument("--out-dir", default="./pki/certs")
    cert_p.add_argument("--validity-days", type=int, default=365)

    list_p = ca_sub.add_parser("list-certs", help="Список сертификатов из БД")
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)

    show_p = ca_sub.add_parser("show-cert", help="Показать сертификат по serial")
    show_p.add_argument("serial", help="Серийный номер в hex")

    db_parser = subparsers.add_parser("db", help="Работа с базой данных")
    db_sub = db_parser.add_subparsers(dest="db_command", required=True)
    db_init = db_sub.add_parser("init", help="Инициализировать БД")
    db_init.add_argument("--db-path", default="pki/micropki.db")

    repo_parser = subparsers.add_parser("repo", help="HTTP-репозиторий сертификатов")
    repo_sub = repo_parser.add_subparsers(dest="repo_command", required=True)
    serve_p = repo_sub.add_parser("serve", help="Запустить HTTP-сервер")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    try:
        if args.command == "db":
            if args.db_command == "init":
                PKIDatabase(args.db_path)
                print(f" База данных успешно инициализирована: {args.db_path}")

        elif args.command == "ca":
            ca = CertificateAuthority(out_dir=getattr(args, 'out_dir', "./pki"))
            db = PKIDatabase()

            if args.ca_subcommand == "init":
                passphrase = load_passphrase(Path(args.passphrase_file))
                ca.init_root_ca(
                    subject_str=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=passphrase,
                    validity_days=args.validity_days,
                )

            elif args.ca_subcommand == "issue-intermediate":
                root_pass = load_passphrase(Path(args.root_pass_file))
                new_pass = load_passphrase(Path(args.passphrase_file))
                ca.issue_intermediate_ca(
                    root_cert_path=args.root_cert,
                    root_key_path=args.root_key,
                    root_passphrase=root_pass,
                    subject_str=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=new_pass,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen,
                )

            elif args.ca_subcommand == "issue-cert":
                ca_pass = load_passphrase(Path(args.ca_pass_file))
                ca.issue_end_entity_cert(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_passphrase=ca_pass,
                    template=args.template,
                    subject_str=args.subject,
                    san_list=args.san,
                    validity_days=args.validity_days,
                    db=db
                )

            elif args.ca_subcommand == "list-certs":
                rows = db.list_certs(args.status)
                for row in rows:
                    print(dict(row))

            elif args.ca_subcommand == "show-cert":
                cert = db.get_cert_by_serial(args.serial)
                if cert:
                    print(cert["cert_pem"])
                else:
                    print(f"Сертификат с serial {args.serial} не найден")

            db.close()

        elif args.command == "repo":
            if args.repo_command == "serve":
                run_server(host=args.host, port=args.port)

    except Exception as e:
        print(f" Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()