import argparse
import sys
from pathlib import Path

from .ca import CertificateAuthority
from .crypto_utils import load_passphrase
from .logger import setup_logger


def main():
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="Простая PKI для обучения криптографии (MopsikPKI)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── ca ───────────────────────────────────────────────────────
    ca_parser = subparsers.add_parser("ca", help="Операции с удостоверяющим центром")
    ca_sub = ca_parser.add_subparsers(dest="subcommand", required=True)

    # ca init (Sprint 1)
    init_parser = ca_sub.add_parser("init", help="Создать корневой УЦ")
    init_parser.add_argument("--subject", required=True)
    init_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_parser.add_argument("--key-size", type=int, default=4096)
    init_parser.add_argument("--passphrase-file", required=True)
    init_parser.add_argument("--out-dir", default="./pki")
    init_parser.add_argument("--validity-days", type=int, default=3650)
    init_parser.add_argument("--log-file", default=None)

    # ca issue-intermediate (Sprint 2)
    int_parser = ca_sub.add_parser("issue-intermediate", help="Выпустить промежуточный УЦ")
    int_parser.add_argument("--root-cert", required=True)
    int_parser.add_argument("--root-key", required=True)
    int_parser.add_argument("--root-pass-file", required=True)
    int_parser.add_argument("--subject", required=True)
    int_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    int_parser.add_argument("--key-size", type=int, default=4096)
    int_parser.add_argument("--passphrase-file", required=True)
    int_parser.add_argument("--out-dir", default="./pki")
    int_parser.add_argument("--validity-days", type=int, default=1825)
    int_parser.add_argument("--pathlen", type=int, default=0)
    int_parser.add_argument("--log-file", default=None)

    # ca issue-cert (Sprint 2)
    cert_parser = ca_sub.add_parser("issue-cert", help="Выпустить конечный сертификат")
    cert_parser.add_argument("--ca-cert", required=True)
    cert_parser.add_argument("--ca-key", required=True)
    cert_parser.add_argument("--ca-pass-file", required=True)
    cert_parser.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    cert_parser.add_argument("--subject", required=True)
    cert_parser.add_argument("--san", action="append", default=[])
    cert_parser.add_argument("--out-dir", default="./pki/certs")
    cert_parser.add_argument("--validity-days", type=int, default=365)
    cert_parser.add_argument("--log-file", default=None)

    args = parser.parse_args()

    ca = CertificateAuthority(out_dir=args.out_dir, log_file=args.log_file)

    try:
        if args.command == "ca":
            if args.subcommand == "init":
                passphrase = load_passphrase(Path(args.passphrase_file))
                ca.init_root_ca(
                    subject_str=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=passphrase,
                    validity_days=args.validity_days,
                )

            elif args.subcommand == "issue-intermediate":
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

            elif args.subcommand == "issue-cert":
                ca_pass = load_passphrase(Path(args.ca_pass_file))
                ca.issue_end_entity_cert(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_passphrase=ca_pass,
                    template=args.template,
                    subject_str=args.subject,
                    san_list=args.san,
                    validity_days=args.validity_days,
                )

        sys.exit(0)

    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()