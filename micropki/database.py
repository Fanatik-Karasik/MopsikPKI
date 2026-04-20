from pathlib import Path
import sqlite3
import datetime
from .logger import setup_logger

logger = setup_logger()

class PKIDatabase:
    def __init__(self, db_path: str | Path = "pki/micropki.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'valid',
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
        self.conn.commit()
        logger.info(f"База данных инициализирована: {self.db_path}")

    def insert_certificate(self, cert, cert_pem: str, issuer_dn: str):
        serial_hex = format(cert.serial_number, 'X')
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        self.conn.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'valid', ?)
        """, (serial_hex, subject, issuer_dn, not_before, not_after, cert_pem, created_at))
        self.conn.commit()
        logger.info(f"Сертификат сохранён в БД. Serial: {serial_hex}")

    def get_cert_by_serial(self, serial_hex: str):
        row = self.conn.execute(
            "SELECT * FROM certificates WHERE serial_hex = ?", 
            (serial_hex.upper(),)
        ).fetchone()
        return dict(row) if row else None

    def list_certs(self, status: str = None):
        query = "SELECT serial_hex, subject, not_after, status FROM certificates"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        return self.conn.execute(query, params).fetchall()

    def close(self):
        self.conn.close()