from pathlib import Path
import sqlite3
import datetime
import threading
from .logger import setup_logger

logger = setup_logger()

class PKIDatabase:
    _local = threading.local()

    def __init__(self, db_path: str | Path = "pki/micropki.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._get_conn()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._create_tables()
        return self._local.conn

    def _create_tables(self):
        conn = self._get_conn()
        conn.execute("""
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
        conn.commit()

    def insert_certificate(self, cert, cert_pem: str, issuer_dn: str):
        conn = self._get_conn()
        serial_hex = format(cert.serial_number, 'X')
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn.execute("""
            INSERT OR REPLACE INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'valid', ?)
        """, (serial_hex, subject, issuer_dn, not_before, not_after, cert_pem, created_at))
        conn.commit()

    def get_cert_by_serial(self, serial_hex: str):
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM certificates WHERE serial_hex = ?", 
            (serial_hex.upper(),)
        ).fetchone()
        return dict(row) if row else None

    def list_certs(self, status: str = None):
        conn = self._get_conn()
        query = "SELECT serial_hex, subject, not_after, status FROM certificates"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        return conn.execute(query, params).fetchall()

    def revoke_cert(self, serial_hex: str, reason: str):
        conn = self._get_conn()
        revocation_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn.execute("""
            UPDATE certificates 
            SET status = 'revoked', 
                revocation_reason = ?, 
                revocation_date = ?
            WHERE serial_hex = ?
        """, (reason, revocation_date, serial_hex.upper()))
        conn.commit()

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()