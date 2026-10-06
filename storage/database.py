import sqlite3
from pathlib import Path
from utils.config import DB_PATH

_conn = None

def _connect():
    """Return a per-process connection, opened once and reused.

    The previous version opened and closed the database file on every packet,
    which capped throughput at roughly 1.6k packets/sec. Because saving happens
    synchronously inside the capture callback, that ceiling caused dropped
    packets on a busy interface.

    WAL mode lets the dashboard read while the capture process is writing,
    instead of the two blocking each other.
    """
    global _conn
    if _conn is None:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn

def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                length INTEGER,
                tcp_flags TEXT,
                ttl INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                type TEXT,
                reason TEXT,
                observed_value REAL,
                threshold REAL,
                severity TEXT
            )
        """)

def save_packet(p):
    with _connect() as conn:
        conn.execute(
            """INSERT INTO packets
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags, ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                p.get("timestamp"), p.get("src_ip"), p.get("dst_ip"),
                p.get("protocol"), p.get("src_port"), p.get("dst_port"),
                p.get("length"), p.get("tcp_flags"), p.get("ttl")
            )
        )

def save_alert(a):
    with _connect() as conn:
        conn.execute(
            """INSERT INTO alerts
            (timestamp, source_ip, destination_ip, type, reason, observed_value, threshold, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                a.get("timestamp"), a.get("source_ip"), a.get("destination_ip"),
                a.get("type"), a.get("reason"), a.get("observed_value"),
                a.get("threshold"), a.get("severity")
            )
        )

def fetch_packets(limit=200):
    with _connect() as conn:
        cur = conn.execute(
            "SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags, ttl FROM packets ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def fetch_alerts(limit=200):
    with _connect() as conn:
        cur = conn.execute(
            "SELECT timestamp, source_ip, destination_ip, type, reason, observed_value, threshold, severity FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
