"""Private, transactional storage for the Python TVCAS service.

Legacy rows are retained as JSON so a migration does not discard vendor or local
columns. Table/column names never become SQL text. This database contains card
and ECM keys: keep it outside source control and back it up as a secret.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Iterator, Mapping

TABLES = (
    "tvcas_ecmg", "tvcas_emmg", "tvcas_smartcards", "tvcas_logs", "tvcas_ecmg_log"
)
_ALIASES = {name.removeprefix("tvcas_"): name for name in TABLES}
_ALIASES.update({"cards": "tvcas_smartcards"})

DEFAULTS: dict[str, dict[str, Any]] = {
    "tvcas_ecmg": dict(info=None, network_id=1, host=0, port=0, packet_mode=0,
        key=None, timeout=60, ac_delay_start=0, ac_delay_stop=0, delay_start=5000,
        delay_stop=5000, transition_delay_start=5000, transition_delay_stop=5000,
        repetition_period=200, min_cp_duration=100, max_compute_time=8000,
        ecm_time1=60, ecm_time2=60, ecm_block_time=0, status=1, reload=0,
        version=9, touch_version=9, touch_time=0, peers=None, c_time=1499385600,
        m_time=1499385600, enable=0, csa_entropy_reduction=False),
    "tvcas_emmg": dict(info=None, network_id=1, host="", port=0,
        protocol_version=2, packet_mode=0, bandwidth=64, repetition=60,
        period=30, period_messages=1, channel_test_delay=60, stream_test_delay=60,
        timeout=0, client_id=184549377, status=1, reload=0, version=8,
        touch_version=8, touch_time=0, channel_time_open=0, stream_time_open=0,
        error_time_last=0, error_count=0, datagram_time_last=0, datagram_count=0,
        queue_size=0, c_id=0, c_time=0, c_ip=0, m_id=0, m_time=0, m_ip=0,
        d_id=0, d_time=0, d_ip=0, reload_time=None, reload_sec=300, enable=0, uid=15),
    "tvcas_smartcards": dict(serial_no=0, name="", info=None, network_id=1,
        key="", access_criteria="00000000", status=1, cn=None, type=1, pair=0,
        start=None, finish=None, c_time=None, edit=None, uid=15,
        subscription_slot1=0, subscription_slot2=0),
    "tvcas_logs": dict(msg="", type=0, user="", time=0, ip=""),
    "tvcas_ecmg_log": dict(access_criteria="00000000", cw1="", cw2="", sock=0,
        ecmg_id=0, time=0),
}

DEFAULT_SETTINGS = {
    "runtime_enabled": False,
    "ident": "0B00",
    "trademark": "TVCAS Python",
    "zone": "+0000",
    "timezone": "UTC",
    "admin_password_hash": "",
    "oper_password_hash": "",
    "api_key": "",
    "ecm_key": "",
}

_SMALL_SIGNED = {"ac_delay_start", "ac_delay_stop", "delay_start", "delay_stop",
                 "transition_delay_start", "transition_delay_stop"}
_SMALL_UNSIGNED = {"port", "timeout", "repetition_period", "min_cp_duration",
                   "max_compute_time", "ecm_time1", "ecm_time2", "ecm_block_time",
                   "bandwidth", "repetition", "channel_test_delay", "stream_test_delay",
                   "reload_sec"}
_TINY_UNSIGNED = {"protocol_version", "packet_mode", "period", "period_messages",
                  "status", "reload"}
_SIGNED_INTS = {"uid", "type", "pair", "subscription_slot1", "subscription_slot2"}
_NULLABLE_INTS = {"start", "finish", "c_time", "edit", "reload_time"}
_TEXT_LENGTHS = {"name": 255, "cn": 255}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def table_name(table: str) -> str:
    resolved = _ALIASES.get(table, table)
    if resolved not in TABLES:
        raise ValueError("Unknown TVCAS table")
    return resolved


def hash_password(password: str, *, iterations: int = 600_000) -> str:
    """Generate a Werkzeug-compatible PBKDF2 hash without a web dependency."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2:sha256:{iterations}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, salt, expected = encoded.split("$", 2)
        algorithm, digest, iterations = method.split(":", 2)
        if algorithm != "pbkdf2" or digest != "sha256":
            return False
        rounds = int(iterations)
        if not 100_000 <= rounds <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac(digest, password.encode(), salt.encode(), rounds).hex()
        return hmac.compare_digest(actual, expected)
    except (AttributeError, ValueError, TypeError):
        return False


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int | None:
    if value is None and field in _NULLABLE_INTS:
        return None
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
        value = int(value)
    if not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer in {minimum}..{maximum}")
    return value


def validate_row(table: str, values: Mapping[str, Any], *, importing: bool = False) -> dict[str, Any]:
    """Validate known fields, preserving unknown vendor columns and original hex case.

    The importer tolerates legacy nullable fields and blank keys, while runtime
    startup must enforce complete keys and usable addresses. Import never changes
    timestamps, IDs, flags, or saved enable values.
    """
    table = table_name(table)
    if not isinstance(values, Mapping):
        raise ValueError("Row must be an object")
    row = dict(values)
    for field, value in list(row.items()):
        if not isinstance(field, str):
            raise ValueError("Column names must be strings")
        if field == "id":
            row[field] = _integer(value, field, 1, 0xFFFFFFFF)
            continue
        if field not in DEFAULTS[table]:
            continue
        if value is None and importing:
            continue  # The original MariaDB columns are mostly nullable.
        default = DEFAULTS[table][field]
        is_int = isinstance(default, int) or field in _NULLABLE_INTS
        if is_int:
            if field == "csa_entropy_reduction":
                limits = (0, 1)
            elif field in _SMALL_SIGNED:
                limits = (-32768, 32767)
            elif field in _SMALL_UNSIGNED:
                limits = (0, 65535)
            elif field in _TINY_UNSIGNED:
                limits = (0, 255)
            elif field in _SIGNED_INTS:
                limits = (-2147483648, 2147483647)
            elif table == "tvcas_logs" and field in {"time", "type"}:
                limits = (-2147483648, 2147483647)
            else:
                limits = (0, 0xFFFFFFFF)
            row[field] = _integer(value, field, *limits)
        elif value is not None and not isinstance(value, str):
            raise ValueError(f"{field} must be text")
        if field in _TEXT_LENGTHS and value is not None and len(value) > _TEXT_LENGTHS[field]:
            raise ValueError(f"{field} exceeds {_TEXT_LENGTHS[field]} characters")
        if field == "host" and table == "tvcas_emmg" and value is not None and len(value) > 255:
            raise ValueError("host exceeds 255 characters")
        size = None
        if field == "key":
            size = 64 if table == "tvcas_ecmg" else 32
        elif field == "access_criteria":
            size = 8
        elif field in {"cw1", "cw2"}:
            size = 16
        if size and value not in (None, ""):
            if not isinstance(value, str) or len(value) != size or not _HEX.fullmatch(value):
                raise ValueError(f"{field} must contain exactly {size} hexadecimal characters")
    try:
        json.dumps(row, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Row must contain JSON values") from exc
    return row


class Store:
    """One SQLite connection per operation; transactions serialize concurrent writers."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = str(Path(path).resolve())
        if str(path) == ":memory:":
            raise ValueError("Use a private file; per-operation connections cannot use :memory:")
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    table_name TEXT NOT NULL,
                    row_id INTEGER NOT NULL,
                    serial_no INTEGER,
                    data TEXT NOT NULL,
                    PRIMARY KEY (table_name, row_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS smartcard_serial
                    ON records(table_name, serial_no) WHERE serial_no IS NOT NULL;
                CREATE TABLE IF NOT EXISTS settings (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL
                );
            """)
            for name, value in DEFAULT_SETTINGS.items():
                conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (name, json.dumps(value)))

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_rows(self, table: str) -> list[dict[str, Any]]:
        table = table_name(table)
        with closing(self._connect()) as conn:
            result = conn.execute("SELECT data FROM records WHERE table_name=? ORDER BY row_id", (table,))
            return [json.loads(item[0]) for item in result]

    def get_row(self, table: str, id: int) -> dict[str, Any] | None:
        table = table_name(table)
        with closing(self._connect()) as conn:
            result = conn.execute("SELECT data FROM records WHERE table_name=? AND row_id=?", (table, int(id))).fetchone()
            return json.loads(result[0]) if result else None

    def _save(self, conn: sqlite3.Connection, table: str, data: Mapping[str, Any],
              id: int | None = None, *, importing: bool = False) -> dict[str, Any]:
        table = table_name(table)
        if not isinstance(data, Mapping):
            raise ValueError("Row must be an object")
        if id is None and "id" in data:
            id = data["id"]
        if id is not None:
            id = _integer(id, "id", 1, 0xFFFFFFFF)
        old = None
        if id is not None:
            old_result = conn.execute("SELECT data FROM records WHERE table_name=? AND row_id=?", (table, id)).fetchone()
            old = json.loads(old_result[0]) if old_result else None
        row = dict(DEFAULTS[table])
        if old:
            row.update(old)
        row.update(data)
        if id is None:
            id = conn.execute("SELECT COALESCE(MAX(row_id),0)+1 FROM records WHERE table_name=?", (table,)).fetchone()[0]
        row["id"] = id
        if not importing:
            now = int(time.time())
            if old is None and "c_time" in row and "c_time" not in data:
                row["c_time"] = now
            stamp = "edit" if table == "tvcas_smartcards" else "m_time"
            if stamp in row and stamp not in data:
                row[stamp] = now
        row = validate_row(table, row, importing=importing)
        serial = row.get("serial_no") if table == "tvcas_smartcards" else None
        try:
            conn.execute("""INSERT INTO records(table_name,row_id,serial_no,data) VALUES (?,?,?,?)
                ON CONFLICT(table_name,row_id) DO UPDATE SET serial_no=excluded.serial_no,data=excluded.data""",
                (table, id, serial, json.dumps(row, ensure_ascii=False, sort_keys=True, allow_nan=False)))
        except sqlite3.IntegrityError as exc:
            raise ValueError("A card with this serial number already exists") from exc
        return row

    def save_row(self, table: str, data: Mapping[str, Any], id: int | None = None) -> dict[str, Any]:
        with self.transaction() as conn:
            return self._save(conn, table, data, id)

    def save_rows(self, table: str, rows: list[tuple[Mapping[str, Any], int | None]]) -> list[dict[str, Any]]:
        """Atomic validated batch, for CSV imports and other multi-row operations."""
        with self.transaction() as conn:
            return [self._save(conn, table, data, id) for data, id in rows]

    def delete_row(self, table: str, id: int) -> bool:
        table = table_name(table)
        with self.transaction() as conn:
            result = conn.execute("DELETE FROM records WHERE table_name=? AND row_id=?", (table, int(id)))
            return bool(result.rowcount)

    def get_settings(self) -> dict[str, Any]:
        with closing(self._connect()) as conn:
            return {name: json.loads(value) for name, value in conn.execute("SELECT name,value FROM settings")}

    def _set_settings(self, conn: sqlite3.Connection, values: Mapping[str, Any]) -> None:
        if not isinstance(values, Mapping) or not all(isinstance(name, str) for name in values):
            raise ValueError("Settings must be an object with string keys")
        if "runtime_enabled" in values and not isinstance(values["runtime_enabled"], bool):
            raise ValueError("runtime_enabled must be a boolean")
        for name, value in values.items():
            conn.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                         (name, json.dumps(value, ensure_ascii=False, allow_nan=False)))

    def set_settings(self, values: Mapping[str, Any]) -> dict[str, Any]:
        with self.transaction() as conn:
            self._set_settings(conn, values)
        return self.get_settings()

    def audit(self, actor: str, action: str, details: Any = None) -> None:
        """Record non-secret metadata. Never pass card keys, CWs, passwords or CSV rows."""
        with self.transaction() as conn:
            conn.execute("INSERT INTO audit_log(time,actor,action,details) VALUES (?,?,?,?)",
                         (int(time.time()), str(actor), str(action), json.dumps(details, ensure_ascii=False)))

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT id,time,actor,action,details FROM audit_log ORDER BY id DESC LIMIT ?",
                                (max(1, min(int(limit), 1000)),))
            return [dict(id=r[0], time=r[1], actor=r[2], action=r[3], details=json.loads(r[4])) for r in rows]

    def export_rows(self) -> dict[str, list[dict[str, Any]]]:
        """Consistent private snapshot; callers must never expose it publicly."""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN")
            result = {table: [] for table in TABLES}
            for table, data in conn.execute("SELECT table_name,data FROM records ORDER BY table_name,row_id"):
                result[table].append(json.loads(data))
            conn.commit()
            return result
