"""Offline import of a private TVCAS PHP/MariaDB snapshot.

This module never executes PHP, opens a network connection, or starts generators.
Input rows must be exported as JSON objects, not executable SQL. Keep both the
original backup and the resulting database private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Mapping

from .storage import Store, TABLES, hash_password, table_name

# Only literal array elements are accepted. Never evaluate PHP code.
_ENTRY = re.compile(
    r"(?P<key>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")\s*=>\s*"
    r"(?P<value>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|-?\d+|true|false|null)(?=\s*[,\)])",
    re.IGNORECASE,
)
_ARRAY = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*array\s*\(", re.IGNORECASE)


def _unquote_php(token: str) -> str:
    quote = token[0]
    body = token[1:-1]
    if quote == "'":
        return re.sub(r"\\([\\'])", r"\1", body)
    if re.search(r"(?<!\\)(?:\\\\)*\$", body):
        raise ValueError("Interpolated PHP strings are not supported; export settings as JSON")
    escapes = {"n": "\n", "r": "\r", "t": "\t", "v": "\v", "e": "\x1b", "f": "\f", "\\": "\\", '"': '"', "$": "$"}
    def sub(match: re.Match[str]) -> str:
        value = match.group(1)
        if value.startswith("x") and len(value) > 1:
            return chr(int(value[1:], 16))
        if value[0] in "01234567":
            return chr(int(value, 8) & 255)
        return escapes.get(value, "\\" + value)
    return re.sub(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", sub, body)


def _literal(token: str) -> Any:
    if token[0] in "'\"":
        return _unquote_php(token)
    if token.lower() == "true":
        return True
    if token.lower() == "false":
        return False
    if token.lower() == "null":
        return None
    return int(token)


def _array_text(source: str, start: int) -> str:
    """Read one balanced PHP array while ignoring parentheses in strings."""
    depth = 1
    quote = None
    escaped = False
    for pos in range(start, len(source)):
        char = source[pos]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return source[start:pos] + ")"
    raise ValueError("Unterminated PHP settings array")


def parse_php_settings(path: str | Path) -> dict[str, Any]:
    """Read the literal settings array containing ecm_key/pass_admin from config.php.

    Dynamic zone/time expressions are deliberately not evaluated. zone defaults
    to UTC until the server's actual timezone is supplied via import overrides.
    """
    source = Path(path).read_text(encoding="utf-8-sig")
    candidates = []
    for match in _ARRAY.finditer(source):
        body = _array_text(source, match.end())
        entries = {_unquote_php(item.group("key")): _literal(item.group("value"))
                   for item in _ENTRY.finditer(body)}
        if "ecm_key" in entries or "pass_admin" in entries:
            candidates.append(entries)
    if len(candidates) != 1:
        raise ValueError("Expected exactly one literal TVCAS settings array")
    settings = candidates[0]
    for required in ("ecm_key", "pass_admin", "pass_oper"):
        if required not in settings or not isinstance(settings[required], str) or not settings[required]:
            raise ValueError(f"Missing literal {required} in PHP settings")
    key = settings["ecm_key"]
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", key):
        raise ValueError("Legacy global ECM key is not 32 bytes of hexadecimal")
    return settings


def migrate_settings(legacy: Mapping[str, Any], *, timezone: str | None = None,
                     zone: str | None = None) -> dict[str, Any]:
    """Map settings without storing plaintext HTTP Basic login passwords."""
    result = {key: legacy[key] for key in ("ident", "trademark", "api_key", "ecm_key", "zone") if key in legacy}
    for role, old_key in (("admin", "pass_admin"), ("oper", "pass_oper")):
        password = legacy.get(old_key)
        if isinstance(password, str) and password:
            result[f"{role}_password_hash"] = hash_password(password)
        else:
            raise ValueError(f"Missing {role} password; import cannot create an accessible login")
    # Preserve vendor metadata/database connection configuration in the private
    # database, but do not carry legacy plaintext web passwords into the port.
    result["legacy_config"] = {key: value for key, value in legacy.items()
                               if key not in {"pass_admin", "pass_oper", "time_start"}}
    if timezone is not None:
        result["timezone"] = timezone
    if zone is not None:
        if not re.fullmatch(r"[+-](?:0\d|1[0-4])[0-5]\d", zone):
            raise ValueError("zone must be a PHP UTC offset such as +0200")
        result["zone"] = zone
    result["runtime_enabled"] = False
    return result


def _normalize_export(data: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(data, Mapping):
        raise ValueError("Database JSON must be an object keyed by table names")
    # Optionally accept metadata alongside a 'tables' payload.
    tables = data.get("tables", data)
    if not isinstance(tables, Mapping):
        raise ValueError("tables must be an object")
    result = {}
    for name, rows in tables.items():
        table = table_name(name)
        if table in result:
            raise ValueError("Duplicate table alias in import")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError(f"{table} must be a list of row objects")
        result[table] = rows
    if set(result) != set(TABLES):
        raise ValueError("Import requires all five TVCAS tables, including empty tables")
    return result


def import_legacy_json(store: Store, data: Mapping[str, Any], config_path: str | Path | None = None,
                       *, replace: bool = False, legacy_settings: Mapping[str, Any] | None = None,
                       timezone: str | None = None, zone: str | None = None) -> dict[str, Any]:
    """Atomically import exact legacy rows and settings, leaving runtime disabled.

    A nonempty destination is rejected unless replace=True. Duplicate IDs or card
    serials reject the entire import. Original generator enable flags are kept;
    the separate global runtime_enabled switch is forced False.
    """
    tables = _normalize_export(data)
    if config_path is not None and legacy_settings is not None:
        raise ValueError("Use either config_path or legacy_settings")
    if config_path is not None:
        legacy_settings = parse_php_settings(config_path)
    settings = migrate_settings(legacy_settings, timezone=timezone, zone=zone) if legacy_settings is not None else {"runtime_enabled": False}
    counts = {name: len(rows) for name, rows in tables.items()}
    for name, rows in tables.items():
        ids = [int(row["id"]) for row in rows if "id" in row]
        if len(ids) != len(rows) or len(ids) != len(set(ids)):
            raise ValueError(f"{name} contains missing or duplicate IDs")
    # Content hash goes into private metadata only, never printed with source rows.
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    report = dict(imported_at=int(time.time()), counts=counts,
                  source_sha256=hashlib.sha256(canonical).hexdigest(), runtime_enabled=False)
    settings["migration"] = report
    with store.transaction() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if existing and not replace:
            raise ValueError("Destination contains records; use a fresh database or explicitly replace")
        if replace:
            conn.execute("DELETE FROM records")
        for table, rows in tables.items():
            for row in rows:
                store._save(conn, table, row, importing=True)
        store._set_settings(conn, settings)
        conn.execute("INSERT INTO audit_log(time,actor,action,details) VALUES (?,?,?,?)",
                     (int(time.time()), "migration", "legacy_import", json.dumps({"counts": counts})))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import private TVCAS backup; generators remain disabled")
    parser.add_argument("--database", required=True, help="Private destination SQLite file")
    parser.add_argument("--rows", required=True, help="Private JSON export of all five tables")
    parser.add_argument("--php-config", required=True, help="Private installed includes/config.php")
    parser.add_argument("--timezone", default="UTC", help="Source server IANA timezone")
    parser.add_argument("--zone", default="+0000", help="Source PHP offset (e.g. +0200)")
    parser.add_argument("--replace", action="store_true", help="Replace all imported records atomically")
    args = parser.parse_args(argv)
    data = json.loads(Path(args.rows).read_text(encoding="utf-8"))
    result = import_legacy_json(Store(args.database), data, args.php_config,
                                replace=args.replace, timezone=args.timezone, zone=args.zone)
    print(json.dumps({"counts": result["counts"], "runtime_enabled": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
