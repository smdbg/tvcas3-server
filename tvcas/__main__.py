"""CLI for offline validation and a single supervised TVCAS web process."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import sys
from urllib.parse import quote

from . import __version__
from .storage import Store, TABLES, hash_password, validate_row


class CLIError(Exception):
    """An actionable message containing no configuration secrets."""


def existing_database(path: str | Path) -> Path:
    target = Path(path).resolve()
    if not target.is_file():
        raise CLIError("Database does not exist; import a private backup or use init for a new system")
    return target


@contextmanager
def database_lock(path: str | Path):
    """One serving process per canonical database path, including across containers.

    The lock file remains in place after unlock; unlinking it would introduce an
    inode race and allow a second process to acquire a different lock.
    """
    path = Path(path).resolve()
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path) + ".serve.lock", flags, 0o600)
    locked = False
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            raise CLIError("Another TVCAS serving process already holds this database") from None
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        yield
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_private_snapshot(path: str | Path):
    """Read-only SQLite access: check never initializes schema or changes settings."""
    path = existing_database(path)
    conn = sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=ro", uri=True)
    try:
        conn.execute("BEGIN")
        rows = {name: [] for name in TABLES}
        for table, raw in conn.execute("SELECT table_name,data FROM records ORDER BY table_name,row_id"):
            if table not in rows:
                raise CLIError("Database contains an unsupported table")
            rows[table].append(json.loads(raw))
        settings = {name: json.loads(raw) for name, raw in conn.execute("SELECT name,value FROM settings")}
        return rows, settings
    finally:
        conn.close()


def _hex_ok(value, size):
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-fA-F]{{{size}}}", value) is not None


def check_database(path: str | Path) -> dict:
    """Validate the supported profile without sockets or generating entitlements."""
    from .crypto import conax_date_at
    from .ecmg import ECMGServer
    from .emmg import EMMGClient
    from .runtime import zone_minutes

    rows, settings = _read_private_snapshot(path)
    errors = []
    warnings = []
    def error(location, field):
        errors.append({"location": location, "field": field})
    if not _hex_ok(settings.get("ecm_key"), 64):
        error("settings", "ecm_key must be 32 bytes of hexadecimal")
    if not _hex_ok(settings.get("ident"), 4):
        error("settings", "ident must be 2 bytes of hexadecimal")
    for role in ("admin", "oper"):
        hashed = settings.get(role + "_password_hash", "")
        match = re.fullmatch(r"pbkdf2:sha256:([0-9]+)\$[^$]+\$[0-9a-f]{64}", hashed) if isinstance(hashed, str) else None
        if not match or not 100_000 <= int(match.group(1)) <= 2_000_000:
            error("settings", role + " password hash is missing or unsupported")
    try:
        offset = zone_minutes(settings.get("zone", "+0000"))
    except (ValueError, TypeError):
        offset = 0
        error("settings", "zone is not a valid fixed UTC offset")
    if not isinstance(settings.get("runtime_enabled"), bool):
        error("settings", "runtime_enabled must be a boolean")
    seen_serials = set()
    ecm_ports = set()
    for table, records in rows.items():
        for row in records:
            location = f"{table}:{row.get('id', '?')}"
            try:
                validate_row(table, row, importing=True)
            except (ValueError, TypeError):
                error(location, "stored field type or range is invalid")
                continue
            if table == "tvcas_smartcards":
                serial = row.get("serial_no")
                if serial in seen_serials:
                    error(location, "duplicate serial number")
                seen_serials.add(serial)
                if not _hex_ok(row.get("key"), 32):
                    error(location, "key must be 16 bytes of hexadecimal")
                if not _hex_ok(row.get("access_criteria"), 8):
                    error(location, "access_criteria must be 4 bytes of hexadecimal")
                start, finish = row.get("start"), row.get("finish")
                try:
                    if not isinstance(start, int) or not isinstance(finish, int) or finish < start:
                        raise ValueError()
                    conax_date_at(start, offset)
                    conax_date_at(finish, offset)
                except (ValueError, OverflowError, OSError):
                    error(location, "validity dates must be ordered and representable in the card format (1990–2069)")
                if row.get("type") not in (1, 2) or row.get("pair") not in (0, 1):
                    error(location, "unsupported type or pair flag")
            elif table in ("tvcas_ecmg", "tvcas_emmg"):
                kind = table.removeprefix("tvcas_")
                try:
                    if not 1 <= int(row.get("port") or 0) <= 65535:
                        raise ValueError()
                    if kind == "ecmg":
                        bind = str(ipaddress.IPv4Address(int(row.get("host") or 0)))
                        if row.get("cw_order", "legacy") not in ("legacy", "cp"):
                            raise ValueError()
                        ECMGServer(row)
                        if row.get("enable"):
                            address = (bind, row["port"])
                            if address in ecm_ports:
                                error(location, "duplicate enabled ECMG bind address and port")
                            ecm_ports.add(address)
                    else:
                        if not isinstance(row.get("host"), str) or not row["host"].strip():
                            raise ValueError()
                        EMMGClient(row, lambda: [])
                except (ValueError, TypeError, KeyError, OverflowError):
                    error(location, "generator configuration does not match the supported TVCAS3 section profile")
    if not settings.get("api_key"):
        warnings.append("Legacy billing API has no configured key")
    return {"ok": not errors, "profile": "TVCAS3 SimulCrypt section mode / DVB-CSA",
            "counts": {name: len(records) for name, records in rows.items()},
            "runtime_enabled": settings.get("runtime_enabled", False),
            "activation_performed": False, "errors": errors, "warnings": warnings}


def serve(args) -> int:
    from waitress import create_server
    from .runtime import Runtime
    from .web import create_app

    target = existing_database(args.database)
    if not 1 <= args.port <= 65535:
        raise CLIError("Web port must be between 1 and 65535")
    # Acquire before constructing Runtime or binding any socket.
    with database_lock(target):
        store = Store(target)
        runtime = Runtime(store, activation_allowed=args.activate)
        server = None
        old_handlers = {}
        def stop(signum, frame):
            raise KeyboardInterrupt()
        try:
            app = create_app(store, runtime)
            server = create_server(app, host=args.host, port=args.port, threads=4,
                                   clear_untrusted_proxy_headers=True)
            for sig in (signal.SIGINT, signal.SIGTERM):
                old_handlers[sig] = signal.signal(sig, stop)
            runtime.start()
            logging.getLogger(__name__).info("TVCAS web started; generator activation permission: %s", args.activate)
            server.run()
        except KeyboardInterrupt:
            pass
        finally:
            if server is not None:
                server.close()
                server.task_dispatcher.shutdown(timeout=10)
            runtime.close()
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
    return 0


def initialize(args) -> int:
    target = Path(args.database).resolve()
    if target.exists():
        raise CLIError("Refusing to initialize an existing database; its keys will not be regenerated")
    passwords = {}
    for role in ("admin", "oper"):
        first = getpass.getpass(f"New {role} password: ")
        second = getpass.getpass(f"Repeat {role} password: ")
        if not first or first != second:
            raise CLIError("Passwords are empty or do not match; no database was created")
        passwords[role] = hash_password(first)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        raise CLIError("Database was created concurrently; refusing to replace it") from None
    os.close(fd)
    store = Store(target)
    store.set_settings({"admin_password_hash": passwords["admin"],
                        "oper_password_hash": passwords["oper"],
                        "ecm_key": secrets.token_hex(32).upper(),
                        "api_key": secrets.token_hex(32), "runtime_enabled": False})
    print(json.dumps({"initialized": True, "runtime_enabled": False}))
    return 0


def configure_runtime(args) -> int:
    """Persist the standalone activation gate while no server owns the database."""
    target = existing_database(args.database)
    with database_lock(target):
        if args.enable and not check_database(target)["ok"]:
            raise CLIError("Database validation failed; run check before enabling generators")
        store = Store(target)
        store.set_settings({"runtime_enabled": args.enable})
        store.audit("cli", "runtime", {"enabled": args.enable})
    print(json.dumps({"runtime_enabled": args.enable, "activation_performed": False}))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="tvcas", description="TVCAS3 Python administration and generators")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve", help="Serve the web UI; generators are offline unless explicitly activated")
    server.add_argument("--database", required=True)
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8091)
    server.add_argument("--activate", action="store_true", help="Permit generators only when the saved runtime switch is also enabled")
    check = sub.add_parser("check", help="Read-only offline validation; no generator or network connections")
    check.add_argument("--database", required=True)
    init = sub.add_parser("init", help="Initialize a NEW installation; never use this for an existing card system")
    init.add_argument("--database", required=True)
    runtime = sub.add_parser("runtime", help="Set the saved generator gate with the service stopped; opens no sockets")
    runtime.add_argument("--database", required=True)
    state = runtime.add_mutually_exclusive_group(required=True)
    state.add_argument("--enable", action="store_true", help="Permit generators on the next serve --activate")
    state.add_argument("--disable", dest="enable", action="store_false", help="Keep generators offline")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        if args.command == "serve":
            return serve(args)
        if args.command == "check":
            report = check_database(args.database)
            print(json.dumps(report, ensure_ascii=False, sort_keys=True))
            return 0 if report["ok"] else 1
        if args.command == "init":
            return initialize(args)
        if args.command == "runtime":
            return configure_runtime(args)
    except CLIError as exc:
        print(f"tvcas: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, RuntimeError) as exc:
        # Library errors can contain user values; print only the exception category.
        print(f"tvcas: operation failed ({type(exc).__name__}); check private paths and configuration", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
