# TVCAS3 Server — Python

A standalone Python implementation of the TVCAS3.2 administration application,
ECM generator (ECMG) and EMM generator (EMMG). This fork retains the original
[PHP project's](https://github.com/unidiag/tvcas3-server) Git history and GPL
license; the current branch runs Python with SQLite.

No PHP, Apache, MariaDB, Docker or headend application is needed. The web interface
currently uses Bulgarian labels; the documentation and CLI are in English.

## What it does

- Manage smartcards, individual card keys, 32-bit access masks, validity periods,
  card type and pairing; create cards individually or in batches.
- Import/export CSV and download the original 90-byte uploader `CONFIG.bin` format.
- Serve TVCAS-compatible ECMs over DVB SimulCrypt TCP; deliver entitlement EMMs
  to a scrambler/MUX over a separate TCP connection.
- Show ECMG peers, counters and an administrator-only live CW/ECM request log.
- Import existing PHP installations without regenerating their card or ECM keys.
- Run all generators in one asyncio runtime, with a Waitress web server and
  private SQLite storage.

This is a CAS server, not a video scrambler or multiplexer. The MPEG-TS stream and
EPG do not pass through it. A separate scrambler, such as
[DVB Scrambler](https://github.com/smdbg/dvb-scrambler), inserts ECM/EMM into the TS.
It implements the TVCAS3 smartcard payload format, not arbitrary commercial CAS
systems. It does not include card firmware or an uploader.

## Install

Requires Linux, Python **3.10 or newer**, and the Python dependencies declared in
`pyproject.toml`. No C program needs to be compiled in this repository.

On Debian/Ubuntu:

```sh
sudo apt-get install git python3 python3-venv
git clone https://github.com/smdbg/tvcas3-server.git
cd tvcas3-server
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
tvcas --help
```

Installation also provides `tvcas-migrate`. `python -m tvcas` is equivalent to
`tvcas`. Dependencies are Flask, cryptography and Waitress; SQLite is provided
by Python. Package versions/ranges are in [pyproject.toml](pyproject.toml).

## Start a new installation

For existing programmed cards, use [migration](docs/migration.md) instead of
`init`: the new-install command generates a **new** ECM master key.

```sh
umask 077
mkdir -p "$HOME/.local/share/tvcas"
tvcas init --database "$HOME/.local/share/tvcas/tvcas.sqlite"
tvcas check --database "$HOME/.local/share/tvcas/tvcas.sqlite"
tvcas serve --database "$HOME/.local/share/tvcas/tvcas.sqlite" \
  --host 127.0.0.1 --port 8091
```

`init` asks twice for each account's password: `admin` and `oper`. There is no
shipped password or shared demo key. ECM and billing keys are generated locally;
individual card keys are generated when cards are added. Initialization refuses
to overwrite an existing database.

Open [http://127.0.0.1:8091/](http://127.0.0.1:8091/). Both `/` and `/cas/` lead to
the card list at `/manage/cards`. Use `admin` for setup. Card date fields are UTC;
the eight hexadecimal access-criteria digits are synchronized with 32 checkboxes.

The first start is **offline**: edit settings and create ECMG/EMMG records without
opening generator sockets. See [example settings](examples/README.md) for a local
scrambler setup, including JSON examples usable through the authenticated API.

## Enable generators

Three conditions are required: `serve --activate`, the saved global runtime gate,
and each generator's own enabled flag/status. New and imported installations have
the global gate disabled. New generators are individually disabled.

1. Create and review ECMG/EMMG settings. Enable the desired entries using
   **Разреши** in the generator lists.
2. Stop the offline web process with Ctrl+C, then run:

   ```sh
   tvcas check --database "$HOME/.local/share/tvcas/tvcas.sqlite"
   tvcas runtime --database "$HOME/.local/share/tvcas/tvcas.sqlite" --enable
   tvcas serve --database "$HOME/.local/share/tvcas/tvcas.sqlite" \
     --host 127.0.0.1 --port 8091 --activate
   ```

`runtime --enable` only saves a flag after validation; it opens no network sockets.
The database lock requires the server to be stopped for this command. Use
`runtime ... --disable` while stopped to clear the global gate. Starting without
`--activate` always keeps generators offline, even if saved flags are enabled.
The per-generator web buttons work while the server is running.

Only one serving process may own a database. Do not run multiple WSGI workers,
PHP cron jobs or another TVCAS instance against the same generator endpoints.
The local lock does not coordinate copies of the database on other machines.

## Operation and integration

- [Configuration and scrambler examples](examples/README.md)
- [Service installation, backup and diagnostics](docs/operations.md)
- [PHP migration and JSON export format](docs/migration.md)
- [Protocol and card compatibility](docs/compatibility.md)
- [Changes from the PHP version](CHANGELOG.md)
- [Source provenance and licensing](docs/PROVENANCE.md)

The optional **Headend** navigation link is hidden by default. Set
`HEADEND_PORT=8090` when starting the service to link to that port on the same
hostname and scheme; this does not start or depend on a headend.

Web passwords are hashed. Normal API responses redact secret keys. Admin CSV,
card CONFIG downloads, the database and live CW logs are sensitive. Keep them
private. Bind the web UI and generator ports to trusted interfaces; use HTTPS or
an SSH tunnel for remote administration. SimulCrypt here uses TCP without TLS.

## Tests and packaging

```sh
python -m pip install '.[test]' build
python -m pytest -q
node tests/cards_ui_test.cjs   # optional JS helper tests; Node.js 18+
python -m build
```

Tests use synthetic keys, temporary databases and loopback protocol peers. They
cover ECM/EMM payloads, CP wrap/order, protocol validation, reconnects, entitlement
refresh, migration, roles, CSRF, redaction, card exports, CLI locking and shutdown.
They do not contact real cards or production generators.

The migration was checked against PHP 7.2 using synthetic vectors: ECM, EMM and
the full 90-byte CONFIG output matched. The Python server has also been tested
with TSDuck and the native DVB Scrambler; stable receiver picture and sound across
key changes were confirmed. These results apply to the tested TVCAS3 profile,
not every card, scrambler or ETSI option.

## License

GPL-3.0-or-later. Original TVCAS copyright: **2018–2020 Homer Simpson / TVCAS.COM**.
See [COPYING](COPYING) and [PROVENANCE](docs/PROVENANCE.md). Runtime dependencies
retain their own licenses. No production keys, subscriber records, database dumps
or deployment credentials are distributed with the Python version.
