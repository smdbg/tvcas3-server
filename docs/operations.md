# Operation

## Process and ports

Run one `tvcas serve` process. It owns the web server and the shared asyncio
ECMG/EMMG runtime. No cron launcher, PHP interpreter, per-card process or transport
stream reader is required. SIGINT/SIGTERM closes generator connections and the
HTTP server. A lock next to the database prevents a second local serving process.

The default web bind is `127.0.0.1:8091`. Change `--host` only when you want remote
access. ECMG binds its configured address/port. EMMG connects out to its configured
MUX. Bind/firewall those endpoints to your trusted network. For remote web access,
use an SSH tunnel or an HTTPS reverse proxy; avoid sending web passwords over an
untrusted plain-HTTP connection. The legacy billing API carries its key in the
query string; keep such URLs out of proxy/access logs.

`HEADEND_PORT` is optional and only adds a navigation link. It accepts a port from
1 to 65535, uses the current request's hostname and scheme, and is hidden when
unset or invalid. A headend is not required.

## Optional systemd service

The example [tvcas.service](../examples/tvcas.service) assumes a source/venv install
at `/opt/tvcas`, user `tvcas`, and state under `/var/lib/tvcas`. Adapt these paths to
your system. One way to prepare a new dedicated installation:

```sh
sudo useradd --system --home /var/lib/tvcas --shell /usr/sbin/nologin tvcas
sudo install -d -m 0700 -o tvcas -g tvcas /var/lib/tvcas
sudo git clone https://github.com/smdbg/tvcas3-server.git /opt/tvcas
sudo python3 -m venv /opt/tvcas/.venv
sudo /opt/tvcas/.venv/bin/python -m pip install /opt/tvcas
sudo -u tvcas /opt/tvcas/.venv/bin/tvcas init \
  --database /var/lib/tvcas/tvcas.sqlite
sudo install -m 0644 /opt/tvcas/examples/tvcas.service /etc/systemd/system/tvcas.service
sudo systemctl daemon-reload
sudo systemctl enable --now tvcas
```

If the account/directory already exists, reuse it. For migration, import the
private snapshot instead of running `init`. The unit includes `--activate`, but
the newly initialized/imported database gate is off, so generators remain offline
while you configure the web UI.

When ready, after setting individual generator flags in the UI:

```sh
sudo systemctl stop tvcas
sudo -u tvcas /opt/tvcas/.venv/bin/tvcas check --database /var/lib/tvcas/tvcas.sqlite
sudo -u tvcas /opt/tvcas/.venv/bin/tvcas runtime --database /var/lib/tvcas/tvcas.sqlite --enable
sudo systemctl start tvcas
sudo systemctl status tvcas
journalctl -u tvcas --since '10 minutes ago'
```

Run each command only after the preceding command succeeds. Runtime gates cannot
be changed by the CLI while the serving process holds the database lock. Turning
off one generator in the UI does not require stopping the whole service.

## Health and diagnostics

`GET /healthz` is a minimal unauthenticated HTTP health check. It is not a promise
that cards are entitled or a receiver is decoding. `/api/status` requires login
(or HTTP Basic as `admin`/`oper`) and exposes generator state without CWs.

**ECMG** lists connected/disconnected peers, timestamps and CW/ECM counters.
`cw_count` counts successfully handled CW_PROVISION messages, not individual words.
Administrators can open each peer's live log with access criteria, `cw1` (odd) and
`cw2` (even). There are up to 1000 entries and 64 retained disconnected peers per
generator, in RAM. Restarting a generator clears its live history; it does not
append CWs to the general log or imported SQL history. The browser polls peers
at 5 seconds and the live journal at 3 seconds, pausing when hidden.

Normal API responses redact card keys and CW fields. `admin` can export full CSV
and card CONFIG; `oper` can view generator status, toggle generators and edit
allowed fields of existing cards, but cannot create/delete cards, edit generator
configuration, view settings or export secrets. Both accounts can be given new
passwords in Settings by an administrator.

## Private state and backups

The SQLite file holds cards, keys, password hashes, settings and audit records.
Keep its directory private (`0700`) and use `umask 077`; the application creates
its database/lock files with `0600`. Do not publish that directory, CSV exports,
CONFIG files, packet captures or CW diagnostics.

For a consistent offline backup, stop the service and use SQLite's backup API:

```sh
sudo systemctl stop tvcas
sudo -u tvcas /opt/tvcas/.venv/bin/python - <<'PY'
import os
import sqlite3
from pathlib import Path
os.umask(0o077)
source = Path('/var/lib/tvcas/tvcas.sqlite')
target = Path('/var/lib/tvcas/backup.sqlite')
if not source.is_file() or target.exists():
    raise SystemExit('Source is missing or backup already exists')
with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as src:
    with sqlite3.connect(target) as dst:
        src.backup(dst)
PY
sudo systemctl start tvcas
```

Move the resulting backup to protected backup storage. Do not copy just a live
SQLite main file while WAL writes are in progress. Preserve the original backup
before upgrading; install updated code into the venv, run `check` and restart.
Never rerun `init` over an existing installation or regenerate keys for existing
programmed cards.
