# Migrating from TVCAS3 PHP

Migration reads a private JSON database snapshot and the installed PHP
`includes/config.php`. It does not execute PHP, run SQL from a dump, connect to
the old server or start generators. SQLite uses its own schema; MariaDB is not
needed at runtime.

Do not run `init` for existing programmed cards: their master and individual keys
must be preserved. Keep the original server backup for rollback.

## Source backup

Capture a consistent backup of the five application tables, the installed
configuration and the old server's PHP timezone/fixed EMM offset. The original
schema may mix InnoDB and MyISAM: a transaction-only database dump is not a
consistent snapshot for all tables. Arrange read locks or stop writes for the
snapshot. Keep a normal SQL dump for rollback as well as the JSON import file.

Protect the entire backup: it contains ECM/card keys, accounts, subscriber data
and potentially historical CW logs. Do not copy it into this repository.

## Required JSON shape

Export rows as column-name/value objects, with numeric SQL columns as numbers and
SQL NULL as JSON null. All five tables must be present, even if empty. Preserve
row IDs, serial numbers, key strings including their case, timestamps and extra
vendor columns. The importer accepts this shape, optionally inside `{"tables": …}`:

```json
{
  "tvcas_ecmg": [],
  "tvcas_emmg": [],
  "tvcas_smartcards": [],
  "tvcas_logs": [],
  "tvcas_ecmg_log": []
}
```

The arrays above demonstrate the schema only; use your actual private snapshot.
There is no SQL-dump parser or remote database exporter in this package. Obtain
this JSON from the source database using a read-only export script/database tool;
do not turn PHP or SQL into executable Python.

## Import and validate

Paths are examples. Replace them with private files from your own installation:

```sh
umask 077
tvcas-migrate \
  --database "$HOME/.local/share/tvcas/migrated.sqlite" \
  --rows /secure-backup/database.json \
  --php-config /secure-backup/includes/config.php \
  --timezone UTC --zone +0000

tvcas check --database "$HOME/.local/share/tvcas/migrated.sqlite"
tvcas serve --database "$HOME/.local/share/tvcas/migrated.sqlite" \
  --host 127.0.0.1 --port 8091
```

Use the original PHP timezone instead of UTC if different. After import, verify
**CONFIG timezone / `php_timezone`** in Settings before downloading card CONFIG
files; it must match the source PHP timezone. EMM `zone` is a separate fixed
`±HHMM` offset. Card date inputs in the UI are always UTC.

The importer:

- Preserves row IDs, columns, key text case and generator enable flags.
- Imports atomically and rejects duplicate IDs/serials or a nonempty target unless
  explicitly given `--replace`. Prefer a new target file; `--replace` deletes its
  existing imported records.
- Hashes the original `admin` and `oper` web passwords. It does not substitute SSH
  credentials and does not store plaintext copies of those two web passwords.
- Keeps remaining legacy configuration metadata in the private database.
- Always sets the global `runtime_enabled` gate to false, regardless of imported
  generator flags.
- Parses literal PHP settings only. Dynamic/interpolated expressions are not
  evaluated. A non-literal configuration needs an explicit private conversion;
  do not run an obfuscation/packaging helper to prepare it.

Inspect the card counts, masks, validity dates, card type/pair flags and generator
addresses before activation. `check` reports field errors without secret values.
It does not prove compatibility with a physical card.

## Trial and cutover

1. Use a separate test scrambler/MUX with non-conflicting endpoints. Keep the same
   private keys for its existing test card. Send test EMMs only to the test path.
2. Stop the offline web process. Use `tvcas runtime --database … --enable`, then
   `tvcas serve --database … --activate`; enable only the needed generator entries.
3. Check ECMG handshake, EMM reception, access masks, validity and stable picture
   across multiple CW changes on a real receiver. Verify ECM descriptors, CAT/EMM
   and EPG at the downstream TS; the CAS server itself never carries EPG.
4. Before final cutover, take a fresh snapshot if the original system changed.
   Stop the old generators/cron supervisor, then switch scramblers to Python ECMG
   and direct EMMG to the intended MUX endpoint.
5. Retain only one active writer/generator set per deployment. A local file lock
   cannot detect an old server or a separately copied database.

For rollback, stop the Python generators and restore the previous endpoints and
old service. Migration never modifies the source PHP server/database. Preserve
changes made after migration before restoring an older backup.
