# Changes

## Python 0.1.0 — 2026-11-16

First standalone Python publication in the existing TVCAS3 fork.

### Relative to TVCAS3.2 PHP

- Replace PHP web pages, cron-started generator scripts and MariaDB runtime
  storage with Flask/Waitress, one supervised asyncio generator runtime and SQLite.
- Retain TVCAS3 ECM/EMM formats, legacy billing compatibility, individual card keys
  and the 90-byte uploader CONFIG layout; import original rows and settings.
- Add hashed passwords, session authentication, CSRF validation, key redaction,
  private-file permissions and transactional card/CSV changes.
- Add card mask checkboxes, UTC validity controls, sorting, search, batch creation
  and audit records. The default page is the smartcard list.
- Restore ECMG peer information and bounded in-memory CW/ECM logs for administrators.
- Validate the supported SimulCrypt section profile, CP/CW combinations and
  protocol frames. Bound queues and reconnect attempts; respect allocated EMM
  bandwidth, including allocation zero.
- Refresh EMM queues after card changes and skip invalid/expired cards. Do not
  produce the old dummy-card EMM when the queue is empty.
- Add explicit CP ordering and optional DVB-CSA entropy reduction for scrambler
  interoperability; preserve legacy defaults on import.
- Add offline validation, new-install initialization, single-process locking,
  SIGTERM cleanup and separate saved/runtime activation gates.

### Standalone publication adjustments

The protocol, storage and card algorithms are taken from the headend Python
implementation described in [PROVENANCE](docs/PROVENANCE.md).

- Add `tvcas runtime --enable/--disable` so standalone installations can configure
  the saved activation gate without the headend supervisor.
- Make the optional Headend link depend on an explicitly configured `HEADEND_PORT`.
- Add installation/service instructions, key-free generator examples, migration
  documentation and Python source/wheel packaging metadata.
- Replace installation-specific documentation and a test peer address with generic
  examples. No production data is part of this publication.
- Remove legacy PHP pages, SQL dump, packaging scripts and browser SQL tunnel from
  the current tree. The fork's upstream Git history is retained unchanged.
