# TVCAS3 web and card-configuration compatibility

The reference is the deployed PHP application retrieved from the existing TVCAS
server. Its application files match the supplied `tvcas3.tar.gz`; deployment
configuration is separate and remains private.

## Pair and type changes

The original **admin** `cas/smartcards.php` increments a card's `start` by one
second when toggling `pair` or `type`, and updates `edit`. Its operator page and
billing API did not apply the same increment. We retain the admin behavior
consistently across the Python form, JSON API, legacy billing API and CSV import:

- Increment `start` once when `pair` or `type` actually changes and the submitted
  start is absent or numerically identical to the previous start.
- Preserve a genuinely different start explicitly supplied by the caller.
- Saving identical flags is idempotent. Changing both flags together causes one
  increment, not two. New cards and unchanged CSV round trips do not increment.
- Preserve null start timestamps; a maximum unsigned-32-bit start cannot be
  incremented and the request fails validation.

This is a conservative compatibility measure based on the existing admin code,
**not a verified claim about firmware duplicate detection**. The supplied
`TVCAS3.RAR` exposes filenames including `SOURCES/8051SYS/Main.c`, but its file
contents are encrypted; those firmware contents were not available for review.
The Python application updates `edit` and requests an EMM refresh after changes.
No active smartcard has been changed to test this behavior.

## Legacy billing API

`GET /api.php?api_key=...&serial_no=...` and its `set[name]`, `set[info]`,
`set[access_criteria]`, `set[pair]`, `set[start]`, `set[finish]` parameters remain
available. The response fields are `serial_no`, `name`, `info`,
`access_criteria`, `pair`, `start`, and `finish`.

The original ordinary `mysqli` text query returns numeric columns as strings;
this endpoint likewise serializes numeric fields as **JSON strings** and retains
SQL null as JSON `null`. The mask is eight hexadecimal characters; letter case
submitted through this legacy endpoint is preserved. The modern `/api/cards`
endpoint returns typed numbers instead.

The legacy HTTP 400 error identifiers, including its misspelling
`SMARDCARD_NOT_FOUND`, are preserved. Deliberate corrections are strict full-value
validation, rejecting accidental `set[serial_no]` support, decoding URL values
once, updating the edit timestamp, and consistently refreshing pair/type changes
as described above. Admin-only CSV/configuration exports, hashed web passwords,
CSRF checks and secret redaction are intentional access-control improvements.

## Uploader CONFIG format

The `.bin` download is a **90-byte card configuration**, not a firmware image.
The uploader contains the firmware. The exporter retains the original layout:

| Offset | Length | Content |
|---|---:|---|
| 0 | 4 | Serial number, big endian |
| 4 | 1 | Low CAID byte when CAID begins `0B`, otherwise zero |
| 5 | 3 | First three bytes of MD5 of the ECM key's hexadecimal **text** |
| 8 | 15 | Trademark UTF-8 bytes, truncated and space padded |
| 23 | 4 | Start epoch, big endian |
| 27 | 4 | Finish epoch, big endian |
| 31 | 4 | 32-bit access mask, big endian |
| 35 | 2 | Packed Conax start date |
| 37 | 2 | Packed Conax finish date |
| 39 | 1 | Pair flag |
| 40 | 1 | `type == 1` flag |
| 41 | 1 | Zero |
| 42 | 32 | Global ECM key |
| 74 | 16 | Individual card key |

ECM text case matters for the MD5 prefix even when the decoded key bytes are the
same; import must not normalize that string. Date packing for this particular
file follows the original PHP server timezone (`php_timezone`, default `UTC`),
not the configurable EMM/UI `zone` offset. Card filenames group digits from the
left, for example `210-000-000-1.bin`.

Tests cover exact synthetic byte layout, key-text case, timezone boundaries,
legacy API string/null values, and flag refresh across mutation paths. No real
keys or subscriber data are included in tests or source files.

On 2026-11-15 the extracted original CONFIG algorithm was also executed by the
source server's PHP 7.2 runtime with a synthetic record (UTC timezone). Its full
90-byte output matched the Python exporter exactly. The extracted ECM and EMM
functions were checked the same way; both synthetic outputs also matched byte
for byte. These are payload compatibility checks, not a physical-card test.

## Optional DVB-CSA CW normalization for older TSDuck

The ECMG profile field `csa_entropy_reduction` is disabled by default, retaining
the original PHP/Astra CW bytes. Set it to `true` (or `1`) only for a scrambler
which sends unreduced CWs to the ECMG but uses reduced DVB-CSA keys on the TS.
This behavior is confirmed in TSDuck 3.33-3139, which lacks `--pre-reduce-cw`;
it may also apply to earlier versions, whose behavior should be checked first.

When enabled, bytes 3 and 7 of both current and next CW become the modulo-256
sums of bytes 0–2 and 4–6 respectively. The ECM payload and the administrator's
CW journal both contain these effective keys. CP/parity ordering, access rights,
the ECM master key and card records are unaffected. Already-reduced CWs remain
unchanged. This does not alter the incoming protocol frame.

Keep TSDuck's default CSA entropy reduction enabled with this compatibility
option; do not use `--no-entropy-reduction`. A newer scrambler's own
`--pre-reduce-cw` is preferable where available, leaving this server option off.
Synthetic tests verify even/odd CPs, CP wrap, both ordering modes, disabled
defaults, idempotence and agreement between encrypted ECM payload and journal.
A real receiver test is still needed for a new combination of card and scrambler.

Reference: [TSDuck 3.33 scrambler](https://github.com/tsduck/tsduck/blob/v3.33-3139/src/tsplugins/tsplugin_scrambler.cpp)
and [CSA key setup](https://github.com/tsduck/tsduck/blob/v3.33-3139/src/libtsduck/crypto/tsDVBCSA2.cpp).

## Live ECM diagnostics

The ECMG peer list and request log restore the original PHP troubleshooting
view. Peer counters count successfully processed CW_PROVISION requests and
generated ECM responses. Log `cw1` and `cw2` retain the PHP payload convention:
odd then even, rather than blindly using the incoming parameter order.
This changes observability only; ECM bytes and SimulCrypt negotiation are
unchanged.

Each generator retains up to 1000 request records and 64 disconnected peers
in memory. A new TCP connection has a new opaque peer ID. Restarting that
generator resets its live history. The imported SQL history remains intact
and is not mixed with live connection IDs. Diagnostic pages and their JSON
endpoint require `admin`; ordinary status and operator views contain no CWs.
Browser-local display times do not change protocol timestamps, card dates,
or the configured EMM timezone.

## Subsequent receiver verification

After the synthetic PHP comparisons, the Python server was used with TSDuck and
with the native DVB Scrambler. The receiver operator confirmed stable picture and
sound across CW changes. This validates those tested configurations; it does not
extend the supported profile to encrypted CWs, packet mode or other CAS formats.
