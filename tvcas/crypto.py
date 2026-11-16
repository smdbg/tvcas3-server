"""TVCAS3 card-compatible payloads, ported from the supplied GPL-3.0 PHP.

This is a compatibility implementation, not a new cryptosystem. TVCAS3 uses
two-key Triple DES in ECB mode and additive byte checksums. Preserve the keys
and field layout when migrating existing cards. No live keys belong here.

Reference: tvcas3.tar.gz, html/cas/bin/functions.php (2018-2020 TVCAS.COM).
The original copyright is Homer Simpson <admin@tvcas.com>, GPL-3.0-or-later.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import secrets
import struct
from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43, including distribution packages
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


def _unsigned(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def _bytes(value: bytes | str, size: int, name: str) -> bytes:
    if isinstance(value, str):
        try:
            value = bytes.fromhex(value)
        except ValueError:
            raise ValueError(f"{name} must be hexadecimal") from None
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return value


def encrypt_ecb(plaintext: bytes, key: bytes | str) -> bytes:
    """Encrypt whole blocks as PHP des-ede3(K1 || K2 || K1), without padding.

    PHP encrypted each 8-byte block with PKCS#7 then discarded the padding
    block. Whole-block ECB without padding is exactly the same operation.
    """
    key = _bytes(key, 16, "key")
    if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) % 8:
        raise ValueError("plaintext must be a non-empty multiple of 8 bytes")
    encryptor = Cipher(TripleDES(key + key[:8]), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def conax_date(value: date) -> int:
    """Legacy date bits: decade since 1990 | day (5) | year digit (4) | month (4)."""
    if not isinstance(value, date) or not 1990 <= value.year <= 2069:
        raise ValueError("Conax packed date must be between 1990 and 2069")
    return ((value.year - 1990) // 10 << 13) | (value.day << 8) | (value.year % 10 << 4) | value.month


def conax_date_at(timestamp: int, timezone_offset_minutes: int = 0) -> int:
    """Pack a timestamp using the TVCAS configured fixed UTC offset.

    The old PHP app applies its configured +/-HHMM zone rather than a named
    DST-aware zone. This helper never inherits the Python host's timezone.
    """
    _unsigned(timestamp, 32, "timestamp")
    zone = timezone(timedelta(minutes=timezone_offset_minutes))
    return conax_date(datetime.fromtimestamp(timestamp, zone).date())


def build_ecm(
    table_id: int,
    timestamp: int,
    odd_cw: bytes | str,
    even_cw: bytes | str,
    key: bytes | str,
    access_criteria: int,
    *,
    random_bytes: bytes | None = None,
) -> bytes:
    """Build one 55-byte TVCAS3 ECM section (table_id 0x80/0x81).

    CW order in the private payload is always odd then even. ``key`` is the
    already-selected 16-byte even/odd half of the 32-byte ECM master key.
    Supply 23 deterministic random bytes only for reproducible tests.
    """
    if table_id not in (0x80, 0x81):
        raise ValueError("ECM table_id must be 0x80 or 0x81")
    timestamp = _unsigned(timestamp, 32, "timestamp")
    access_criteria = _unsigned(access_criteria, 32, "access_criteria")
    odd_cw = _bytes(odd_cw, 8, "odd_cw")
    even_cw = _bytes(even_cw, 8, "even_cw")
    if random_bytes is None:
        random_bytes = secrets.token_bytes(23)
    random_bytes = _bytes(random_bytes, 23, "random_bytes")
    plain = struct.pack("!I", timestamp) + odd_cw + even_cw
    plain += struct.pack("!I", access_criteria) + random_bytes
    plain += bytes([sum(plain) & 0xFF])
    encrypted = encrypt_ecb(plain, key)
    return bytes([table_id, 0x70, 52, 0x70, 50, 0x64, 0x21]) + encrypted


def build_ecm_for_cp(
    cp_number: int,
    combinations: Iterable[tuple[int, bytes]],
    key: bytes | str,
    access_criteria: int,
    timestamp: int,
    *,
    random_bytes: bytes | None = None,
    cw_order: str = "legacy",
) -> bytes:
    """Build the ECM for lead_CW=1, CW_per_msg=2 (current and next CP).

    The default preserves PHP's positional lookup of the two CW parameters.
    ``cw_order='cp'`` explicitly uses their CP labels instead. Do not change
    an existing installation's interpretation without a compatibility test.
    CP wraps at 65535; only 8-byte DVB-CSA words are supported.
    """
    _unsigned(cp_number, 16, "cp_number")
    master_key = _bytes(key, 32, "ECM master key")
    pairs = list(combinations)
    expected = {cp_number, (cp_number + 1) & 0xFFFF}
    if len(pairs) != 2 or {pair[0] for pair in pairs} != expected:
        raise ValueError("exactly the current and next CP/CW combinations are required")
    parity = cp_number & 1
    words = [_bytes(cw, 8, "CW") for _, cw in pairs]
    if cw_order == "legacy":
        odd, even = words if parity else words[::-1]
    elif cw_order == "cp":
        by_parity = {cp & 1: cw for (cp, _), cw in zip(pairs, words)}
        odd, even = by_parity[1], by_parity[0]
    else:
        raise ValueError("cw_order must be 'legacy' or 'cp'")
    return build_ecm(
        0x80 + parity, timestamp, odd, even,
        master_key[16 * parity:16 * (parity + 1)], access_criteria,
        random_bytes=random_bytes,
    )


def build_emm(
    serial_no: int,
    access_criteria: int,
    key: bytes | str,
    start: int,
    finish: int,
    *,
    pair: int = 0,
    type_flag: int = 0,
    timezone_offset_minutes: int = 0,
    packed_start_date: int | None = None,
    packed_finish_date: int | None = None,
) -> bytes:
    """Build a 62-byte addressed entitlement EMM, command 0x6410.

    Preserve PHP's inclusive ``finish + 1`` and its exact MD5-derived filler.
    Packed dates may be supplied explicitly for migration verification of
    servers with an unusual PHP/system timezone combination.
    """
    _unsigned(serial_no, 32, "serial_no")
    _unsigned(access_criteria, 32, "access_criteria")
    _unsigned(start, 32, "start")
    _unsigned(finish, 32, "finish")
    if packed_start_date is None:
        packed_start_date = conax_date_at(start, timezone_offset_minutes)
    if packed_finish_date is None:
        packed_finish_date = conax_date_at(finish, timezone_offset_minutes)
    _unsigned(packed_start_date, 16, "packed_start_date")
    _unsigned(packed_finish_date, 16, "packed_finish_date")
    plain = struct.pack(
        "!IIIIHHBBB", serial_no, access_criteria, start, (finish + 1) & 0xFFFFFFFF,
        packed_start_date, packed_finish_date, int(pair > 0), int(type_flag == 1), 0,
    )
    checksum = sum(plain) & 0xFF
    plain += bytes([checksum])
    # Decimal string concatenation is intentional: it matches PHP's '.' operator.
    filler = hashlib.md5(f"{start}{checksum}".encode("ascii"), usedforsecurity=False).digest()
    filler += hashlib.md5(f"{finish}{checksum}".encode("ascii"), usedforsecurity=False).digest()
    plain += filler[:23]
    plain += bytes([sum(plain) & 0xFF])
    encrypted = encrypt_ecb(plain, key)
    return b"\x82\x70\x3b\x00\x00\x00" + struct.pack("!I", serial_no) + b"\x70\x32\x64\x10" + encrypted
