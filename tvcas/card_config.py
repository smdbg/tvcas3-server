"""TVCAS3 uploader configuration format (90 bytes, not a firmware image)."""
from datetime import datetime
import hashlib
import re
import struct
from zoneinfo import ZoneInfo

from .crypto import conax_date


def _hex(value, size, field):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{%d}' % (size * 2), value):
        raise ValueError(f'{field} must contain {size * 2} hexadecimal characters')
    return bytes.fromhex(value)


def build_card_config(card, settings):
    """Match legacy PHP config download, including its hash of ECM key text.

    php_timezone is the old PHP server timezone. It affects Conax date fields;
    the UI's fixed `zone` offset does not affect this particular legacy file.
    """
    try:
        serial = int(card['serial_no'])
        start, finish = int(card['start']), int(card['finish'])
    except (KeyError, TypeError, ValueError):
        raise ValueError('card requires serial_no and validity timestamps') from None
    if any(not 0 <= value <= 0xffffffff for value in (serial, start, finish)):
        raise ValueError('serial and timestamps must be unsigned 32-bit values')
    if finish < start:
        raise ValueError('finish must not precede start')
    ecm_text = settings['ecm_key']
    ecm_key = _hex(ecm_text, 32, 'ECM key')
    card_key = _hex(card['key'], 16, 'card key')
    mask = _hex(card['access_criteria'], 4, 'access criteria')
    ident = str(settings.get('ident', '0B00')).upper()
    _hex(ident, 2, 'CAID')
    caid_low = int(ident[2:4], 16) if ident.startswith('0B') else 0
    # Legacy PHP substr uses bytes, including when the label is UTF-8.
    trademark = str(settings.get('trademark', '')).encode('utf-8')[:15].ljust(15, b' ')
    tz = ZoneInfo(settings.get('php_timezone') or 'UTC')
    date_start = conax_date(datetime.fromtimestamp(start, tz).date())
    date_finish = conax_date(datetime.fromtimestamp(finish, tz).date())
    result = (struct.pack('>IB', serial, caid_low)
              + hashlib.md5(ecm_text.encode('ascii'), usedforsecurity=False).digest()[:3]
              + trademark + struct.pack('>II', start, finish) + mask
              + struct.pack('>HHBBB', date_start, date_finish, int(bool(int(card.get('pair', 0)))),
                            int(int(card.get('type', 1)) == 1), 0)
              + ecm_key + card_key)
    assert len(result) == 90
    return result


def config_filename(serial):
    digits = str(int(serial))
    return '-'.join(digits[i:i+3] for i in range(0, len(digits), 3)) + '.bin'
