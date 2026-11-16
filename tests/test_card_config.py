import hashlib
import struct
import unittest

from tvcas.card_config import build_card_config, config_filename


class CardConfigTests(unittest.TestCase):
    def setUp(self):
        self.card = dict(serial_no=2100000001, start=1704067200, finish=1735689600,
                         access_criteria='80000001', pair=1, type=2, key='12' * 16)
        self.settings = dict(ecm_key='ab' * 32, ident='0B17', trademark='Example', php_timezone='UTC')

    def test_exact_legacy_layout(self):
        binary = build_card_config(self.card, self.settings)
        expected = (struct.pack('>IB', 2100000001, 0x17)
                    + hashlib.md5(('ab' * 32).encode(), usedforsecurity=False).digest()[:3]
                    + b'Example        '
                    + bytes.fromhex('65920080677485808000000161416151010000')
                    + bytes.fromhex('ab' * 32 + '12' * 16))
        self.assertEqual(len(expected), 90)
        self.assertEqual(binary, expected)
        self.assertEqual(config_filename(2100000001), '210-000-000-1.bin')

    def test_legacy_fingerprint_retains_hex_text_case(self):
        lower = build_card_config(self.card, self.settings)
        upper = build_card_config(self.card, {**self.settings, 'ecm_key': self.settings['ecm_key'].upper()})
        self.assertNotEqual(lower[5:8], upper[5:8])
        self.assertEqual(lower[42:], upper[42:])

    def test_server_timezone_changes_date_not_epoch(self):
        card = {**self.card, 'start': 1704063600}
        utc = build_card_config(card, self.settings)
        sofia = build_card_config(card, {**self.settings, 'php_timezone': 'Europe/Sofia'})
        self.assertEqual(utc[23:35], sofia[23:35])
        self.assertNotEqual(utc[35:37], sofia[35:37])

    def test_invalid_key_rejected(self):
        with self.assertRaises(ValueError):
            build_card_config({**self.card, 'key': 'bad'}, self.settings)


if __name__ == '__main__':
    unittest.main()
