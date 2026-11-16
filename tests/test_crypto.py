"""Synthetic wire vectors; no operational keys, cards or CWs.

Ciphertext fixtures were independently generated with OpenSSL's
`enc -des-ede3-ecb -nopad` using explicit synthetic plaintext records. They
also matched selected pure functions from the installed PHP application on
its PHP 7.2 runtime; that isolated harness supplied deterministic random
bytes and never included the application bootstrap, database or live keys.
"""

from datetime import date
import unittest

from tvcas.crypto import build_ecm, build_ecm_for_cp, build_emm, conax_date, conax_date_at, encrypt_ecb


KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
ECM = bytes.fromhex(
    "80703470326421"
    "1da4a7977f7246753f065064d55d4f210d803e53da1f099c"
    "52c5c0705d9089e1decfc0f111152b1280bd53c91aa119e9"
)
EMM = bytes.fromhex(
    "82703b0000000102030470326410"
    "65103ddab69b21b37c588d5861ebed9c56a69ec9b80adbb2"
    "7cc65ca80e5b49470c4af2cc2b60cbe887139bc7c4716151"
)


class CryptoTests(unittest.TestCase):
    def test_two_key_triple_des_openssl_vector(self):
        self.assertEqual(encrypt_ecb(bytes.fromhex("0123456789abcdef"), KEY).hex(), "1a4d672dca6cb335")

    def test_ecm_matches_synthetic_openssl_vector(self):
        actual = build_ecm(0x80, 0x65000000, bytes(range(8)), bytes(range(16, 24)), KEY, 0x81,
                           random_bytes=bytes(range(23)))
        self.assertEqual(actual, ECM)
        self.assertEqual(len(actual), 55)

    def test_emm_matches_synthetic_openssl_vector(self):
        self.assertEqual(build_emm(0x01020304, 0x81, KEY, 1704067200, 1706745599,
                                   pair=1, type_flag=1), EMM)
        self.assertEqual(len(EMM), 62)

    def test_ecm_key_selection_and_legacy_word_order(self):
        words = [(0, bytes(range(16, 24))), (1, bytes(range(8)))]
        master = KEY + bytes(range(16))
        self.assertEqual(build_ecm_for_cp(0, words, master, 0x81, 0x65000000,
                                          random_bytes=bytes(range(23))), ECM)
        # Explicit CP mode tolerates reversed TLV order; legacy mode preserves
        # the actual historical behavior rather than silently changing it.
        self.assertEqual(build_ecm_for_cp(0, words[::-1], master, 0x81, 0x65000000,
                                          random_bytes=bytes(range(23)), cw_order="cp"), ECM)
        self.assertNotEqual(build_ecm_for_cp(0, words[::-1], master, 0x81, 0x65000000,
                                             random_bytes=bytes(range(23))), ECM)
        next_words = [(1, words[1][1]), (2, words[0][1])]
        actual = build_ecm_for_cp(1, next_words, master, 0x81, 0x65000000,
                                  random_bytes=bytes(range(23)))
        expected = build_ecm(0x81, 0x65000000, words[1][1], words[0][1], bytes(range(16)), 0x81,
                             random_bytes=bytes(range(23)))
        self.assertEqual(actual, expected)

    def test_cp_wrap_and_invalid_combinations(self):
        words = [(65535, bytes(8)), (0, bytes(range(8)))]
        actual = build_ecm_for_cp(65535, words, KEY * 2, 1, 1700000000, random_bytes=bytes(23))
        self.assertEqual(actual[0], 0x81)
        for bad in ([], words[:1], [words[0], words[0]], [(0, bytes(8)), (2, bytes(8))]):
            with self.assertRaises(ValueError):
                build_ecm_for_cp(0, bad, KEY * 2, 1, 1700000000)

    def test_dates_and_explicit_timezone(self):
        self.assertEqual(conax_date(date(2024, 1, 1)), 0x6141)
        self.assertEqual(conax_date(date(2024, 1, 31)), 0x7F41)
        self.assertEqual(conax_date(date(2029, 12, 31)), 0x7F9C)
        self.assertEqual(conax_date(date(2030, 1, 1)), 0x8101)
        # Midnight Jan 1 UTC is still Dec 31 with -01:00; do not use host TZ.
        self.assertEqual(conax_date_at(1704067200, -60), conax_date(date(2023, 12, 31)))
        with self.assertRaises(ValueError):
            conax_date(date(2070, 1, 1))

    def test_emm_legacy_flags(self):
        self.assertEqual(build_emm(0x01020304, 0x81, KEY, 1704067200, 1706745599,
                                   pair=123, type_flag=1), EMM)
        common = (0x01020304, 0x81, KEY, 1704067200, 1706745599)
        self.assertEqual(build_emm(*common, type_flag=2), build_emm(*common, type_flag=0))

    def test_reject_invalid_sizes_without_echoing_key(self):
        for bad in (b"secret", bytes(24), "bad hex"):
            with self.assertRaises(ValueError) as raised:
                encrypt_ecb(bytes(8), bad)
            self.assertNotIn(str(bad), str(raised.exception))
        for bad in (b"", bytes(7), bytes(9)):
            with self.assertRaises(ValueError):
                encrypt_ecb(bad, KEY)
        with self.assertRaises(ValueError):
            build_ecm(0x82, 0, bytes(8), bytes(8), KEY, 0)
        with self.assertRaises(ValueError):
            build_ecm(0x80, 0, bytes(8), bytes(8), KEY, 0, random_bytes=bytes(22))


if __name__ == "__main__":
    unittest.main()
