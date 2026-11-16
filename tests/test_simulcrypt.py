"""Protocol boundaries and explicit ETSI-style synthetic wire messages."""

import struct
import unittest

from tvcas.simulcrypt import (
    ECMGMessage, ECMGTag, EMMGMessage, EMMGTag, Frame, FrameDecoder,
    ProtocolError, TLV, cp_cw_combinations, cp_cw_parameter, decode_frame,
    packetize_section,
)


class SimulcryptTests(unittest.TestCase):
    def test_channel_setup_literal_wire_vector(self):
        wire = bytes.fromhex("010001000e000100040b000001000e00020017")
        frame = Frame(1, ECMGMessage.CHANNEL_SETUP, (
            TLV.integer(ECMGTag.SUPER_CAS_ID, 0x0B000001, 4),
            TLV.integer(ECMGTag.ECM_CHANNEL_ID, 23),
        ))
        self.assertEqual(frame.encode(), wire)
        self.assertEqual(decode_frame(wire), frame)
        self.assertEqual(frame.integer(ECMGTag.SUPER_CAS_ID, 4), 0x0B000001)

    def test_fragmentation_at_every_boundary_and_coalescing(self):
        first = bytes.fromhex("010001000e000100040b000001000e00020017")
        second = bytes.fromhex("0100040006000e00020017")
        both = first + second
        expected = [decode_frame(first), decode_frame(second)]
        for split in range(len(both) + 1):
            decoder = FrameDecoder()
            self.assertEqual(decoder.feed(both[:split]) + decoder.feed(both[split:]), expected)
            decoder.eof()
        decoder = FrameDecoder()
        frames = []
        for value in both:
            frames.extend(decoder.feed(bytes([value])))
        self.assertEqual(frames, expected)

    def test_repeated_cw_and_emm_datagram_values_are_preserved(self):
        words = ((0xFFFF, bytes(range(8))), (0, bytes(range(8, 16))))
        request = Frame(2, ECMGMessage.CW_PROVISION, tuple(cp_cw_parameter(*word) for word in words))
        self.assertEqual(cp_cw_combinations(decode_frame(request.encode())), words)
        datagrams = Frame(1, EMMGMessage.DATA_PROVISION, (
            TLV.integer(EMMGTag.CLIENT_ID, 0x100, 4),
            TLV(EMMGTag.DATAGRAM, b"first"), TLV(EMMGTag.DATAGRAM, b"second"),
        ))
        self.assertEqual(decode_frame(datagrams.encode()).get_all(EMMGTag.DATAGRAM), (b"first", b"second"))
        with self.assertRaises(ProtocolError):
            datagrams.get(EMMGTag.DATAGRAM)

    def test_signed_delays_and_unknown_tags(self):
        frame = Frame(1, ECMGMessage.CHANNEL_STATUS, (
            TLV.integer(ECMGTag.DELAY_START, -300, signed=True), TLV(0xFF00, b"private"),
        ))
        self.assertIn(bytes.fromhex("00030002fed4"), frame.encode())
        copy = decode_frame(frame.encode())
        self.assertEqual(copy.integer(ECMGTag.DELAY_START, signed=True), -300)
        self.assertEqual(copy.get(0xFF00), b"private")
        self.assertIsNone(copy.get(0xFF01))
        with self.assertRaises(ProtocolError):
            copy.integer(0xFF01)

    def test_bad_lengths_and_limits_fail_closed(self):
        malformed = (
            b"", b"\x01\x00\x01\x00",  # missing header
            bytes.fromhex("010001000100"),  # partial TLV header
            bytes.fromhex("010001000400010001"),  # TLV value outside message
            bytes.fromhex("010001000000"),  # trailing byte
            bytes.fromhex("0100010001"),  # truncated payload
        )
        for wire in malformed:
            with self.subTest(wire=wire.hex()), self.assertRaises(ProtocolError):
                decode_frame(wire)
        decoder = FrameDecoder(max_payload=10)
        with self.assertRaises(ProtocolError):
            decoder.feed(bytes.fromhex("010001000b"))
        self.assertEqual(decoder.feed(bytes.fromhex("0100010000")), [Frame(1, 1)])
        decoder.feed(b"\x01")
        with self.assertRaises(ProtocolError):
            decoder.eof()

    def test_size_and_numeric_validation(self):
        with self.assertRaises(ProtocolError):
            TLV.integer(1, -1)
        with self.assertRaises(ProtocolError):
            TLV.integer(1, 32768, signed=True)
        with self.assertRaises(ProtocolError):
            Frame(1, 1, (TLV(1, bytes(65532)),)).encode()
        with self.assertRaises(ProtocolError):
            Frame(1, 1, (TLV(1, b"\x01"),)).integer(1)
        with self.assertRaises(ProtocolError):
            cp_cw_parameter(0, bytes(16))
        with self.assertRaises(ProtocolError):
            cp_cw_combinations(Frame(1, 0x201, (TLV(ECMGTag.CP_CW_COMBINATION, bytes(9)),)))

    def test_packetized_section_pointer_stuffing_and_cc_wrap(self):
        # 300-byte synthetic private section spanning two transport packets.
        section = bytes([0x82, 0x71, 0x29]) + bytes(range(256)) + bytes(41)
        result, next_cc = packetize_section(section, pid=90, continuity_counter=15)
        self.assertEqual(len(result), 376)
        self.assertEqual(result[:5], bytes.fromhex("47405a1f00"))
        self.assertEqual(result[188:192], bytes.fromhex("47005a10"))
        self.assertEqual(result[5:188] + result[192:309], section)
        self.assertEqual(result[309:], b"\xff" * 67)
        self.assertEqual(next_cc, 1)
        with self.assertRaises(ProtocolError):
            packetize_section(section[:-1], pid=90)


if __name__ == "__main__":
    unittest.main()
