import asyncio
import json
import unittest

from tvcas.crypto import Cipher, TripleDES, modes
from tvcas.ecmg import ECMGServer, ECM_LOG_LIMIT, RECENT_PEER_LIMIT, _Peer
from tvcas.simulcrypt import ECMGMessage as M, ECMGTag as T, Frame, TLV, cp_cw_parameter, decode_frame


class CSAEntropyCompatibilityTests(unittest.TestCase):
    def test_effective_cws_match_ecm_and_journal_for_both_parities(self):
        original = (bytes.fromhex("01020399040506AA"), bytes.fromhex("F02030BB90A0B0CC"))
        reduced = (bytes.fromhex("010203060405060F"), bytes.fromhex("F020304090A0B0E0"))
        for setting in (None, False, 0, True, 1):
            for cp in (0, 1, 65535):
                for order, reverse in (("legacy", False), ("cp", False), ("cp", True)):
                    for source in (original, reduced):
                        with self.subTest(setting=setting, cp=cp, order=order, reverse=reverse,
                                          already_reduced=source == reduced):
                            config = {"key": bytes(range(32)).hex(), "cw_order": order}
                            if setting is not None:
                                config["csa_entropy_reduction"] = setting
                            server = ECMGServer(config)
                            peer = _Peer(channel_id=7, version=2, streams={9: 101})
                            pairs = [cp_cw_parameter(cp, source[0]),
                                     cp_cw_parameter((cp + 1) & 0xFFFF, source[1])]
                            if reverse:
                                pairs.reverse()
                            frame = Frame(2, M.CW_PROVISION, (
                                TLV.integer(T.ECM_CHANNEL_ID, 7), TLV.integer(T.ECM_STREAM_ID, 9),
                                TLV.integer(T.CP_NUMBER, cp), TLV.integer(T.ACCESS_CRITERIA, 1, 4),
                                *pairs))
                            original_frame = frame.encode()
                            response, close = server._handle(peer, frame)
                            self.assertFalse(close)
                            self.assertEqual(frame.encode(), original_frame)
                            key = bytes(range(32))[16 * (cp & 1):16 * ((cp & 1) + 1)]
                            decryptor = Cipher(TripleDES(key + key[:8]), modes.ECB()).decryptor()
                            plain = decryptor.update(response.require(T.ECM_DATAGRAM)[7:]) + decryptor.finalize()
                            effective = reduced if setting else source
                            odd, even = effective if cp & 1 else effective[::-1]
                            self.assertEqual(plain[4:12], odd)
                            self.assertEqual(plain[12:20], even)
                            entry = server.diagnostics()["entries"][0]
                            self.assertEqual((entry["cw1"], entry["cw2"]),
                                             (odd.hex().upper(), even.hex().upper()))

    def test_invalid_reduction_settings_are_rejected_before_start(self):
        for invalid in (None, "false", "true", "0", "1", 1.0, -1, 2, [], {}):
            with self.subTest(setting=invalid), self.assertRaisesRegex(ValueError, "csa_entropy_reduction"):
                ECMGServer({"key": bytes(range(32)).hex(), "csa_entropy_reduction": invalid})


class ECMGTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.logs = []
        self.server = ECMGServer({"host": "127.0.0.1", "port": 0, "key": bytes(range(32)).hex(),
                                  "timeout": 2, "delay_start": -300, "min_cp_duration": 50}, self.logs.append)
        await self.server.start()
        port = self.server.status()["addresses"][0][1]
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)

    async def asyncTearDown(self):
        self.writer.close()
        await self.writer.wait_closed()
        await self.server.close()

    async def receive(self, reader=None):
        reader = reader or self.reader
        header = await asyncio.wait_for(reader.readexactly(5), 2)
        body = await asyncio.wait_for(reader.readexactly(int.from_bytes(header[3:], "big")), 2)
        return decode_frame(header + body)

    def send(self, message_type, parameters=(), *, channel=7, version=1):
        self.writer.write(Frame(version, message_type, (TLV.integer(T.ECM_CHANNEL_ID, channel), *parameters)).encode())

    async def establish(self):
        self.send(M.CHANNEL_SETUP, (TLV.integer(T.SUPER_CAS_ID, 0x0B000001, 4),))
        channel = await self.receive()
        self.assertEqual(channel.message_type, M.CHANNEL_STATUS)
        self.assertEqual(channel.integer(T.DELAY_START, signed=True), -300)
        self.assertEqual(channel.integer(T.LEAD_CW, 1), 1)
        self.assertEqual(channel.integer(T.CW_PER_MSG, 1), 2)
        self.send(M.STREAM_SETUP, (TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.ECM_ID, 101),
                                   TLV.integer(T.NOMINAL_CP_DURATION, 100)))
        self.assertEqual((await self.receive()).message_type, M.STREAM_STATUS)

    async def test_handshake_ecm_and_graceful_closure(self):
        await self.establish()
        self.send(M.CW_PROVISION, (TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.CP_NUMBER, 0),
                                  TLV.integer(T.ACCESS_CRITERIA, 1, 4),
                                  cp_cw_parameter(0, bytes(range(8))), cp_cw_parameter(1, bytes(range(8, 16)))))
        response = await self.receive()
        self.assertEqual(response.message_type, M.ECM_RESPONSE)
        self.assertEqual(response.integer(T.CP_NUMBER), 0)
        self.assertEqual(response.require(T.ECM_DATAGRAM)[:7], bytes.fromhex("80703470326421"))
        self.assertEqual(len(response.require(T.ECM_DATAGRAM)), 55)
        self.assertEqual(self.server.status()["ecm_count"], 1)
        self.send(M.STREAM_TEST, (TLV.integer(T.ECM_STREAM_ID, 9),))
        self.assertEqual((await self.receive()).message_type, M.STREAM_STATUS)
        self.send(M.STREAM_CLOSE_REQUEST, (TLV.integer(T.ECM_STREAM_ID, 9),))
        self.assertEqual((await self.receive()).message_type, M.STREAM_CLOSE_RESPONSE)
        self.assertEqual(self.server.status()["streams"], 0)
        self.send(M.CHANNEL_CLOSE)
        self.assertEqual(await asyncio.wait_for(self.reader.read(), 2), b"")
        self.assertNotIn(bytes(range(32)).hex(), str(self.server.status()) + str(self.logs))

    async def test_missing_stream_bad_cw_and_version_error(self):
        await self.establish()
        self.send(M.STREAM_TEST, (TLV.integer(T.ECM_STREAM_ID, 90),))
        self.assertEqual((await self.receive()).integer(T.ERROR_STATUS), 7)
        self.send(M.CHANNEL_TEST, version=7)
        self.assertEqual((await self.receive()).integer(T.ERROR_STATUS), 2)
        self.send(M.CW_PROVISION, (TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.CP_NUMBER, 0),
                                  TLV.integer(T.ACCESS_CRITERIA, 1, 4), cp_cw_parameter(0, bytes(8))))
        response = await self.receive()
        self.assertEqual(response.message_type, M.STREAM_ERROR)
        self.assertEqual(response.integer(T.ERROR_STATUS), 0xB)
        self.assertEqual(self.server.status()["ecm_count"], 0)
        self.assertEqual(self.server.diagnostics()["entries"], [])

    async def test_peer_log_counters_payload_order_and_public_redaction(self):
        await self.establish()
        first = bytes.fromhex("1122334455667788")
        second = bytes.fromhex("89ABCDEF01234567")
        peer = self.server.status()["peers"][0]
        self.assertTrue(peer["connected"])
        self.assertEqual(peer["address"], "127.0.0.1:" + str(self.writer.get_extra_info("sockname")[1]))
        self.assertEqual(peer["channel_id"], 7)
        self.assertEqual(peer["streams"], 1)
        self.assertGreaterEqual(peer["last_seen"], peer["connected_at"])
        for cp, order, reverse in ((0, "legacy", False), (1, "legacy", False),
                                   (2, "cp", True), (3, "cp", True)):
            self.server.config["cw_order"] = order
            pairs = [cp_cw_parameter(cp, first), cp_cw_parameter(cp + 1, second)]
            if reverse:
                pairs.reverse()
            self.send(M.CW_PROVISION, (TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.CP_NUMBER, cp),
                                      TLV.integer(T.ACCESS_CRITERIA, 0x80000001, 4), *pairs))
            response = await self.receive()
            entry = self.server.diagnostics(peer["peer_id"], limit=1)["entries"][0]
            # Independently decrypt the emitted ECM to check exactly which two
            # words the journal reports, including reversed CP-labelled TLVs.
            key = bytes(range(32))[16 * (cp & 1):16 * ((cp & 1) + 1)]
            decryptor = Cipher(TripleDES(key + key[:8]), modes.ECB()).decryptor()
            plain = decryptor.update(response.require(T.ECM_DATAGRAM)[7:]) + decryptor.finalize()
            self.assertEqual(entry["cw1"], plain[4:12].hex().upper())
            self.assertEqual(entry["cw2"], plain[12:20].hex().upper())
            self.assertEqual(entry["cw1"], (first if cp & 1 else second).hex().upper())
            self.assertEqual(entry["cw2"], (second if cp & 1 else first).hex().upper())
            self.assertEqual(entry["access_criteria"], "80000001")
            self.assertEqual((entry["cp_number"], entry["channel_id"], entry["stream_id"]), (cp, 7, 9))
            self.assertEqual(entry["address"], peer["address"])
        current = self.server.status()["peers"][0]
        self.assertEqual((current["cw_count"], current["ecm_count"]), (4, 4))
        self.assertEqual(self.server.diagnostics("unknown")["entries"], [])
        public = json.dumps(self.server.status()) + str(self.logs)
        for word in (first, second):
            self.assertNotIn(word.hex().upper(), public)
            self.assertNotIn(word.hex().lower(), public)
        self.assertNotIn("cw1", public)
        # Diagnostic callers receive copies, never mutable journal rows.
        changed = self.server.diagnostics()
        changed["entries"][0]["cw1"] = "changed"
        changed["peers"][0]["address"] = "changed"
        self.assertNotEqual(self.server.diagnostics()["entries"][0]["cw1"], "changed")
        self.assertNotEqual(self.server.status()["peers"][0]["address"], "changed")

    async def test_disconnect_history_is_bounded_and_connection_ids_are_not_reused(self):
        await self.establish()
        active_id = self.server.status()["peers"][0]["peer_id"]
        seen = {active_id}
        first_closed_id = None
        for index in range(RECENT_PEER_LIMIT + 2):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.server.status()["addresses"][0][1])
            writer.write(Frame(1, M.CHANNEL_SETUP, (TLV.integer(T.ECM_CHANNEL_ID, 7),
                                                   TLV.integer(T.SUPER_CAS_ID, 0x0B000001, 4))).encode())
            await self.receive(reader)
            port = writer.get_extra_info("sockname")[1]
            peer = next(row for row in self.server.status()["peers"]
                        if row["connected"] and row["address"] == f"127.0.0.1:{port}")
            self.assertNotIn(peer["peer_id"], seen)
            seen.add(peer["peer_id"])
            if index == 0:
                first_closed_id = peer["peer_id"]
            writer.write(Frame(1, M.CHANNEL_CLOSE, (TLV.integer(T.ECM_CHANNEL_ID, 7),)).encode())
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            writer.close()
            await writer.wait_closed()
        peers = self.server.diagnostics()["peers"]
        self.assertEqual(len(peers), RECENT_PEER_LIMIT + 1)
        self.assertEqual(peers[0]["peer_id"], active_id)
        self.assertNotIn(first_closed_id, {peer["peer_id"] for peer in peers})
        for peer in peers[1:]:
            self.assertFalse(peer["connected"])
            self.assertGreaterEqual(peer["disconnected_at"], peer["connected_at"])

    async def test_ram_journal_retention_and_peer_filter(self):
        one = _Peer(address="127.0.0.1:10001", channel_id=7, version=1, streams={9: 101})
        two = _Peer(address="127.0.0.1:10002", channel_id=7, version=1, streams={9: 101})
        for cp in range(ECM_LOG_LIMIT + 5):
            frame = Frame(1, M.CW_PROVISION, (TLV.integer(T.ECM_CHANNEL_ID, 7),
                          TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.CP_NUMBER, cp),
                          TLV.integer(T.ACCESS_CRITERIA, 1, 4),
                          cp_cw_parameter(cp, bytes(range(8))), cp_cw_parameter(cp + 1, bytes(range(8, 16)))))
            self.server._handle(one if cp % 2 else two, frame)
        result = self.server.diagnostics(limit=100000)
        self.assertEqual(len(result["entries"]), ECM_LOG_LIMIT)
        self.assertEqual(result["retention_limit"], ECM_LOG_LIMIT)
        self.assertEqual(result["entries"][0]["seq"], ECM_LOG_LIMIT + 5)
        self.assertEqual(result["entries"][-1]["seq"], 6)
        filtered = self.server.diagnostics(one.peer_id, limit=9)["entries"]
        self.assertEqual(len(filtered), 9)
        self.assertTrue(all(row["peer_id"] == one.peer_id for row in filtered))
        self.assertEqual([row["seq"] for row in filtered], sorted([row["seq"] for row in filtered], reverse=True))

    async def test_fragmented_and_coalesced_requests(self):
        setup = Frame(1, M.CHANNEL_SETUP, (TLV.integer(T.ECM_CHANNEL_ID, 7),
                                          TLV.integer(T.SUPER_CAS_ID, 0x0B000001, 4))).encode()
        for byte in setup:
            self.writer.write(bytes([byte]))
            await self.writer.drain()
        self.assertEqual((await self.receive()).message_type, M.CHANNEL_STATUS)
        test = Frame(1, M.CHANNEL_TEST, (TLV.integer(T.ECM_CHANNEL_ID, 7),)).encode()
        self.writer.write(test + test)
        self.assertEqual((await self.receive()).message_type, M.CHANNEL_STATUS)
        self.assertEqual((await self.receive()).message_type, M.CHANNEL_STATUS)

    async def test_peers_have_independent_channels_and_streams(self):
        await self.establish()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.server.status()["addresses"][0][1])
        try:
            writer.write(Frame(1, M.CHANNEL_SETUP, (TLV.integer(T.ECM_CHANNEL_ID, 7),
                                                   TLV.integer(T.SUPER_CAS_ID, 0x0B000001, 4))).encode())
            self.assertEqual((await self.receive(reader)).message_type, M.CHANNEL_STATUS)
            self.assertEqual(self.server.status()["clients"], 2)
            writer.write(Frame(1, M.STREAM_TEST, (TLV.integer(T.ECM_CHANNEL_ID, 7), TLV.integer(T.ECM_STREAM_ID, 9))).encode())
            self.assertEqual((await self.receive(reader)).integer(T.ERROR_STATUS), 7)
        finally:
            writer.close()
            await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
