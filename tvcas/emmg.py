"""TVCAS3 EMMG client. ETSI TS 103 197 section 6, TCP section transport.

The original application is copyright 2018-2020 TVCAS.COM, GPL-3.0-or-later.
Private payloads remain card compatible. No card keys or EMM bytes are logged.
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable

from .crypto import build_emm
from .simulcrypt import Frame, TLV, decode_frame, ProtocolError
from .simulcrypt import EMMGMessage as M, EMMGTag as T


def eligible_cards(cards, now: int):
    """Match PHP cache selection AND its subsequent expiration check.

    A recently edited future entitlement is sent before its start date. An
    expired row can enter the PHP cache, but PHP's queue discards it again.
    status/network_id/uid are deliberately not new entitlement filters.
    """
    return sorted((c for c in cards
                   if int(c.get("finish") or 0) >= now
                   and (int(c.get("edit") or 0) > now - 7 * 86400
                        or int(c.get("start") or 0) < now < int(c.get("finish") or 0))),
                  key=lambda c: int(c.get("edit") or 0), reverse=True)


class EMMGClient:
    def __init__(self, config: dict, cards: Callable[[], list[dict]], *,
                 timezone_offset_minutes=0, log_callback=None):
        self.config = dict(config)
        self.cards = cards
        self.timezone_offset_minutes = timezone_offset_minutes
        self.log_callback = log_callback
        self.version = int(config.get("protocol_version", 2))
        if self.version not in (1, 2, 3):
            raise ValueError("EMMG protocol version must be 1, 2 or 3")
        if int(config.get("packet_mode", 0)) != 0:
            raise ValueError("EMMG supports section mode 0; packet mode is not enabled")
        self.client_id = int(config["client_id"])
        self.channel_id = int(config.get("data_channel_id", 1))
        self.stream_id = int(config.get("data_stream_id", 1))
        self.data_id = int(config.get("data_id", 1))
        self._task = None
        self._writer = None
        self._reload = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._stats = {"state": "stopped", "datagram_count": 0, "queue_size": 0,
                       "error_count": 0, "last_error": None, "bandwidth_kbps": 0}
        self._bandwidth = int(config.get("bandwidth", 64))
        self._last_rx = 0.0

    def status(self):
        return dict(self._stats)

    async def start(self):
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def close(self):
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        self._stats["state"] = "stopped"

    def reload_cards(self):
        self._reload.set()

    def _common(self, stream=False):
        params = [TLV.integer(T.CLIENT_ID, self.client_id, 4),
                  TLV.integer(T.DATA_CHANNEL_ID, self.channel_id)]
        if stream:
            params.append(TLV.integer(T.DATA_STREAM_ID, self.stream_id))
        return params

    def _channel(self, message):
        return Frame(self.version, message, self._common() + [
            TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)])

    def _stream(self, message):
        return Frame(self.version, message, self._common(True) + [
            TLV.integer(T.DATA_ID, self.data_id), TLV.integer(T.DATA_TYPE, 0, 1)])

    async def _send(self, frame):
        async with self._send_lock:
            self._writer.write(frame.encode())
            await asyncio.wait_for(self._writer.drain(), 10)

    async def _read(self, reader):
        header = await reader.readexactly(5)
        size = int.from_bytes(header[3:5], "big")
        frame = decode_frame(header + await reader.readexactly(size))
        if frame.version != self.version:
            raise ProtocolError("EMMG peer protocol version mismatch")
        if frame.integer(T.CLIENT_ID, 4) != self.client_id:
            raise ProtocolError("EMMG peer client ID mismatch")
        if frame.integer(T.DATA_CHANNEL_ID) != self.channel_id:
            raise ProtocolError("EMMG peer channel ID mismatch")
        if frame.message_type >= 0x100 and frame.integer(T.DATA_STREAM_ID) != self.stream_id:
            raise ProtocolError("EMMG peer stream ID mismatch")
        self._last_rx = time.monotonic()
        return frame

    async def _handle(self, frame):
        if frame.message_type == M.CHANNEL_TEST:
            await self._send(self._channel(M.CHANNEL_STATUS))
        elif frame.message_type == M.STREAM_TEST:
            await self._send(self._stream(M.STREAM_STATUS))
        elif frame.message_type == M.CHANNEL_STATUS:
            if frame.integer(T.SECTION_TSPKT_FLAG, 1) != 0:
                raise ProtocolError("MUX did not accept EMM section mode")
        elif frame.message_type == M.STREAM_STATUS:
            if frame.integer(T.DATA_ID) != self.data_id or frame.integer(T.DATA_TYPE, 1) != 0:
                raise ProtocolError("MUX stream status does not match EMM stream")
        elif frame.message_type == M.STREAM_BW_ALLOCATION:
            # Absent means unknown, not zero; keep the requested ceiling.
            allocation = (frame.integer(T.BANDWIDTH) if frame.get(T.BANDWIDTH) is not None
                          else int(self.config.get("bandwidth", 64)))
            self._bandwidth = min(allocation, int(self.config.get("bandwidth", 64)))
            self._stats["bandwidth_kbps"] = self._bandwidth
        elif frame.message_type in (M.CHANNEL_ERROR, M.STREAM_ERROR):
            codes = [int.from_bytes(v, "big") for v in frame.get_all(T.ERROR_STATUS)]
            raise ProtocolError("MUX reported error codes " + ",".join(map(str, codes)))
        elif frame.message_type in (M.CHANNEL_CLOSE, M.STREAM_CLOSE_RESPONSE):
            raise ConnectionError("MUX closed EMM channel")
        else:
            raise ProtocolError("Unexpected EMMG message type")

    async def _expect(self, reader, expected):
        async def receive_expected():
            while True:
                frame = await self._read(reader)
                await self._handle(frame)
                if frame.message_type == expected:
                    return

        # Bound the entire handshake step, including unsolicited peer tests.
        # asyncio.timeout() is only available in Python 3.11 and later.
        await asyncio.wait_for(receive_expected(), max(5, int(self.config.get("timeout") or 10)))

    async def _run(self):
        retry = 1
        while True:
            try:
                self._stats["state"] = "connecting"
                reader, self._writer = await asyncio.wait_for(asyncio.open_connection(
                    self.config["host"], int(self.config["port"])), 10)
                await self._send(self._channel(M.CHANNEL_SETUP))
                await self._expect(reader, M.CHANNEL_STATUS)
                self._stats["channel_time_open"] = int(time.time())
                await self._send(self._stream(M.STREAM_SETUP))
                await self._expect(reader, M.STREAM_STATUS)
                self._stats["stream_time_open"] = int(time.time())
                await self._send(Frame(self.version, M.STREAM_BW_REQUEST,
                    self._common(True) + [TLV.integer(T.BANDWIDTH, int(self.config.get("bandwidth", 64)))]))
                await self._expect(reader, M.STREAM_BW_ALLOCATION)
                self._stats.update(state="connected", last_error=None)
                retry = 1
                tasks = [asyncio.create_task(self._receive(reader)),
                         asyncio.create_task(self._emit()),
                         asyncio.create_task(self._heartbeat())]
                try:
                    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        task.result()
                    raise ConnectionError("EMMG session ended")
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
            except (OSError, ConnectionError, asyncio.IncompleteReadError,
                    asyncio.TimeoutError, ValueError) as exc:
                self._stats["error_count"] += 1
                self._stats["last_error"] = str(exc) if isinstance(exc, ProtocolError) else type(exc).__name__
                self._stats["state"] = "reconnecting"
                if self.log_callback:
                    self.log_callback("EMMG connection failed: " + self._stats["last_error"])
            finally:
                if self._writer:
                    self._writer.close()
                    with contextlib.suppress(OSError):
                        await self._writer.wait_closed()
                    self._writer = None
            await asyncio.sleep(retry)
            retry = min(30, retry * 2)

    async def _receive(self, reader):
        while True:
            await self._handle(await self._read(reader))

    async def _heartbeat(self):
        channel_delay = max(1, int(self.config.get("channel_test_delay") or 60))
        stream_delay = max(1, int(self.config.get("stream_test_delay") or 60))
        next_channel = time.monotonic() + channel_delay
        next_stream = time.monotonic() + stream_delay
        while True:
            await asyncio.sleep(min(channel_delay, stream_delay, 5))
            now = time.monotonic()
            if now >= next_channel:
                await self._send(Frame(self.version, M.CHANNEL_TEST, self._common()))
                next_channel = now + channel_delay
            if now >= next_stream:
                await self._send(Frame(self.version, M.STREAM_TEST, self._common(True)))
                next_stream = now + stream_delay
            timeout = int(self.config.get("timeout") or max(channel_delay, stream_delay) * 2 + 10)
            if now - self._last_rx > timeout:
                raise asyncio.TimeoutError("EMMG peer did not respond")

    def _queue(self):
        queue = []
        invalid = 0
        for card in eligible_cards(self.cards(), int(time.time())):
            try:
                queue.append((int(card["finish"]), build_emm(
                    int(card["serial_no"]), int(card["access_criteria"], 16), card["key"],
                    int(card["start"]), int(card["finish"]), pair=int(card.get("pair", 0)),
                    type_flag=int(card.get("type", 1)),
                    timezone_offset_minutes=self.timezone_offset_minutes)))
            except (KeyError, ValueError, TypeError):
                # A single incomplete legacy record must not stop other entitlements.
                invalid += 1
        self._stats["invalid_cards"] = invalid
        return queue

    async def _emit(self):
        queue, index, refreshed, next_send = [], 0, float("-inf"), 0.0
        while True:
            now = time.monotonic()
            if self._reload.is_set() or now - refreshed >= max(1, int(self.config.get("reload_sec") or 300)):
                self._reload.clear()
                queue, index, refreshed = self._queue(), 0, now
                self._stats["queue_size"] = len(queue)
            if queue and self._bandwidth > 0 and now >= next_send:
                finish, section = queue[index % len(queue)]
                index += 1
                if finish >= int(time.time()):
                    frame = Frame(self.version, M.DATA_PROVISION,
                                  self._common(True) + [TLV.integer(T.DATA_ID, self.data_id),
                                                        TLV(T.DATAGRAM, section)])
                    await self._send(frame)
                    self._stats["datagram_count"] += 1
                    self._stats["datagram_time_last"] = int(time.time())
                    # Include framing overhead: conservative wrt negotiated data rate.
                    bandwidth_delay = len(frame.encode()) * 8 / (self._bandwidth * 1000)
                    repetition_delay = min(10, max(60, int(self.config.get("repetition", 60))) / len(queue))
                    next_send = time.monotonic() + max(repetition_delay, bandwidth_delay)
                else:
                    queue = [(expires, payload) for expires, payload in queue if expires >= int(time.time())]
                    self._stats["queue_size"] = len(queue)
                    index = 0
            delay = (min(1.0, max(0.05, next_send - time.monotonic()))
                     if queue and self._bandwidth > 0 else 1.0)
            try:
                await asyncio.wait_for(self._reload.wait(), delay)
            except asyncio.TimeoutError:
                pass
