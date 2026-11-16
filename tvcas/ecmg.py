"""Async TVCAS3 ECMG service; no scrambler or production process is started on import."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
import ipaddress
import time
import uuid

from .crypto import build_ecm_for_cp
from .simulcrypt import ECMGMessage as M, ECMGTag as T, Frame, ProtocolError, TLV, cp_cw_combinations, decode_frame

ECM_LOG_LIMIT = 1000
RECENT_PEER_LIMIT = 64


def _reduce_csa_word(word: bytes) -> bytes:
    """Match DVB-CSA's conventional 48-bit entropy key representation."""
    if len(word) != 8:
        raise ValueError("DVB-CSA control word must contain 8 bytes")
    reduced = bytearray(word)
    reduced[3] = sum(reduced[:3]) & 0xFF
    reduced[7] = sum(reduced[4:7]) & 0xFF
    return bytes(reduced)


class _RequestError(Exception):
    def __init__(self, code: int):
        self.code = code


@dataclass
class _Peer:
    peer_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    address: str = ""
    connected_at: float = field(default_factory=time.time)
    last_seen: float | None = None
    disconnected_at: float | None = None
    channel_id: int | None = None
    version: int | None = None
    streams: dict[int, int | None] = field(default_factory=dict)
    cw_count: int = 0
    ecm_count: int = 0


class ECMGServer:
    """TVCAS legacy configuration dict -> asynchronous ECMG/SCS TCP server.

    Config keys mirror tvcas_ecmg: host, port, key (32-byte hex), timeout,
    packet_mode, delay_start/stop, transition_delay_start/stop, ac_delay_start/
    stop, repetition_period, min_cp_duration, max_compute_time. ``super_cas_id``
    optionally restricts clients; PHP accepted any value. The supplied/live
    implementation uses section mode 0; reject other modes until that profile
    is explicitly deployed and validated. No key or CW enters text logs/status.

    ``log_callback`` accepts a short text string. status() returns counters
    and bind addresses, never config secrets. Explicit diagnostics() includes a
    bounded RAM-only CW journal for the authenticated administrator. Default
    bind is loopback.

    ``csa_entropy_reduction`` defaults to False. Enable it only when the
    scrambler sends unreduced CWs but actually uses their reduced DVB-CSA
    form (for example TSDuck 3.33's default scrambling mode).
    """

    def __init__(self, config: dict, log_callback=None):
        self.config = dict(config)
        self._log_callback = log_callback
        self._server = None
        self._writers = set()
        self._tasks = set()
        self._peers = {}
        self._recent_peers = deque(maxlen=RECENT_PEER_LIMIT)
        self._entries = deque(maxlen=ECM_LOG_LIMIT)
        self._entry_seq = 0
        self._cw_count = 0
        self._ecm_count = 0
        self._errors = 0
        self._last_ecm = None
        self._started_at = None
        try:
            value = self.config["key"]
            self._key = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
        except (KeyError, TypeError, ValueError):
            raise ValueError("ECMG requires a 32-byte master key") from None
        if len(self._key) != 32:
            raise ValueError("ECMG requires a 32-byte master key")
        if int(self.config.get("packet_mode", 0)) != 0:
            raise ValueError("this TVCAS3 ECMG profile supports section packet_mode=0 only")
        reduction = self.config.get("csa_entropy_reduction", False)
        if type(reduction) not in (bool, int) or reduction not in (0, 1):
            raise ValueError("csa_entropy_reduction must be a boolean or 0/1")
        self._csa_entropy_reduction = bool(reduction)
        self.timeout = float(self.config.get("timeout", 30))
        if self.timeout <= 0:
            raise ValueError("ECMG timeout must be positive")
        self.max_streams = int(self.config.get("max_streams", 256))
        self.max_clients = int(self.config.get("max_clients", 64))
        if not 1 <= self.max_streams <= 65535 or not 1 <= self.max_clients <= 65535:
            raise ValueError("invalid ECMG stream/client limit")
        # Validate advertised parameters before binding, rather than after a peer connects.
        self._channel_status(1, 0).encode()

    def _log(self, message: str):
        if self._log_callback:
            try:
                self._log_callback(message)
            except Exception:
                pass  # A failed status sink must not interrupt ECM generation.

    async def start(self):
        if self._server is not None:
            return
        host = self.config.get("bind_host", self.config.get("host", "127.0.0.1"))
        if isinstance(host, int) or str(host).isdigit():
            host = str(ipaddress.IPv4Address(int(host)))
        self._server = await asyncio.start_server(self._accept, host, int(self.config.get("port", 43000)), limit=65540)
        self._started_at = time.time()
        self._log("ECMG listener started")

    async def close(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for writer in tuple(self._writers):
            writer.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._log("ECMG listener stopped")

    def status(self) -> dict:
        addresses = [sock.getsockname()[:2] for sock in self._server.sockets] if self._server else []
        return {
            "running": self._server is not None,
            "addresses": addresses,
            "clients": len(self._peers),
            "channels": sum(peer.channel_id is not None for peer in self._peers.values()),
            "streams": sum(len(peer.streams) for peer in self._peers.values()),
            "cw_count": self._cw_count,
            "ecm_count": self._ecm_count,
            "errors": self._errors,
            "last_ecm": self._last_ecm,
            "started_at": self._started_at,
            "peers": self._peer_infos(),
        }

    @staticmethod
    def _peer_info(peer):
        return {
            "peer_id": peer.peer_id,
            "address": peer.address,
            "connected_at": peer.connected_at,
            "last_seen": peer.last_seen,
            "disconnected_at": peer.disconnected_at,
            "connected": peer.disconnected_at is None,
            "channel_id": peer.channel_id,
            "streams": len(peer.streams),
            "cw_count": peer.cw_count,
            "ecm_count": peer.ecm_count,
        }

    def _peer_infos(self):
        peers = [self._peer_info(peer) for peer in self._peers.values()]
        peers.extend(dict(peer) for peer in self._recent_peers)
        return sorted(peers, key=lambda peer: (peer["connected"], peer["connected_at"]), reverse=True)

    def diagnostics(self, peer_id=None, limit=100):
        """Private, bounded snapshot; call on the owning event-loop thread.

        cw1/cw2 retain PHP's log order: the odd/even words placed in the ECM,
        not necessarily the order of the two incoming CW parameters. Nothing
        from this journal is included in public status or ordinary logging.
        """
        limit = min(ECM_LOG_LIMIT, max(1, int(limit)))
        entries = []
        for entry in reversed(self._entries):
            if peer_id is None or entry["peer_id"] == peer_id:
                entries.append(dict(entry))
                if len(entries) == limit:
                    break
        return {"running": self._server is not None, "peers": self._peer_infos(),
                "entries": entries, "retention_limit": ECM_LOG_LIMIT}

    async def _send(self, writer, frame):
        writer.write(frame.encode())
        await asyncio.wait_for(writer.drain(), self.timeout)

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        self._writers.add(writer)
        endpoint = writer.get_extra_info("peername")
        address = ""
        if endpoint:
            host, port = str(endpoint[0]), endpoint[1]
            address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        now = time.time()
        peer = _Peer(address=address, connected_at=now, last_seen=now)
        try:
            if len(self._peers) >= self.max_clients:
                return
            self._peers[writer] = peer
            self._log("ECMG client connected")
            tested = False
            while True:
                try:
                    header = await asyncio.wait_for(reader.readexactly(5), self.timeout)
                except asyncio.TimeoutError:
                    if peer.channel_id is None or tested:
                        break
                    await self._send(writer, Frame(peer.version, M.CHANNEL_TEST, (TLV.integer(T.ECM_CHANNEL_ID, peer.channel_id),)))
                    tested = True
                    continue
                size = int.from_bytes(header[3:5], "big")
                # A body timeout closes the connection: the header is consumed.
                payload = await asyncio.wait_for(reader.readexactly(size), self.timeout)
                peer.last_seen = time.time()
                tested = False
                try:
                    frame = decode_frame(header + payload)
                except ProtocolError:
                    self._errors += 1
                    await self._send(writer, self._error(peer, None, 0x0001))
                    break
                try:
                    response, close = self._handle(peer, frame)
                except _RequestError as error:
                    self._errors += 1
                    response, close = self._error(peer, frame, error.code), False
                except (ProtocolError, ValueError, TypeError):
                    self._errors += 1
                    response, close = self._error(peer, frame, 0x0011), False
                if response is not None:
                    await self._send(writer, response)
                if close:
                    break
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            if self._peers.pop(writer, None) is not None:
                peer.disconnected_at = time.time()
                self._recent_peers.append(self._peer_info(peer))
            self._writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, asyncio.CancelledError):
                pass
            self._tasks.discard(task)
            self._log("ECMG client disconnected")

    @staticmethod
    def _integer(frame, tag, width=2):
        value = frame.get(tag)
        if value is None:
            raise _RequestError(0x0010)
        if len(value) != width:
            raise _RequestError(0x000F)
        return int.from_bytes(value, "big")

    def _channel_status(self, version, channel_id):
        parameters = [TLV.integer(T.ECM_CHANNEL_ID, channel_id), TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)]
        for tag, name in ((T.DELAY_START, "delay_start"), (T.DELAY_STOP, "delay_stop"),
                          (T.TRANSITION_DELAY_START, "transition_delay_start"),
                          (T.TRANSITION_DELAY_STOP, "transition_delay_stop")):
            parameters.append(TLV.integer(tag, int(self.config.get(name, 0)), signed=True))
        for tag, name, default in ((T.ECM_REP_PERIOD, "repetition_period", 100),
                                   (T.MAX_STREAMS, "max_streams", 256),
                                   (T.MIN_CP_DURATION, "min_cp_duration", 10)):
            parameters.append(TLV.integer(tag, int(self.config.get(name, default))))
        parameters += [TLV.integer(T.LEAD_CW, 1, 1), TLV.integer(T.CW_PER_MSG, 2, 1),
                       TLV.integer(T.MAX_COMP_TIME, int(self.config.get("max_compute_time", 100)))]
        for tag, name in ((T.AC_DELAY_START, "ac_delay_start"), (T.AC_DELAY_STOP, "ac_delay_stop")):
            if int(self.config.get(name, 0)):
                parameters.append(TLV.integer(tag, int(self.config[name]), signed=True))
        return Frame(version, M.CHANNEL_STATUS, tuple(parameters))

    @staticmethod
    def _stream_status(peer, stream_id):
        parameters = [TLV.integer(T.ECM_CHANNEL_ID, peer.channel_id), TLV.integer(T.ECM_STREAM_ID, stream_id)]
        ecm_id = peer.streams[stream_id]
        if ecm_id is not None:
            parameters.append(TLV.integer(T.ECM_ID, ecm_id))
        parameters.append(TLV.integer(T.ACCESS_CRITERIA_TRANSFER_MODE, 1, 1))
        return Frame(peer.version, M.STREAM_STATUS, tuple(parameters))

    @staticmethod
    def _error(peer, request, code):
        version = peer.version or (request.version if request and request.version in (1, 2, 3) else 1)
        channel_id = peer.channel_id if peer.channel_id is not None else 0
        stream_id = None
        if request:
            try:
                raw = request.get(T.ECM_CHANNEL_ID)
                if raw is not None and len(raw) == 2:
                    channel_id = int.from_bytes(raw, "big")
                raw = request.get(T.ECM_STREAM_ID)
                if raw is not None and len(raw) == 2:
                    stream_id = int.from_bytes(raw, "big")
            except ProtocolError:
                pass
        fields = [TLV.integer(T.ECM_CHANNEL_ID, channel_id)]
        if stream_id is not None:
            fields.append(TLV.integer(T.ECM_STREAM_ID, stream_id))
        fields.append(TLV.integer(T.ERROR_STATUS, code))
        return Frame(version, M.STREAM_ERROR if stream_id is not None else M.CHANNEL_ERROR, tuple(fields))

    def _handle(self, peer, frame):
        if frame.version not in (1, 2, 3) or (peer.version is not None and frame.version != peer.version):
            raise _RequestError(0x0002)
        if frame.message_type not in M._value2member_map_:
            raise _RequestError(0x0003)
        channel_id = self._integer(frame, T.ECM_CHANNEL_ID)
        if frame.message_type == M.CHANNEL_SETUP:
            super_cas_id = self._integer(frame, T.SUPER_CAS_ID, 4)
            if self.config.get("super_cas_id") is not None and super_cas_id != int(self.config["super_cas_id"]):
                raise _RequestError(0x0005)
            if peer.channel_id is not None:
                raise _RequestError(0x0013)
            peer.channel_id, peer.version = channel_id, frame.version
            return self._channel_status(peer.version, channel_id), False
        if peer.channel_id is None or channel_id != peer.channel_id:
            raise _RequestError(0x0006)
        if frame.message_type == M.CHANNEL_TEST:
            return self._channel_status(peer.version, channel_id), False
        if frame.message_type == M.CHANNEL_CLOSE:
            return None, True
        if frame.message_type == M.CHANNEL_STATUS:
            return None, False  # reply to our idle keepalive
        if frame.message_type == M.CHANNEL_ERROR:
            return None, True
        stream_id = self._integer(frame, T.ECM_STREAM_ID)
        if frame.message_type == M.STREAM_SETUP:
            if stream_id in peer.streams:
                raise _RequestError(0x0014)
            if len(peer.streams) >= self.max_streams:
                raise _RequestError(0x0009)
            # Legacy PHP permits omitted ECM_id/nominal_CP_duration. Preserve
            # that handshake while validating either parameter if supplied.
            ecm_id = self._integer(frame, T.ECM_ID) if frame.get(T.ECM_ID) is not None else None
            if ecm_id is not None and ecm_id in peer.streams.values():
                raise _RequestError(0x0015)
            if frame.get(T.NOMINAL_CP_DURATION) is not None:
                self._integer(frame, T.NOMINAL_CP_DURATION)
            peer.streams[stream_id] = ecm_id
            return self._stream_status(peer, stream_id), False
        if stream_id not in peer.streams:
            raise _RequestError(0x0007)
        if frame.message_type == M.STREAM_TEST:
            return self._stream_status(peer, stream_id), False
        if frame.message_type == M.STREAM_CLOSE_REQUEST:
            del peer.streams[stream_id]
            return Frame(peer.version, M.STREAM_CLOSE_RESPONSE, (
                TLV.integer(T.ECM_CHANNEL_ID, channel_id), TLV.integer(T.ECM_STREAM_ID, stream_id))), False
        if frame.message_type == M.STREAM_ERROR:
            return None, False
        if frame.message_type != M.CW_PROVISION:
            raise _RequestError(0x0001)
        if frame.get(T.CW_ENCRYPTION) is not None:
            raise _RequestError(0x0011)  # Never interpret encrypted CWs as clear.
        cp = self._integer(frame, T.CP_NUMBER)
        access_criteria = self._integer(frame, T.ACCESS_CRITERIA, 4)
        words = cp_cw_combinations(frame)
        if len(words) != 2:
            raise _RequestError(0x000B)
        if self._csa_entropy_reduction:
            # Use the effective scrambling keys for both the ECM payload and
            # the administrator's journal. Never modify the incoming frame.
            words = [(number, _reduce_csa_word(word)) for number, word in words]
        ecm = build_ecm_for_cp(cp, words, self._key, access_criteria, int(time.time()),
                               cw_order=self.config.get("cw_order", "legacy"))
        peer.cw_count += 1
        peer.ecm_count += 1
        self._cw_count += 1
        self._ecm_count += 1
        self._last_ecm = time.time()
        if self.config.get("cw_order", "legacy") == "cp":
            by_parity = {number & 1: word for number, word in words}
            odd, even = by_parity[1], by_parity[0]
        else:
            first, second = words[0][1], words[1][1]
            odd, even = (first, second) if cp & 1 else (second, first)
        self._entry_seq += 1
        self._entries.append({
            "seq": self._entry_seq, "time": self._last_ecm,
            "peer_id": peer.peer_id, "address": peer.address,
            "channel_id": channel_id, "stream_id": stream_id, "cp_number": cp,
            "access_criteria": f"{access_criteria:08X}",
            "cw1": odd.hex().upper(), "cw2": even.hex().upper(),
        })
        return Frame(peer.version, M.ECM_RESPONSE, (
            TLV.integer(T.ECM_CHANNEL_ID, channel_id), TLV.integer(T.ECM_STREAM_ID, stream_id),
            TLV.integer(T.CP_NUMBER, cp), TLV(T.ECM_DATAGRAM, ecm))), False
