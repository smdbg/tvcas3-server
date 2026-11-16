"""Bounded DVB SimulCrypt TLV framing for ECMG/SCS and EMMG/MUX.

ETSI TS 103 197 V1.5.1, clauses 4.4.1, 5 and 6. Only encoding/decoding is
implemented here; connection state, policy and sockets belong to the service.
Unknown parameters are preserved, repeated parameters retain their wire order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import struct


class ProtocolError(ValueError):
    """Malformed or ambiguous SimulCrypt message; no payload is included."""


class ECMGMessage(IntEnum):
    CHANNEL_SETUP = 0x0001
    CHANNEL_TEST = 0x0002
    CHANNEL_STATUS = 0x0003
    CHANNEL_CLOSE = 0x0004
    CHANNEL_ERROR = 0x0005
    STREAM_SETUP = 0x0101
    STREAM_TEST = 0x0102
    STREAM_STATUS = 0x0103
    STREAM_CLOSE_REQUEST = 0x0104
    STREAM_CLOSE_RESPONSE = 0x0105
    STREAM_ERROR = 0x0106
    CW_PROVISION = 0x0201
    ECM_RESPONSE = 0x0202


class EMMGMessage(IntEnum):
    CHANNEL_SETUP = 0x0011
    CHANNEL_TEST = 0x0012
    CHANNEL_STATUS = 0x0013
    CHANNEL_CLOSE = 0x0014
    CHANNEL_ERROR = 0x0015
    STREAM_SETUP = 0x0111
    STREAM_TEST = 0x0112
    STREAM_STATUS = 0x0113
    STREAM_CLOSE_REQUEST = 0x0114
    STREAM_CLOSE_RESPONSE = 0x0115
    STREAM_ERROR = 0x0116
    STREAM_BW_REQUEST = 0x0117
    STREAM_BW_ALLOCATION = 0x0118
    DATA_PROVISION = 0x0211


class ECMGTag(IntEnum):
    SUPER_CAS_ID = 0x0001
    SECTION_TSPKT_FLAG = 0x0002
    DELAY_START = 0x0003
    DELAY_STOP = 0x0004
    TRANSITION_DELAY_START = 0x0005
    TRANSITION_DELAY_STOP = 0x0006
    ECM_REP_PERIOD = 0x0007
    MAX_STREAMS = 0x0008
    MIN_CP_DURATION = 0x0009
    LEAD_CW = 0x000A
    CW_PER_MSG = 0x000B
    MAX_COMP_TIME = 0x000C
    ACCESS_CRITERIA = 0x000D
    ECM_CHANNEL_ID = 0x000E
    ECM_STREAM_ID = 0x000F
    NOMINAL_CP_DURATION = 0x0010
    ACCESS_CRITERIA_TRANSFER_MODE = 0x0011
    CP_NUMBER = 0x0012
    CP_DURATION = 0x0013
    CP_CW_COMBINATION = 0x0014
    ECM_DATAGRAM = 0x0015
    AC_DELAY_START = 0x0016
    AC_DELAY_STOP = 0x0017
    CW_ENCRYPTION = 0x0018
    ECM_ID = 0x0019
    ERROR_STATUS = 0x7000
    ERROR_INFORMATION = 0x7001


class EMMGTag(IntEnum):
    CLIENT_ID = 0x0001
    SECTION_TSPKT_FLAG = 0x0002
    DATA_CHANNEL_ID = 0x0003
    DATA_STREAM_ID = 0x0004
    DATAGRAM = 0x0005
    BANDWIDTH = 0x0006
    DATA_TYPE = 0x0007
    DATA_ID = 0x0008
    ERROR_STATUS = 0x7000
    ERROR_INFORMATION = 0x7001


def _uint(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ProtocolError(f"{name} must be an unsigned {bits}-bit integer")
    return value


@dataclass(frozen=True)
class TLV:
    tag: int
    value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _uint(self.tag, 16, "tag")
        if not isinstance(self.value, bytes) or len(self.value) > 65535:
            raise ProtocolError("parameter must contain at most 65535 bytes")

    @classmethod
    def integer(cls, tag: int, value: int, width: int = 2, *, signed: bool = False) -> TLV:
        if width not in (1, 2, 4) or not isinstance(value, int):
            raise ProtocolError("integer parameter width must be 1, 2 or 4 bytes")
        try:
            return cls(tag, value.to_bytes(width, "big", signed=signed))
        except OverflowError:
            raise ProtocolError("integer parameter is outside its declared range") from None

    def encode(self) -> bytes:
        return struct.pack("!HH", self.tag, len(self.value)) + self.value


@dataclass(frozen=True)
class Frame:
    version: int
    message_type: int
    parameters: tuple[TLV, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.version, 8, "version")
        _uint(self.message_type, 16, "message_type")
        object.__setattr__(self, "parameters", tuple(self.parameters))
        if any(not isinstance(value, TLV) for value in self.parameters):
            raise ProtocolError("parameters must be TLV objects")

    def encode(self) -> bytes:
        payload = b"".join(value.encode() for value in self.parameters)
        if len(payload) > 65535:
            raise ProtocolError("message payload exceeds 65535 bytes")
        return struct.pack("!BHH", self.version, self.message_type, len(payload)) + payload

    def get_all(self, tag: int) -> tuple[bytes, ...]:
        return tuple(value.value for value in self.parameters if value.tag == tag)

    def get(self, tag: int, default: bytes | None = None) -> bytes | None:
        values = self.get_all(tag)
        if len(values) > 1:
            raise ProtocolError(f"duplicate singleton parameter 0x{tag:04x}")
        return values[0] if values else default

    def require(self, tag: int) -> bytes:
        value = self.get(tag)
        if value is None:
            raise ProtocolError(f"missing parameter 0x{tag:04x}")
        return value

    def integer(self, tag: int, width: int = 2, *, signed: bool = False) -> int:
        value = self.require(tag)
        if width not in (1, 2, 4) or len(value) != width:
            raise ProtocolError(f"invalid length for parameter 0x{tag:04x}")
        return int.from_bytes(value, "big", signed=signed)


def decode_frame(data: bytes, *, max_payload: int = 65535) -> Frame:
    """Decode exactly one frame, rejecting truncation and trailing bytes."""
    if len(data) < 5:
        raise ProtocolError("truncated message header")
    version, message_type, length = struct.unpack_from("!BHH", data)
    if length > max_payload:
        raise ProtocolError("message payload exceeds configured limit")
    if len(data) != 5 + length:
        raise ProtocolError("message length does not match frame length")
    parameters = []
    offset = 5
    while offset < len(data):
        if len(data) - offset < 4:
            raise ProtocolError("truncated parameter header")
        tag, size = struct.unpack_from("!HH", data, offset)
        offset += 4
        if size > len(data) - offset:
            raise ProtocolError("parameter exceeds message boundary")
        parameters.append(TLV(tag, bytes(data[offset:offset + size])))
        offset += size
    return Frame(version, message_type, tuple(parameters))


class FrameDecoder:
    """TCP decoder accepting fragmented headers/payloads or coalesced frames.

    Buffered partial state is bounded to a single frame. A protocol error
    clears that state; the caller should close the offending connection.
    """

    def __init__(self, max_payload: int = 65535):
        _uint(max_payload, 16, "max_payload")
        self.max_payload = max_payload
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[Frame]:
        result = []
        view = memoryview(chunk)
        try:
            while view:
                target = 5
                if len(self._buffer) >= 5:
                    length = struct.unpack_from("!H", self._buffer, 3)[0]
                    if length > self.max_payload:
                        raise ProtocolError("message payload exceeds configured limit")
                    target += length
                take = min(target - len(self._buffer), len(view))
                self._buffer.extend(view[:take])
                view = view[take:]
                if len(self._buffer) < 5:
                    continue
                length = struct.unpack_from("!H", self._buffer, 3)[0]
                if length > self.max_payload:
                    raise ProtocolError("message payload exceeds configured limit")
                if len(self._buffer) == length + 5:
                    result.append(decode_frame(bytes(self._buffer), max_payload=self.max_payload))
                    self._buffer.clear()
            return result
        except ProtocolError:
            self._buffer.clear()
            raise

    def eof(self) -> None:
        if self._buffer:
            self._buffer.clear()
            raise ProtocolError("connection closed with an incomplete frame")


def cp_cw_parameter(cp_number: int, cw: bytes) -> TLV:
    _uint(cp_number, 16, "cp_number")
    if not isinstance(cw, bytes) or len(cw) != 8:
        raise ProtocolError("TVCAS3 requires an 8-byte DVB-CSA control word")
    return TLV(ECMGTag.CP_CW_COMBINATION, struct.pack("!H", cp_number) + cw)


def cp_cw_combinations(frame: Frame) -> tuple[tuple[int, bytes], ...]:
    result = []
    for value in frame.get_all(ECMGTag.CP_CW_COMBINATION):
        if len(value) != 10:
            raise ProtocolError("TVCAS3 CP/CW parameter must contain 10 bytes")
        result.append((int.from_bytes(value[:2], "big"), value[2:]))
    return tuple(result)


def packetize_section(section: bytes, pid: int, continuity_counter: int = 0) -> tuple[bytes, int]:
    """Wrap one section in 188-byte TS packets, returning next continuity CC.

    Used only when section_TSpkt_flag=1 is negotiated. The first packet has
    PUSI and a zero pointer field; unused payload bytes are 0xff stuffing.
    """
    if not 0 <= pid <= 0x1FFE or not 0 <= continuity_counter <= 15:
        raise ProtocolError("invalid TS PID or continuity counter")
    if len(section) < 3 or (int.from_bytes(section[1:3], "big") & 0xFFF) + 3 != len(section):
        raise ProtocolError("invalid section length")
    remaining = section
    result = bytearray()
    first = True
    cc = continuity_counter
    while remaining:
        payload = b"\x00" if first else b""
        amount = 184 - len(payload)
        payload += remaining[:amount]
        remaining = remaining[amount:]
        result.extend(bytes([0x47, (pid >> 8) | (0x40 if first else 0), pid & 0xFF, 0x10 | cc]))
        result.extend(payload.ljust(184, b"\xff"))
        cc = (cc + 1) & 15
        first = False
    return bytes(result), cc
