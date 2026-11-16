"""EMMG acceptance tests against an independent loopback MUX peer.

No production address, card, key, or entitlement is used here.
"""
import asyncio
import contextlib
import time
from types import SimpleNamespace

import pytest

from tvcas.emmg import EMMGClient, eligible_cards
from tvcas.simulcrypt import Frame, TLV, decode_frame
from tvcas.simulcrypt import EMMGMessage as M, EMMGTag as T

CLIENT_ID = 0x0B000001
SERIAL = 2100000999


def card(**overrides):
    now = int(time.time())
    result = dict(serial_no=SERIAL, key='0123456789abcdeffedcba9876543210',
                  access_criteria='00000005', start=now - 3600,
                  finish=now + 86400, edit=now, pair=0, type=1)
    result.update(overrides)
    return result


def config(port, **overrides):
    result = dict(host='127.0.0.1', port=port, client_id=CLIENT_ID,
                  protocol_version=2, packet_mode=0, bandwidth=64,
                  repetition=60, channel_test_delay=60, stream_test_delay=60,
                  timeout=60, reload_sec=300)
    result.update(overrides)
    return result


def mux_frame(message, *, stream=False, extra=(), client=CLIENT_ID,
              channel=1, stream_id=1, version=2):
    params = [TLV.integer(T.CLIENT_ID, client, 4), TLV.integer(T.DATA_CHANNEL_ID, channel)]
    if stream:
        params.append(TLV.integer(T.DATA_STREAM_ID, stream_id))
    return Frame(version, message, params + list(extra))


async def read_frame(reader, timeout=2):
    async def receive():
        header = await reader.readexactly(5)
        return decode_frame(header + await reader.readexactly(int.from_bytes(header[3:5], 'big')))
    return await asyncio.wait_for(receive(), timeout)


async def send_frame(writer, frame, fragmented=False):
    raw = frame.encode()
    if fragmented:
        for block in (raw[:1], raw[1:3], raw[3:7], raw[7:]):
            writer.write(block)
            await writer.drain()
            await asyncio.sleep(0)
    else:
        writer.write(raw)
        await writer.drain()


async def handshake(reader, writer, *, allocation=64, exercise_tests=False):
    frame = await read_frame(reader)
    assert frame.message_type == M.CHANNEL_SETUP
    assert frame.integer(T.CLIENT_ID, 4) == CLIENT_ID
    assert frame.integer(T.DATA_CHANNEL_ID) == 1
    assert frame.integer(T.SECTION_TSPKT_FLAG, 1) == 0
    if exercise_tests:
        await send_frame(writer, mux_frame(M.CHANNEL_TEST), True)
        status = await read_frame(reader)
        assert status.message_type == M.CHANNEL_STATUS
        assert status.integer(T.SECTION_TSPKT_FLAG, 1) == 0
    await send_frame(writer, mux_frame(M.CHANNEL_STATUS,
                     extra=[TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)]), True)
    frame = await read_frame(reader)
    assert frame.message_type == M.STREAM_SETUP
    assert frame.integer(T.DATA_STREAM_ID) == 1
    assert frame.integer(T.DATA_ID) == 1
    assert frame.integer(T.DATA_TYPE, 1) == 0
    if exercise_tests:
        await send_frame(writer, mux_frame(M.STREAM_TEST, stream=True), True)
        status = await read_frame(reader)
        assert status.message_type == M.STREAM_STATUS
        assert status.integer(T.DATA_ID) == 1
    await send_frame(writer, mux_frame(M.STREAM_STATUS, stream=True,
                     extra=[TLV.integer(T.DATA_ID, 1), TLV.integer(T.DATA_TYPE, 0, 1)]), True)
    frame = await read_frame(reader)
    assert frame.message_type == M.STREAM_BW_REQUEST
    assert frame.integer(T.BANDWIDTH) == 64
    extra = [] if allocation is None else [TLV.integer(T.BANDWIDTH, allocation)]
    await send_frame(writer, mux_frame(M.STREAM_BW_ALLOCATION, stream=True, extra=extra), True)


async def with_mux(peer, *, overrides=None, cards=None, timeout=5):
    loop = asyncio.get_running_loop()
    completed = loop.create_future()
    handlers = set()
    async def connected(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        try:
            result = await peer(reader, writer)
            if not completed.done():
                completed.set_result(result)
        except Exception as exc:
            if not completed.done():
                completed.set_exception(exc)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            handlers.discard(task)
    server = await asyncio.start_server(connected, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    client = EMMGClient(config(port, **(overrides or {})), lambda: cards or [card()])
    try:
        await client.start()
        result = await asyncio.wait_for(completed, timeout)
        return result, client.status()
    finally:
        await client.close()
        server.close()
        await server.wait_closed()
        for task in tuple(handlers):
            task.cancel()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)


def test_fragmented_handshake_peer_tests_and_real_emm_datagram():
    async def peer(reader, writer):
        await handshake(reader, writer, exercise_tests=True)
        frame = await read_frame(reader)
        assert frame.message_type == M.DATA_PROVISION
        assert frame.integer(T.CLIENT_ID, 4) == CLIENT_ID
        assert frame.integer(T.DATA_CHANNEL_ID) == 1
        assert frame.integer(T.DATA_STREAM_ID) == 1
        assert frame.integer(T.DATA_ID) == 1
        payload = frame.require(T.DATAGRAM)
        assert len(payload) == 62
        assert payload[:6] == b'\x82\x70\x3b\x00\x00\x00'
        assert int.from_bytes(payload[6:10], 'big') == SERIAL
        assert payload[10:14] == b'\x70\x32\x64\x10'
    _, status = asyncio.run(with_mux(peer))
    assert status['datagram_count'] == 1
    assert status['queue_size'] == 1


def test_zero_allocation_pauses_then_unsolicited_allocation_resumes():
    async def peer(reader, writer):
        await handshake(reader, writer, allocation=0)
        with pytest.raises(asyncio.TimeoutError):
            await read_frame(reader, timeout=0.15)
        await send_frame(writer, mux_frame(M.STREAM_BW_ALLOCATION, stream=True,
                          extra=[TLV.integer(T.BANDWIDTH, 32)]))
        frame = await read_frame(reader)
        assert frame.message_type == M.DATA_PROVISION
    _, status = asyncio.run(with_mux(peer))
    assert status['bandwidth_kbps'] == 32
    assert status['datagram_count'] == 1


def test_absent_allocation_is_unknown_not_zero():
    async def peer(reader, writer):
        await handshake(reader, writer, allocation=None)
        assert (await read_frame(reader)).message_type == M.DATA_PROVISION
    _, status = asyncio.run(with_mux(peer))
    assert status['bandwidth_kbps'] == 64


def test_client_channel_and_stream_heartbeats():
    async def peer(reader, writer):
        await handshake(reader, writer)
        seen = set()
        while seen != {M.CHANNEL_TEST, M.STREAM_TEST}:
            frame = await read_frame(reader)
            if frame.message_type == M.CHANNEL_TEST:
                seen.add(frame.message_type)
                await send_frame(writer, mux_frame(M.CHANNEL_STATUS,
                    extra=[TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)]))
            elif frame.message_type == M.STREAM_TEST:
                seen.add(frame.message_type)
                await send_frame(writer, mux_frame(M.STREAM_STATUS, stream=True,
                    extra=[TLV.integer(T.DATA_ID, 1), TLV.integer(T.DATA_TYPE, 0, 1)]))
            else:
                assert frame.message_type == M.DATA_PROVISION
    asyncio.run(with_mux(peer, overrides=dict(channel_test_delay=1, stream_test_delay=1, timeout=3)))


@pytest.mark.parametrize('wrong', ['client', 'channel', 'version', 'stream'])
def test_wrong_identity_or_version_closes_connection(wrong):
    async def peer(reader, writer):
        assert (await read_frame(reader)).message_type == M.CHANNEL_SETUP
        if wrong == 'stream':
            await send_frame(writer, mux_frame(M.CHANNEL_STATUS,
                extra=[TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)]))
            assert (await read_frame(reader)).message_type == M.STREAM_SETUP
            await send_frame(writer, mux_frame(M.STREAM_STATUS, stream=True, stream_id=2,
                extra=[TLV.integer(T.DATA_ID, 1), TLV.integer(T.DATA_TYPE, 0, 1)]))
        else:
            kwargs = {wrong: {'client': CLIENT_ID + 1, 'channel': 2, 'version': 3}[wrong]}
            await send_frame(writer, mux_frame(M.CHANNEL_STATUS,
                extra=[TLV.integer(T.SECTION_TSPKT_FLAG, 0, 1)], **kwargs))
        assert await asyncio.wait_for(reader.read(), 1) == b''
    _, status = asyncio.run(with_mux(peer))
    assert status['datagram_count'] == 0
    assert status['error_count'] >= 1
    assert 'mismatch' in status['last_error']


def test_reconnect_after_peer_disconnect():
    async def scenario():
        loop = asyncio.get_running_loop()
        completed = loop.create_future()
        attempts = 0
        tasks = set()
        async def connected(reader, writer):
            nonlocal attempts
            attempts += 1
            task = asyncio.current_task()
            tasks.add(task)
            try:
                if attempts == 1:
                    assert (await read_frame(reader)).message_type == M.CHANNEL_SETUP
                    return
                await handshake(reader, writer)
                assert (await read_frame(reader)).message_type == M.DATA_PROVISION
                completed.set_result(True)
            except Exception as exc:
                if not completed.done():
                    completed.set_exception(exc)
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
                tasks.discard(task)
        server = await asyncio.start_server(connected, '127.0.0.1', 0)
        client = EMMGClient(config(server.sockets[0].getsockname()[1]), lambda: [card()])
        try:
            await client.start()
            assert await asyncio.wait_for(completed, 4)
            assert attempts == 2
            assert client.status()['error_count'] >= 1
        finally:
            await client.close()
            server.close()
            await server.wait_closed()
            for task in tuple(tasks):
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(scenario())


def test_first_queue_load_does_not_depend_on_host_uptime(monkeypatch):
    # The event loop retains its real clock; only the EMMG module sees early uptime.
    import tvcas.emmg as module
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: 1.0, time=time.time))
    async def peer(reader, writer):
        await handshake(reader, writer)
        assert (await read_frame(reader, timeout=0.4)).message_type == M.DATA_PROVISION
    asyncio.run(with_mux(peer))


def test_eligibility_matches_php_cache_then_expiry_filter():
    now = 1_800_000_000
    old = now - 8 * 86400
    cards = [
        card(serial_no=1, start=now-100, finish=now+100, edit=old, status=0, network_id=99),
        card(serial_no=2, start=now+100, finish=now+200, edit=now-1),
        card(serial_no=3, start=now-100, finish=now-1, edit=now),  # recently revoked but expired
        card(serial_no=4, start=now+100, finish=now+200, edit=old),
        card(serial_no=5, start=now-100, finish=now, edit=now-2),  # equality survives PHP '<'
        card(serial_no=6, start=now, finish=now+100, edit=old),   # strict current-valid comparison
    ]
    assert [c['serial_no'] for c in eligible_cards(cards, now)] == [2, 5, 1]


def test_incomplete_card_does_not_stop_valid_entitlements():
    async def peer(reader, writer):
        await handshake(reader, writer)
        frame = await read_frame(reader)
        assert frame.message_type == M.DATA_PROVISION
        assert int.from_bytes(frame.require(T.DATAGRAM)[6:10], 'big') == SERIAL
    cards = [card(serial_no=SERIAL+1, start=None), card()]
    _, status = asyncio.run(with_mux(peer, cards=cards))
    assert status['invalid_cards'] == 1
    assert status['queue_size'] == 1
    assert status['datagram_count'] == 1
