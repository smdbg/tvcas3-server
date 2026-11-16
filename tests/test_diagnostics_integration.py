"""Real SimulCrypt TCP request -> runtime thread -> authenticated web journal."""
import json
import socket
import time

from tvcas.runtime import Runtime
from tvcas.simulcrypt import ECMGMessage as M, ECMGTag as T, Frame, TLV, cp_cw_parameter, decode_frame
from tvcas.storage import Store
from tvcas.web import create_app


def test_live_request_visible_without_waiting_for_periodic_snapshot(tmp_path):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    store = Store(tmp_path / 'state.sqlite')
    store.set_settings({'runtime_enabled': True})
    generator = store.save_row('ecmg', {'host': 2130706433, 'port': port,
        'key': 'a1' * 32, 'enable': 1, 'status': 1, 'timeout': 2})
    runner = Runtime(store, activation_allowed=True)
    runner.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not runner.status()['ecmg']:
            time.sleep(.01)
        assert runner.status()['ecmg'][0]['running']
        app = create_app(store, runner)
        app.testing = True
        client = app.test_client()
        with client.session_transaction() as session:
            session['actor'] = 'admin'

        with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
            def exchange(message, parameters):
                frame = Frame(1, message, (TLV.integer(T.ECM_CHANNEL_ID, 7), *parameters))
                connection.sendall(frame.encode())
                def read_exact(size):
                    result = b''
                    while len(result) < size:
                        part = connection.recv(size-len(result))
                        assert part, 'Unexpected ECMG disconnect'
                        result += part
                    return result
                header = read_exact(5)
                return decode_frame(header + read_exact(int.from_bytes(header[3:], 'big')))

            assert exchange(M.CHANNEL_SETUP, [TLV.integer(T.SUPER_CAS_ID, 0x0B000001, 4)]).message_type == M.CHANNEL_STATUS
            assert exchange(M.STREAM_SETUP, [TLV.integer(T.ECM_STREAM_ID, 9)]).message_type == M.STREAM_STATUS
            current, following = bytes.fromhex('1234567890ABCDEF'), bytes.fromhex('FEDCBA0987654321')
            assert exchange(M.CW_PROVISION, [TLV.integer(T.ECM_STREAM_ID, 9), TLV.integer(T.CP_NUMBER, 0),
                TLV.integer(T.ACCESS_CRITERIA, 1, 4), cp_cw_parameter(0, current),
                cp_cw_parameter(1, following)]).message_type == M.ECM_RESPONSE

            path = '/api/ecmg/{}/diagnostics'.format(generator['id'])
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers['Cache-Control'] == 'no-store'
            data = response.get_json()
            assert len(data['entries']) == 1
            peer_id = data['entries'][0]['peer_id']
            assert data['peers'][0]['peer_id'] == peer_id
            assert data['peers'][0]['address'] == '127.0.0.1:{}'.format(connection.getsockname()[1])
            assert data['peers'][0]['cw_count'] == data['peers'][0]['ecm_count'] == 1
            assert data['entries'][0]['cw1'] == following.hex().upper()
            assert data['entries'][0]['cw2'] == current.hex().upper()
            assert data['entries'][0]['access_criteria'] == '00000001'
            assert client.get(path, query_string={'peer_id': peer_id}).get_json()['entries'] == data['entries']
            for public_path in ('/api/status', '/api/ecmg', '/manage/ecmg'):
                public = client.get(public_path).get_data(as_text=True)
                assert current.hex().upper() not in public
                assert following.hex().upper() not in public
                assert 'a1' * 32 not in public
            with client.session_transaction() as session:
                session['actor'] = 'oper'
            assert client.get(path).status_code == 403
            with client.session_transaction() as session:
                session.clear()
            assert client.get(path).status_code == 401
    finally:
        runner.close()
