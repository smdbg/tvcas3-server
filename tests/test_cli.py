import json
from pathlib import Path
import signal
import socket
import sqlite3
from types import SimpleNamespace

import pytest

from tvcas import __main__ as cli
from tvcas.storage import Store, verify_password


def initialized(tmp_path, monkeypatch):
    path = tmp_path / 'instance' / 'tvcas.sqlite'
    answers = iter(['test-admin', 'test-admin', 'test-oper', 'test-oper'])
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: next(answers))
    assert cli.main(['init', '--database', str(path)]) == 0
    return path


def test_init_then_offline_check_preserves_keys_and_passwords(tmp_path, monkeypatch, capsys):
    path = initialized(tmp_path, monkeypatch)
    store = Store(path)
    settings = store.get_settings()
    assert verify_password('test-admin', settings['admin_password_hash'])
    assert verify_password('test-oper', settings['oper_password_hash'])
    assert len(settings['ecm_key']) == 64
    assert settings['runtime_enabled'] is False
    capsys.readouterr()
    def no_network(*args, **kwargs):
        raise AssertionError('offline check must not create a socket')
    monkeypatch.setattr(socket, 'socket', no_network)
    assert cli.main(['check', '--database', str(path)]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report['ok'] is True
    assert report['activation_performed'] is False
    assert settings['ecm_key'] not in output
    assert settings['api_key'] not in output
    assert Store(path).get_settings() == settings


def test_init_refuses_existing_database_before_prompt_or_key_generation(tmp_path, monkeypatch, capsys):
    path = initialized(tmp_path, monkeypatch)
    before = Store(path).get_settings()
    capsys.readouterr()
    def forbidden(*args, **kwargs):
        raise AssertionError('existing database must not regenerate credentials')
    monkeypatch.setattr(cli.getpass, 'getpass', forbidden)
    monkeypatch.setattr(cli.secrets, 'token_hex', forbidden)
    assert cli.main(['init', '--database', str(path)]) == 2
    assert 'will not be regenerated' in capsys.readouterr().err
    assert Store(path).get_settings() == before


def test_init_mismatch_does_not_create_database(tmp_path, monkeypatch):
    answers = iter(['first', 'different'])
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: next(answers))
    path = tmp_path / 'new.sqlite'
    assert cli.main(['init', '--database', str(path)]) == 2
    assert not path.exists()


def test_runtime_gate_is_offline_validated_and_lock_protected(tmp_path, monkeypatch, capsys):
    path = initialized(tmp_path, monkeypatch)
    before = Store(path).get_settings()
    capsys.readouterr()
    def no_network(*args, **kwargs):
        raise AssertionError('runtime gate must not open sockets')
    monkeypatch.setattr(socket, 'socket', no_network)
    assert cli.main(['runtime', '--database', str(path), '--enable']) == 0
    assert Store(path).get_settings() == dict(before, runtime_enabled=True)
    report = json.loads(capsys.readouterr().out)
    assert report == {'runtime_enabled': True, 'activation_performed': False}
    with cli.database_lock(path):
        assert cli.main(['runtime', '--database', str(path), '--disable']) == 2
    assert Store(path).get_settings()['runtime_enabled'] is True
    assert cli.main(['runtime', '--database', str(path), '--disable']) == 0
    assert Store(path).get_settings() == before
    Store(path).set_settings({'ecm_key': ''})
    assert cli.main(['runtime', '--database', str(path), '--enable']) == 2
    assert Store(path).get_settings()['runtime_enabled'] is False
    assert cli.main(['runtime', '--database', str(tmp_path/'missing.sqlite'), '--enable']) == 2
    assert not (tmp_path/'missing.sqlite').exists()


def test_check_reports_fields_without_secret_values(tmp_path, monkeypatch, capsys):
    path = initialized(tmp_path, monkeypatch)
    store = Store(path)
    store.set_settings({'ecm_key': 'DO-NOT-PRINT-THIS-SECRET', 'zone': 'invalid'})
    capsys.readouterr()
    assert cli.main(['check', '--database', str(path)]) == 1
    output = capsys.readouterr().out
    assert 'DO-NOT-PRINT-THIS-SECRET' not in output
    report = json.loads(output)
    assert {issue['location'] for issue in report['errors']} == {'settings'}
    assert len(report['errors']) == 2


def test_check_rejects_unrepresentable_card_dates_and_invalid_profile(tmp_path, monkeypatch):
    path = initialized(tmp_path, monkeypatch)
    store = Store(path)
    store.save_row('cards', {'serial_no': 2100000111, 'key': '12'*16,
                           'start': 1700000000, 'finish': 4294967295})
    store.save_row('ecmg', {'key': '34'*32, 'port': 43000, 'packet_mode': 1})
    report = cli.check_database(path)
    assert not report['ok']
    assert len(report['errors']) == 2
    assert '2069' in report['errors'][0]['field'] or '2069' in report['errors'][1]['field']


def test_canonical_lock_blocks_second_process_path_and_releases(tmp_path):
    path = tmp_path / 'db.sqlite'
    path.touch()
    alias = tmp_path / 'alias.sqlite'
    alias.symlink_to(path)
    with cli.database_lock(path):
        with pytest.raises(cli.CLIError, match='already holds'):
            with cli.database_lock(alias):
                pass
    with cli.database_lock(alias):
        pass
    assert Path(str(path) + '.serve.lock').stat().st_mode & 0o777 == 0o600


def test_serve_defaults_are_offline_loopback_and_missing_db_is_not_created(tmp_path):
    args = cli.build_parser().parse_args(['serve', '--database', str(tmp_path/'absent.sqlite')])
    assert args.activate is False and args.host == '127.0.0.1' and args.port == 8091
    assert cli.main(['serve', '--database', args.database]) == 2
    assert not Path(args.database).exists()


@pytest.mark.parametrize('activate', [False, True])
def test_serve_sigterm_closes_runtime_and_server_and_releases_lock(tmp_path, monkeypatch, activate):
    import waitress
    import tvcas.runtime
    import tvcas.web
    path = initialized(tmp_path, monkeypatch)
    # A persisted enabled switch must not override an absent --activate flag.
    Store(path).set_settings({'runtime_enabled': True})
    calls = []
    old_term = signal.getsignal(signal.SIGTERM)
    class FakeRuntime:
        def __init__(self, store, *, activation_allowed):
            calls.append(('runtime', activation_allowed))
        def start(self):
            calls.append(('start',))
        def close(self):
            calls.append(('close_runtime',))
    class FakeDispatcher:
        def shutdown(self, timeout):
            calls.append(('shutdown_workers', timeout))
    class FakeServer:
        task_dispatcher = FakeDispatcher()
        def run(self):
            calls.append(('run',))
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        def close(self):
            calls.append(('close_server',))
    def server_factory(app, **kwargs):
        assert kwargs['threads'] == 4
        assert kwargs['host'] == '127.0.0.1'
        return FakeServer()
    monkeypatch.setattr(tvcas.runtime, 'Runtime', FakeRuntime)
    monkeypatch.setattr(tvcas.web, 'create_app', lambda store, runtime: object())
    monkeypatch.setattr(waitress, 'create_server', server_factory)
    argv = ['serve', '--database', str(path)] + (['--activate'] if activate else [])
    assert cli.main(argv) == 0
    assert ('runtime', activate) in calls
    assert ('close_runtime',) in calls and ('close_server',) in calls
    assert signal.getsignal(signal.SIGTERM) == old_term
    assert Store(path).get_settings()['runtime_enabled'] is True
    with cli.database_lock(path):
        pass


def test_real_waitress_process_offline_start_lock_and_sigterm(tmp_path, monkeypatch):
    import subprocess
    import sys
    import time
    import urllib.request
    path = initialized(tmp_path, monkeypatch)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    command = [sys.executable, '-m', 'tvcas', 'serve', '--database', str(path), '--port', str(port)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 8
        while True:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(f'TVCAS exited during startup: {process.returncode}; {stderr}')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=0.3) as response:
                    assert response.status == 200
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    pytest.fail('TVCAS health endpoint did not become available')
                time.sleep(0.05)
        duplicate = subprocess.run(command, capture_output=True, text=True, timeout=5)
        assert duplicate.returncode == 2
        assert 'already holds' in duplicate.stderr
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        assert Store(path).get_settings()['runtime_enabled'] is False
        with cli.database_lock(path):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
