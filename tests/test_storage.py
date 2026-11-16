from concurrent.futures import ThreadPoolExecutor
import os
import time

import pytest

from tvcas.storage import Store, hash_password, verify_password


def test_ecmg_csa_reduction_flag_is_opt_in_and_persistent(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    row = store.save_row('ecmg', {'key': bytes(range(32)).hex()})
    assert row['csa_entropy_reduction'] == 0
    store.save_row('ecmg', {'csa_entropy_reduction': True}, row['id'])
    assert Store(store.path).get_row('ecmg', row['id'])['csa_entropy_reduction'] == 1
    for invalid in ('false', 1.0, -1, 2, []):
        with pytest.raises(ValueError, match='csa_entropy_reduction'):
            store.save_row('ecmg', {'csa_entropy_reduction': invalid}, row['id'])


def test_card_update_preserves_secrets_and_unknown_columns(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    card = store.save_row('cards', {'serial_no': 2100000123, 'key': 'a1' * 16,
                                  'vendor_extension': {'revision': 3}, 'finish': 4294967295})
    assert card['uid'] == 15 and card['status'] == 1
    updated = store.save_row('tvcas_smartcards', {'name': 'Нов абонат'}, card['id'])
    assert updated['key'] == 'a1' * 16
    assert updated['finish'] == 4294967295
    assert updated['vendor_extension'] == {'revision': 3}
    assert updated['name'] == 'Нов абонат'
    assert updated['c_time'] <= int(time.time())
    assert os.stat(store.path).st_mode & 0o777 == 0o600


def test_unique_serial_and_range_validation(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    store.save_row('cards', {'serial_no': 2100000001})
    with pytest.raises(ValueError, match='serial'):
        store.save_row('cards', {'serial_no': 2100000001})
    with pytest.raises(ValueError, match='finish'):
        store.save_row('cards', {'serial_no': 2100000002, 'finish': 4294967296})
    with pytest.raises(ValueError, match='hexadecimal'):
        store.save_row('cards', {'serial_no': 2100000002, 'key': 'bad'})
    with pytest.raises(ValueError, match='Unknown'):
        store.list_rows('cards; DROP TABLE records;')
    assert len(store.list_rows('cards')) == 1


def test_concurrent_inserts_do_not_reuse_ids(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    def create(n):
        return store.save_row('cards', {'serial_no': 2100000000 + n})['id']
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(create, range(32)))
    assert len(set(ids)) == 32
    assert sorted(ids) == list(range(1, 33))


def test_transaction_rolls_back_and_settings_merge(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    with pytest.raises(RuntimeError):
        with store.transaction() as conn:
            store._save(conn, 'cards', {'serial_no': 2100000000})
            store._set_settings(conn, {'runtime_enabled': True})
            raise RuntimeError('abort')
    assert store.list_rows('cards') == []
    assert store.get_settings()['runtime_enabled'] is False
    store.set_settings({'timezone': 'Europe/Sofia'})
    assert store.get_settings()['ident'] == '0B00'
    with pytest.raises(ValueError, match='boolean'):
        store.set_settings({'runtime_enabled': 'false'})


def test_password_hash_and_audit(tmp_path):
    encoded = hash_password('synthetic test password')
    assert 'synthetic' not in encoded
    assert verify_password('synthetic test password', encoded)
    assert not verify_password('incorrect', encoded)
    assert not verify_password('anything', '')
    store = Store(tmp_path / 'db.sqlite')
    store.audit('admin', 'card_updated', {'id': 4})
    event = store.list_audit()[0]
    assert event['details'] == {'id': 4}


def test_batch_validation_is_atomic(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    card = store.save_row('cards', {'serial_no': 2100000000, 'name': 'Original'})
    with pytest.raises(ValueError):
        store.save_rows('cards', [({'name': 'Changed'}, card['id']),
                                 ({'serial_no': 2100000001, 'finish': -1}, None)])
    assert store.get_row('cards', card['id'])['name'] == 'Original'
    assert len(store.list_rows('cards')) == 1
