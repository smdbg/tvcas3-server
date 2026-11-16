import copy
import json
from pathlib import Path

import pytest

from tvcas.migration import import_legacy_json, parse_php_settings
from tvcas.storage import DEFAULTS, Store, TABLES, verify_password


def example_rows():
    rows = {table: [] for table in TABLES}
    rows['tvcas_ecmg'] = [dict(DEFAULTS['tvcas_ecmg'], id=30, key='ab' * 32,
                              enable=1, c_time=123, m_time=456, vendor_custom='preserve')]
    rows['tvcas_emmg'] = [dict(DEFAULTS['tvcas_emmg'], id=16, enable=1, c_time=234)]
    rows['tvcas_smartcards'] = [dict(DEFAULTS['tvcas_smartcards'], id=10200,
        serial_no=2100000004, name='Тестова карта', key='cd' * 16, access_criteria='aB1234ff',
        start=2147483648, finish=4294967295, subscription_slot1=123,
        subscription_slot2=456, c_time=42, edit=43, uid=16)]
    return rows


def config_file(tmp_path):
    path = tmp_path / 'config.php'
    path.write_text('''<?php
file_put_contents('/tmp/DO_NOT_EXECUTE_THIS_PHP', 'danger');
$_hashed = array(
'ecm_key' => "''' + 'ef' * 32 + '''",
'pass_admin' => 'synthetic-admin',
'pass_oper' => "synthetic-oper",
'api_key' => 'test-api-key',
'mysql_pass' => "synthetic-db-password",
'zone' => date("O"),
'ident' => '0B00',
'ver' => 'v.3.2',
'escaped' => 'a\\\\b\\\'c',
'double' => "a\\tb",
);
$_columns = array('admin' => 'serial_no;name');
''')
    return path


def test_parse_is_static_and_handles_literals(tmp_path):
    settings = parse_php_settings(config_file(tmp_path))
    assert settings['escaped'] == "a\\b'c"
    assert settings['double'] == 'a\tb'
    assert 'zone' not in settings
    assert not Path('/tmp/DO_NOT_EXECUTE_THIS_PHP').exists()


def test_import_preserves_every_column_and_disables_runtime(tmp_path):
    store = Store(tmp_path / 'private' / 'db.sqlite')
    data = example_rows()
    report = import_legacy_json(store, data, config_file(tmp_path), timezone='Europe/Sofia', zone='+0200')
    assert store.export_rows() == data
    settings = store.get_settings()
    assert settings['runtime_enabled'] is False
    assert store.get_row('ecmg', 30)['enable'] == 1
    assert settings['ecm_key'] == 'ef' * 32
    assert settings['zone'] == '+0200'
    assert verify_password('synthetic-admin', settings['admin_password_hash'])
    assert verify_password('synthetic-oper', settings['oper_password_hash'])
    assert 'pass_admin' not in settings['legacy_config']
    assert 'pass_oper' not in settings['legacy_config']
    assert 'synthetic-admin' not in json.dumps(settings)
    assert report['counts']['tvcas_smartcards'] == 1


def test_failed_replace_rolls_back_rows_and_settings(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    data = example_rows()
    import_legacy_json(store, data)
    before = store.get_settings()
    bad = copy.deepcopy(data)
    duplicate = dict(bad['tvcas_smartcards'][0], id=10201)
    bad['tvcas_smartcards'].append(duplicate)
    with pytest.raises(ValueError, match='serial'):
        import_legacy_json(store, bad, replace=True)
    assert store.export_rows() == data
    assert store.get_settings() == before
    with pytest.raises(ValueError, match='Destination contains'):
        import_legacy_json(store, data)


def test_import_rejects_missing_tables_and_duplicate_ids(tmp_path):
    store = Store(tmp_path / 'db.sqlite')
    with pytest.raises(ValueError, match='all five'):
        import_legacy_json(store, {'cards': []})
    data = example_rows()
    data['tvcas_ecmg'].append(data['tvcas_ecmg'][0].copy())
    with pytest.raises(ValueError, match='duplicate IDs'):
        import_legacy_json(store, data)
    assert store.list_rows('ecmg') == []
