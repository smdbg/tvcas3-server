import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from html.parser import HTMLParser
from urllib.parse import urlsplit

from tvcas.storage import Store, hash_password
from tvcas.web import create_app


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password('test password')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'state.sqlite')
        self.store.set_settings({'admin_password_hash': self.password_hash, 'oper_password_hash': self.password_hash,
                                 'api_key': 'synthetic-test-token', 'ecm_key': 'ab' * 32, 'ident': '0B17'})
        self.card = self.store.save_row('cards', dict(serial_no=2100000001, name='Test Card', info='Example',
                    key='12' * 16, access_criteria='80000001', start=1704067200, finish=1735689600))
        self.app = create_app(self.store)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def auth(self, actor='admin'):
        with self.client.session_transaction() as sess:
            sess.update(actor=actor, csrf='test-csrf')

    def test_login_and_roles(self):
        self.assertEqual(self.client.get('/manage/cards').status_code, 302)
        self.client.get('/login')
        with self.client.session_transaction() as sess:
            csrf = sess['csrf']
        response = self.client.post('/login', data={'username': 'admin', 'password': 'test password', 'csrf_token': csrf})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/settings').status_code, 200)
        self.auth('oper')
        self.assertEqual(self.client.get('/settings').status_code, 403)
        self.assertEqual(self.client.get('/cards/export.csv').status_code, 403)
        self.assertEqual(self.client.get('/cards/2100000001/config.bin').status_code, 403)

    def test_secret_redaction_and_templates(self):
        self.auth()
        for path in ('/', '/manage/cards', '/manage/ecmg', '/manage/emmg', '/settings', '/audit', '/manage/cards/new',
                     '/manage/cards/1', '/manage/ecmg/new', '/manage/emmg/new', '/api/cards'):
            response = self.client.get(path, follow_redirects=True)
            self.assertEqual(response.status_code, 200, path)
            self.assertNotIn(('12' * 16).encode(), response.data)
            self.assertNotIn(('ab' * 32).encode(), response.data)
            self.assertNotIn(b'synthetic-test-token', response.data)

    def test_csrf_protection_and_card_update(self):
        self.auth()
        self.assertEqual(self.client.post('/manage/cards/1', data={'name': 'Changed'}).status_code, 400)
        response = self.client.post('/manage/cards/1', data={'name': 'Changed', 'start': '2024-01-01T00:00:00', 'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 302)
        card = self.store.get_row('cards', self.card['id'])
        self.assertEqual(card['name'], 'Changed')
        self.assertEqual(card['start'], 1704067200)
        self.assertEqual(card['key'], '12' * 16)

    def test_operator_cannot_inject_secret_field(self):
        self.auth('oper')
        self.client.post('/manage/cards/1', data={'name': 'Allowed', 'key': 'ff' * 16, 'csrf_token': 'test-csrf'})
        self.assertEqual(self.store.get_row('cards', 1)['key'], '12' * 16)
        self.assertEqual(self.client.post('/api/cards', json={'serial_no': 42}, headers={'X-CSRF-Token':'test-csrf'}).status_code, 403)

    def test_legacy_billing_api(self):
        self.assertEqual(self.client.get('/api.php').data, b'NOT_VALID_API_KEY')
        args = {'api_key': 'synthetic-test-token', 'serial_no': 2100000001, 'set[access_criteria]': 'FFFFFFFF'}
        response = self.client.get('/api.php', query_string=args)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['access_criteria'], 'FFFFFFFF')
        self.assertNotIn('key', response.json)
        args['set[access_criteria]'] = 'xxFFFFFFFF'
        self.assertEqual(self.client.get('/api.php', query_string=args).data, b'ACCESS_CRITERIA_ERROR')
        args.pop('set[access_criteria]'); args['set[key]'] = 'ff' * 16
        self.assertEqual(self.client.get('/api.php', query_string=args).data, b'UNKNOWN_SET_PARAMETER')

    def test_config_export_is_explicit_and_private(self):
        self.auth()
        response = self.client.get('/cards/2100000001/config.bin')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 90)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertIn('210-000-000-1.bin', response.headers['Content-Disposition'])

    def test_csv_roundtrip_and_atomic_validation(self):
        self.auth()
        response = self.client.get('/cards/export.csv?format=oper')
        self.assertNotIn(('12' * 16).encode(), response.data)
        admin = self.client.get('/cards/export.csv?format=admin').data
        response = self.client.post('/cards/import.csv', data={'csrf_token': 'test-csrf', 'file': (io.BytesIO(admin), 'cards.csv')})
        self.assertEqual(response.status_code, 302)
        invalid = (b'serial_no;name;info;key;access_criteria;type;pair;start;finish;edit\n'
                   + b'2100000002;New;;' + b'34' * 16 + b';00000001;1;0;1704067200;1735689600;0\n'
                   + b'2100000003;Bad;;bad;00000001;1;0;1704067200;1735689600;0\n')
        response = self.client.post('/cards/import.csv', data={'csrf_token': 'test-csrf', 'file': (io.BytesIO(invalid), 'bad.csv')})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.store.list_rows('cards')), 1)

    def test_basic_auth_form_still_requires_csrf(self):
        import base64
        authorization = 'Basic ' + base64.b64encode(b'admin:test password').decode()
        denied = self.client.post('/manage/cards/1', data={'name': 'Cross-site'}, headers={'Authorization': authorization})
        self.assertEqual(denied.status_code, 400)
        accepted = self.client.patch('/api/cards/1', json={'name': 'JSON client'}, headers={'Authorization': authorization})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(self.store.get_row('cards', 1)['name'], 'JSON client')

    def test_bulk_cards_have_distinct_keys_and_packet_mode_is_validated(self):
        self.auth()
        response = self.client.post('/manage/cards/new', data={'csrf_token': 'test-csrf', 'quantity': '3',
                    'serial_no': '2100000010', 'access_criteria': '00000001', 'start': '1704067200', 'finish': '1735689600'})
        self.assertEqual(response.status_code, 302)
        cards = self.store.list_rows('cards')
        self.assertEqual(len(cards), 4)
        self.assertEqual(len({card['key'] for card in cards}), 4)
        denied = self.client.post('/api/ecmg', json={'port': 42000, 'packet_mode': 1}, headers={'X-CSRF-Token': 'test-csrf'})
        self.assertEqual(denied.status_code, 400)

    def test_pair_type_refresh_marker_and_explicit_date(self):
        self.auth()
        start = self.card['start']
        # Form, modern API and CSV all apply the legacy admin refresh marker.
        self.client.post('/manage/cards/1', data={'pair': '1', 'csrf_token': 'test-csrf'})
        self.assertEqual(self.store.get_row('cards', 1)['start'], start + 1)
        self.client.post('/manage/cards/1', data={'pair': '1', 'csrf_token': 'test-csrf'})
        self.assertEqual(self.store.get_row('cards', 1)['start'], start + 1)
        self.client.patch('/api/cards/1', json={'type': 2}, headers={'X-CSRF-Token': 'test-csrf'})
        self.assertEqual(self.store.get_row('cards', 1)['start'], start + 2)
        self.client.patch('/api/cards/1', json={'type': 1, 'start': start + 50}, headers={'X-CSRF-Token': 'test-csrf'})
        self.assertEqual(self.store.get_row('cards', 1)['start'], start + 50)
        body = ('serial_no;name;info;key;access_criteria;type;pair;start;finish;edit\n'
                + '2100000001;Card;;' + '12' * 16 + ';00000001;2;1;'
                + str(start + 50) + ';1735689600;0\n').encode()
        response = self.client.post('/cards/import.csv', data={'csrf_token': 'test-csrf', 'file': (io.BytesIO(body), 'cards.csv')})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.store.get_row('cards', 1)['start'], start + 51)

    def test_legacy_api_numeric_strings_case_and_flag_refresh(self):
        response = self.client.get('/api.php', query_string={'api_key': 'synthetic-test-token',
                    'serial_no': 2100000001, 'set[pair]': '1', 'set[access_criteria]': 'abcdef12'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['serial_no'], '2100000001')
        self.assertEqual(response.json['start'], str(self.card['start'] + 1))
        self.assertEqual(response.json['pair'], '1')
        self.assertEqual(response.json['access_criteria'], 'abcdef12')
        self.store.save_row('cards', {'info': None}, 1)
        response = self.client.get('/api.php', query_string={'api_key': 'synthetic-test-token', 'serial_no': 2100000001})
        self.assertIsNone(response.json['info'])

    def test_generator_toggle_offline(self):
        self.auth('oper')
        gen = self.store.save_row('emmg', {'host': '127.0.0.1', 'port': 41000})
        response = self.client.post('/manage/emmg/%d/toggle' % gen['id'], data={'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.store.get_row('emmg', gen['id'])['enable'], 1)
        self.assertFalse(self.store.get_settings()['runtime_enabled'])

    def test_home_and_login_open_cards_directly(self):
        self.auth()
        for path in ('/', '/cas/'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(urlsplit(response.location).path, '/manage/cards')
        self.client.post('/logout', data={'csrf_token':'test-csrf'})
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        response = self.client.post('/login', data={'username':'admin', 'password':'test password', 'csrf_token':csrf})
        self.assertEqual(urlsplit(response.location).path, '/manage/cards')

    def test_card_editor_bits_serial_and_advanced_fields(self):
        class Inputs(HTMLParser):
            def __init__(self):
                super().__init__(); self.inputs = []; self.fieldsets = []
            def handle_starttag(self, tag, attrs):
                if tag == 'input': self.inputs.append(dict(attrs))
                if tag == 'fieldset': self.fieldsets.append(dict(attrs))
        self.auth()
        response = self.client.get('/manage/cards/1')
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('#210-000-000-1', page)
        parsed = Inputs(); parsed.feed(page)
        bits = [item for item in parsed.inputs if 'data-access-bit' in item]
        self.assertEqual([int(item['data-access-bit']) for item in bits], list(range(31,-1,-1)))
        self.assertEqual({int(item['data-access-bit']) for item in bits if 'checked' in item}, {31,0})
        self.assertTrue(any('data-card-advanced' in item and 'disabled' in item for item in parsed.fieldsets))
        secret = next(item for item in parsed.inputs if item.get('name') == 'key')
        self.assertNotIn('value', secret)
        self.assertIn('cards.js', page)
        self.assertIn('START · UTC', page)
        self.assertIn('FINISH · UTC', page)
        self.assertNotIn(self.card['key'], page)

    def test_basic_card_edit_preserves_seconds_and_advanced_data(self):
        self.auth()
        original = self.store.save_row('cards', {'start':1704067245, 'finish':1735689647,
            'network_id':3, 'type':2, 'pair':1, 'uid':16, 'status':7}, 1)
        response = self.client.post('/manage/cards/1', data={'csrf_token':'test-csrf',
            'name':'New visible name', 'info':'New visible info', 'access_criteria':'FFFFFFFF',
            'start':'2024-01-01T00:00:45', 'finish':'2025-01-01T00:00:47'})
        self.assertEqual(response.status_code, 302)
        saved = self.store.get_row('cards', 1)
        for field in ('key','serial_no','network_id','type','pair','uid','status','start','finish'):
            self.assertEqual(saved[field], original[field], field)
        self.assertEqual(saved['access_criteria'], 'FFFFFFFF')

    def test_cards_listing_formats_serial_and_searches_formatted_number(self):
        self.auth()
        response = self.client.get('/manage/cards?q=210-000-000-1')
        page = response.get_data(as_text=True)
        self.assertIn('Test Card', page)
        self.assertIn('210-000-000-1', page)
        self.assertIn('Информация</th>', page)
        self.assertIn('Начало · UTC</th>', page)
        self.assertIn('Край · UTC</th>', page)
        self.assertIn('Редактирано · UTC</th>', page)
        self.assertIn('Тип 1</th>', page)
        self.assertIn('type="checkbox" disabled checked aria-label="Тип 1"', page)
        self.assertNotIn(self.card['key'], page)

    def test_headend_link_uses_configured_port_and_ipv6_host(self):
        import base64
        header = {'Authorization':'Basic '+base64.b64encode(b'admin:test password').decode()}
        with patch.dict('os.environ', {'HEADEND_PORT':'18995'}):
            page = self.client.get('/manage/cards', base_url='http://[2001:db8::1]:8091', headers=header).get_data(as_text=True)
            self.assertIn('href="http://[2001:db8::1]:18995/"', page)
        for port in ('invalid','0','65536'):
            with patch.dict('os.environ', {'HEADEND_PORT':port}):
                page = self.client.get('/manage/cards', headers=header).get_data(as_text=True)
                self.assertNotIn('class="headend-link"', page)
        with patch.dict('os.environ', {}, clear=True):
            page = self.client.get('/manage/cards', headers=header).get_data(as_text=True)
            self.assertNotIn('class="headend-link"', page)

    def test_runtime_status_is_retained_in_settings(self):
        gen, runtime = self.diagnostic_runtime()
        self.auth()
        page = self.client.get('/settings').get_data(as_text=True)
        self.assertIn('Състояние на услугата', page)
        self.assertIn('ECM генератори', page)
        self.assertEqual(runtime.calls, [])

    def diagnostic_runtime(self):
        gen = self.store.save_row('ecmg', {'host': 0, 'port': 42000, 'key': 'ab' * 32,
                                         'info': 'Test <generator>'})
        class DiagnosticRuntime:
            def __init__(self):
                self.calls = []
                self.peer = dict(peer_id='a1b2c3', address='192.0.2.10:54448', connected_at=1794735092,
                                 disconnected_at=None, connected=True, last_seen=1794735103,
                                 cw_count=1, ecm_count=1, channel_id=1, streams=1)
                self.entry = dict(seq=1, time=1794735103, peer_id='a1b2c3', address=self.peer['address'],
                                  channel_id=1, stream_id=0, cp_number=2, access_criteria='00000001',
                                  cw1='0123456789ABCDEF', cw2='FEDCBA9876543210')

            def status(self):
                return {'state': 'active', 'ecmg': [{'id': gen['id'], 'running': True,
                         'last_ecm': 1794735103, 'peers': [self.peer]}]}

            def ecmg_diagnostics(self, generator_id, peer_id=None, limit=100):
                self.calls.append((generator_id, peer_id, limit))
                entries = [self.entry] if peer_id in (None, self.peer['peer_id']) else []
                return {'state': 'active', 'running': True, 'peers': [self.peer],
                        'entries': entries[:limit], 'retention_limit': 1000}
        runtime = DiagnosticRuntime()
        self.app = create_app(self.store, runtime)
        self.app.testing = True
        self.client = self.app.test_client()
        return gen, runtime

    def test_ecmg_journal_requires_admin_and_is_private(self):
        gen, runtime = self.diagnostic_runtime()
        page = '/manage/ecmg/%d/log' % gen['id']
        api = '/api/ecmg/%d/diagnostics' % gen['id']
        self.assertEqual(self.client.get(page).status_code, 302)
        self.assertEqual(self.client.get(api).status_code, 401)
        self.auth('oper')
        self.assertEqual(self.client.get(page).status_code, 403)
        self.assertEqual(self.client.get(api).status_code, 403)
        self.assertEqual(runtime.calls, [])
        self.auth()
        response = self.client.get(api)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.json['entries'][0]['cw1'], runtime.entry['cw1'])
        self.assertEqual(response.json['entries'][0]['cw2'], runtime.entry['cw2'])
        self.assertNotIn(('ab' * 32).encode(), response.data)
        response = self.client.get(page)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test &lt;generator&gt;', response.data)
        self.assertIn(b'ecmg-live.js', response.data)
        self.assertNotIn(runtime.entry['cw1'].encode(), response.data)
        self.assertNotIn(('ab' * 32).encode(), response.data)

    def test_ecmg_peer_listing_and_general_apis_do_not_expose_cw(self):
        gen, runtime = self.diagnostic_runtime()
        for role in ('admin', 'oper'):
            self.auth(role)
            response = self.client.get('/manage/ecmg')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'192.0.2.10:54448', response.data)
            self.assertIn(b'cw=1, ecm=1', response.data)
            self.assertEqual(b'[log]' in response.data, role == 'admin')
            for path in ('/api/status', '/api/ecmg', '/manage/ecmg'):
                response = self.client.get(path)
                self.assertNotIn(runtime.entry['cw1'].encode(), response.data)
                self.assertNotIn(runtime.entry['cw2'].encode(), response.data)
                self.assertNotIn(('ab' * 32).encode(), response.data)
        self.assertEqual(runtime.calls, [])

    def test_ecmg_journal_filter_limits_and_validation(self):
        gen, runtime = self.diagnostic_runtime()
        self.auth()
        api = '/api/ecmg/%d/diagnostics' % gen['id']
        response = self.client.get(api, query_string={'peer_id':'a1b2c3', 'limit':999999})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(runtime.calls[-1], (gen['id'], 'a1b2c3', 200))
        self.assertEqual(len(response.json['entries']), 1)
        response = self.client.get(api, query_string={'peer_id':'different-peer', 'limit':0})
        self.assertEqual(runtime.calls[-1], (gen['id'], 'different-peer', 1))
        self.assertEqual(response.json['entries'], [])
        calls = len(runtime.calls)
        for args in ({'limit':'invalid'}, {'peer_id':'../bad'}, {'peer_id':'a'*97}):
            self.assertEqual(self.client.get(api, query_string=args).status_code, 400)
        self.assertEqual(len(runtime.calls), calls)
        self.assertEqual(self.client.get('/api/ecmg/9999/diagnostics').status_code, 404)
        self.assertEqual(self.client.get('/manage/ecmg/9999/log').status_code, 404)

    def test_ecmg_journal_offline_is_empty_without_starting_runtime(self):
        gen = self.store.save_row('ecmg', {'host':0, 'port':42000, 'key':'ab'*32})
        self.auth()
        response = self.client.get('/api/ecmg/%d/diagnostics' % gen['id'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['state'], 'offline')
        self.assertFalse(response.json['running'])
        self.assertEqual(response.json['entries'], [])
        self.assertEqual(response.json['peers'], [])
        self.assertFalse(self.store.get_settings()['runtime_enabled'])


if __name__ == '__main__':
    unittest.main()
