"""Authenticated TVCAS administration and legacy billing API."""
import csv
from datetime import datetime, timezone
from functools import wraps
import hmac
import io
import os
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from .card_config import build_card_config, config_filename
from .storage import hash_password, verify_password

CSV_HEADERS = {
    'admin': 'serial_no;name;info;key;access_criteria;type;pair;start;finish;edit'.split(';'),
    'oper': 'serial_no;name;info;access_criteria;pair;start;finish'.split(';'),
}
CARD_FIELDS = ('serial_no', 'name', 'info', 'network_id', 'key', 'access_criteria', 'type', 'pair', 'start', 'finish', 'status', 'uid')
ECMG_FIELDS = ('info', 'host', 'port', 'network_id', 'timeout', 'packet_mode', 'ac_delay_start', 'ac_delay_stop', 'delay_start', 'delay_stop', 'transition_delay_start', 'transition_delay_stop', 'repetition_period', 'min_cp_duration', 'max_compute_time', 'ecm_time1', 'ecm_time2', 'ecm_block_time')
EMMG_FIELDS = ('info', 'host', 'port', 'client_id', 'network_id', 'protocol_version', 'packet_mode', 'bandwidth', 'repetition', 'period', 'period_messages', 'channel_test_delay', 'stream_test_delay', 'timeout', 'reload_sec', 'uid')
TEXT_FIELDS = {'name', 'info', 'key', 'access_criteria', 'host'}
TABLES = {'cards': 'tvcas_smartcards', 'ecmg': 'tvcas_ecmg', 'emmg': 'tvcas_emmg'}
FIELDS = {'cards': CARD_FIELDS, 'ecmg': ECMG_FIELDS, 'emmg': EMMG_FIELDS}
LABELS = {'cards': 'Смарткарти', 'ecmg': 'ECM генератори', 'emmg': 'EMM генератори'}
FIELD_LABELS = {
    'info': 'Описание', 'host': 'Адрес', 'port': 'Порт', 'network_id': 'Мрежа · network_id',
    'timeout': 'Време за изчакване', 'packet_mode': 'Режим на обмен',
    'client_id': 'Идентификатор на клиента', 'protocol_version': 'Версия на протокола',
    'bandwidth': 'Пропускателна способност', 'repetition': 'Повторение на EMM',
    'period': 'Период', 'period_messages': 'Съобщения за период',
    'channel_test_delay': 'Проверка на канала', 'stream_test_delay': 'Проверка на потока',
    'reload_sec': 'Прочитане на картите', 'uid': 'UID',
    'ac_delay_start': 'Access criteria · начало', 'ac_delay_stop': 'Access criteria · край',
    'delay_start': 'Забавяне · начало', 'delay_stop': 'Забавяне · край',
    'transition_delay_start': 'Преход · начало', 'transition_delay_stop': 'Преход · край',
    'repetition_period': 'Повторение на ECM', 'min_cp_duration': 'Минимален криптопериод',
    'max_compute_time': 'Максимално време за изчисляване', 'ecm_time1': 'ECM време 1',
    'ecm_time2': 'ECM време 2', 'ecm_block_time': 'ECM блокиране',
}


def _public(row):
    return {k: v for k, v in row.items() if k not in {'key', 'cw1', 'cw2'}}


def _parse_fields(data, allowed):
    result = {}
    for key in allowed:
        if key not in data:
            continue
        value = data[key]
        if key == 'key' and not value:
            continue
        if key in TEXT_FIELDS:
            value = str(value)
        else:
            try:
                if key in ('start', 'finish') and isinstance(value, str) and 'T' in value:
                    parsed = datetime.fromisoformat(value)
                    value = int((parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp())
                value = int(str(value), 0) if str(value).lower().startswith('0x') else int(value)
            except (TypeError, ValueError):
                raise ValueError(f'{key}: необходимо е цяло число') from None
        result[key] = value
    for key, size in (('key', 32), ('access_criteria', 8)):
        if key in result and not re.fullmatch(r'[0-9A-Fa-f]{%d}' % size, result[key]):
            raise ValueError(f'{key}: необходими са {size} шестнадесетични знака')
        if key in result:
            result[key] = result[key].upper()
    for key in ('pair',):
        if key in result and result[key] not in (0, 1):
            raise ValueError(f'{key}: допустими са 0 и 1')
    if result.get('packet_mode', 0) != 0:
        raise ValueError('Поддържа се само section mode (packet_mode=0)')
    if 'type' in result and result['type'] not in (1, 2):
        raise ValueError('type: допустими са 1 и 2')
    for key in ('serial_no', 'start', 'finish', 'client_id'):
        if key in result and not 0 <= result[key] <= 0xffffffff:
            raise ValueError(f'{key}: извън unsigned 32-bit диапазона')
    if 'start' in result and 'finish' in result and result['finish'] < result['start']:
        raise ValueError('Крайната дата предхожда началната')
    return result


def _card_update(previous, changes):
    """Retain the legacy admin flag-change refresh marker, without double bumps.

    Legacy admin pair/type toggles moved subscription start by one second. The
    protected card firmware is unavailable for inspection, so retain that known
    server behavior consistently when changing flags, unless the caller supplied
    a genuinely different start timestamp. Ordinary saves remain idempotent.
    """
    changes = dict(changes)
    if previous and any(field in changes and int(changes[field]) != int(previous.get(field) or 0)
                        for field in ('pair', 'type')):
        start = previous.get('start')
        if start is not None and changes.get('start', start) == start:
            if int(start) == 0xffffffff:
                raise ValueError('Началната дата не може да бъде увеличена за промяна на pair/type')
            changes['start'] = int(start) + 1
    return changes


def create_app(store, runtime=None):
    app = Flask(__name__)
    settings = store.get_settings()
    if not settings.get('web_session_key'):
        store.set_settings({'web_session_key': secrets.token_hex(32)})
    app.secret_key = store.get_settings()['web_session_key']
    app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=bool(settings.get('web_https_only', False)))

    def reload_runtime():
        if runtime and hasattr(runtime, 'reconcile'):
            runtime.reconcile()

    def card_changed():
        for gen in store.list_rows('tvcas_emmg'):
            if gen.get('enable'):
                store.save_row('tvcas_emmg', {'reload': 1, 'version': int(gen.get('version', 0)) + 1}, gen['id'])
        reload_runtime()

    def authenticated(role=None):
        def decorate(fn):
            @wraps(fn)
            def call(*args, **kwargs):
                if not g.actor:
                    if request.path.startswith('/api/'):
                        return jsonify(error='Authentication required'), 401
                    return redirect(url_for('login'))
                if role and g.actor != role:
                    abort(403)
                return fn(*args, **kwargs)
            return call
        return decorate

    @app.before_request
    def authenticate():
        g.actor = session.get('actor')
        g.basic = False
        auth = request.authorization
        if auth and auth.type.lower() == 'basic':
            current = store.get_settings()
            if auth.username in ('admin', 'oper') and verify_password(auth.password or '', current.get(auth.username + '_password_hash', '')):
                g.actor, g.basic = auth.username, True
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        # Browsers may resend cached Basic credentials on cross-site form posts.
        # Only explicit JSON API clients are exempt: JSON requires a CORS preflight
        # and this application does not grant cross-origin access.
        basic_json_api = g.basic and request.path.startswith('/api/') and request.is_json
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and not basic_json_api:
            supplied = request.headers.get('X-CSRF-Token', '') or request.form.get('csrf_token', '')
            if not hmac.compare_digest(supplied, session['csrf']):
                abort(400, description='Невалиден CSRF token. Презареди страницата.')

    @app.template_filter('utc_date')
    def utc_date(value, local_input=False):
        if value is None or value == '':
            return '' if local_input else '—'
        try:
            return datetime.fromtimestamp(int(value), timezone.utc).strftime('%Y-%m-%dT%H:%M:%S' if local_input else '%d.%m.%Y %H:%M')
        except (ValueError, TypeError, OverflowError):
            return str(value)

    @app.template_filter('card_serial')
    def card_serial(value):
        text = str(value)
        return '-'.join(text[i:i + 3] for i in range(0, len(text), 3))

    @app.context_processor
    def context():
        address = urlsplit(request.host_url)
        hostname = address.hostname or 'localhost'
        if ':' in hostname:
            hostname = '[' + hostname + ']'
        headend_url = None
        try:
            headend_port = int(os.environ.get('HEADEND_PORT', ''))
            if 1 <= headend_port <= 65535:
                headend_url = urlunsplit((address.scheme, hostname + ':' + str(headend_port), '/', '', ''))
        except ValueError:
            pass
        return {'actor': g.actor, 'csrf_token': session.get('csrf'), 'labels': LABELS,
                'field_labels': FIELD_LABELS, 'headend_url': headend_url}

    @app.after_request
    def security_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        if request.path.startswith('/api/'):
            return jsonify(error=str(error)), 400
        return render_template('error.html', message=str(error)), 400

    @app.get('/healthz')
    def health():
        return jsonify(status='ok')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            actor = request.form.get('username', '')
            current = store.get_settings()
            if actor in ('admin', 'oper') and verify_password(request.form.get('password', ''), current.get(actor + '_password_hash', '')):
                session.clear()
                session.update(actor=actor, csrf=secrets.token_urlsafe(32))
                store.audit(actor, 'login', {})
                return redirect(url_for('listing', kind='cards'))
            flash('Невалиден потребител или парола.', 'error')
        return render_template('login.html')

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @app.get('/cas/')
    @authenticated()
    def dashboard():
        return redirect(url_for('listing', kind='cards'))

    @app.get('/manage/<kind>')
    @authenticated()
    def listing(kind):
        if kind not in TABLES:
            abort(404)
        rows = [_public(row) for row in store.list_rows(TABLES[kind])]
        query = request.args.get('q', '').casefold()
        if query:
            serial_query = re.sub(r'[ -]', '', query) if kind == 'cards' else ''
            rows = [row for row in rows if query in ' '.join(str(v) for v in row.values()).casefold()
                    or (serial_query.isdigit() and serial_query in str(row.get('serial_no', '')))]
        total = len(rows)
        page = max(1, request.args.get('page', 1, type=int))
        rows = rows[(page - 1) * 100:page * 100]
        live_ecmg = {}
        if kind == 'ecmg' and runtime and hasattr(runtime, 'status'):
            live_ecmg = {item['id']: item for item in runtime.status().get('ecmg', [])}
        return render_template('cards_listing.html' if kind == 'cards' else 'listing.html', kind=kind, rows=rows, total=total, page=page, query=query,
                               live_ecmg=live_ecmg)

    def ecmg_log_arguments():
        peer_id = request.args.get('peer_id') or None
        if peer_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,96}', peer_id):
            raise ValueError('Невалиден идентификатор на пиър')
        try:
            limit = int(request.args.get('limit', '100'))
        except ValueError:
            raise ValueError('Невалиден лимит на журнала') from None
        return peer_id, max(1, min(limit, 200))

    @app.get('/manage/ecmg/<int:row_id>/log')
    @authenticated('admin')
    def ecmg_log(row_id):
        row = store.get_row('tvcas_ecmg', row_id)
        if not row:
            abort(404)
        peer_id, limit = ecmg_log_arguments()
        return render_template('ecmg_log.html', row=_public(row), peer_id=peer_id or '', limit=limit)

    @app.get('/api/ecmg/<int:row_id>/diagnostics')
    @authenticated('admin')
    def ecmg_diagnostics(row_id):
        if not store.get_row('tvcas_ecmg', row_id):
            abort(404)
        peer_id, limit = ecmg_log_arguments()
        if not runtime or not hasattr(runtime, 'ecmg_diagnostics'):
            return jsonify(state='offline', running=False, peers=[], entries=[], retention_limit=1000)
        return jsonify(runtime.ecmg_diagnostics(row_id, peer_id=peer_id, limit=limit))

    @app.route('/manage/<kind>/new', methods=['GET', 'POST'])
    @app.route('/manage/<kind>/<int:row_id>', methods=['GET', 'POST'])
    @authenticated()
    def edit(kind, row_id=None):
        if kind not in TABLES:
            abort(404)
        if g.actor != 'admin' and (kind != 'cards' or row_id is None):
            abort(403)
        row = store.get_row(TABLES[kind], row_id) if row_id is not None else {}
        if row_id is not None and not row:
            abort(404)
        allowed = FIELDS[kind]
        if g.actor != 'admin':
            allowed = ('name', 'info', 'access_criteria', 'pair', 'start', 'finish')
        if request.method == 'POST':
            data = _parse_fields(request.form, allowed)
            if kind == 'cards':
                data = _card_update(row, data)
            if kind == 'cards' and row_id is None:
                data.setdefault('key', secrets.token_hex(16).upper())
            if kind == 'ecmg' and row_id is None:
                data['key'] = store.get_settings().get('ecm_key', '')
            if kind == 'cards' and row_id is None:
                try:
                    quantity = int(request.form.get('quantity', '1'))
                except ValueError:
                    raise ValueError('Невалиден брой карти') from None
                if not 1 <= quantity <= 5000:
                    raise ValueError('Броят трябва да е между 1 и 5000')
                if quantity > 1 and request.form.get('key'):
                    raise ValueError('При групово създаване ключовете се генерират поотделно')
                batch = []
                for offset in range(quantity):
                    item = dict(data, serial_no=data['serial_no'] + offset)
                    if quantity > 1:
                        item['key'] = secrets.token_hex(16).upper()
                    batch.append((item, None))
                saved_rows = store.save_rows(TABLES[kind], batch)
                saved = saved_rows[0]
                store.audit(g.actor, 'create_cards', {'first_id': saved['id'], 'count': quantity})
            else:
                saved = store.save_row(TABLES[kind], data, row_id)
                store.audit(g.actor, 'save_' + kind, {'id': saved['id']})
            card_changed() if kind == 'cards' else reload_runtime()
            flash('Запазено.', 'success')
            return redirect(url_for('listing', kind=kind))
        if not row:
            if kind == 'cards':
                serial = max([2099999999] + [int(x['serial_no']) for x in store.list_rows('tvcas_smartcards')]) + 1
                row = dict(serial_no=serial, access_criteria='00000000', start=int(time.time()), finish=int(time.time()) + 30*86400, type=1, pair=0, network_id=1, uid=15, status=1)
            elif kind == 'ecmg':
                row = dict(host=0, port=42000, network_id=1, timeout=60, packet_mode=0, ac_delay_start=0, ac_delay_stop=0, delay_start=5000, delay_stop=5000, transition_delay_start=5000, transition_delay_stop=5000, repetition_period=200, min_cp_duration=100, max_compute_time=8000, ecm_time1=60, ecm_time2=60, ecm_block_time=0)
            else:
                row = dict(host='127.0.0.1', port=41000, client_id=0x0b000001, network_id=1, protocol_version=2, packet_mode=0, bandwidth=64, repetition=60, period=30, period_messages=1, channel_test_delay=60, stream_test_delay=60, timeout=60, reload_sec=300, uid=15)
        mask = int(row.get('access_criteria') or '00000000', 16) if kind == 'cards' else 0
        template = 'card_edit.html' if kind == 'cards' else 'edit.html'
        return render_template(template, kind=kind, row=_public(row), fields=allowed, row_id=row_id,
                               mask_bits=[bool(mask & (1 << bit)) for bit in range(32)])

    @app.post('/manage/<kind>/<int:row_id>/delete')
    @authenticated('admin')
    def delete(kind, row_id):
        if kind not in TABLES:
            abort(404)
        store.delete_row(TABLES[kind], row_id)
        store.audit(g.actor, 'delete_' + kind, {'id': row_id})
        card_changed() if kind == 'cards' else reload_runtime()
        return redirect(url_for('listing', kind=kind))

    @app.post('/manage/<kind>/<int:row_id>/toggle')
    @authenticated()
    def toggle(kind, row_id):
        if kind not in ('ecmg', 'emmg'):
            abort(404)
        row = store.get_row(TABLES[kind], row_id)
        if not row:
            abort(404)
        enabled = 0 if row.get('enable') else 1
        store.save_row(TABLES[kind], {'enable': enabled}, row_id)
        store.audit(g.actor, 'enable_' + kind, {'id': row_id, 'enabled': enabled})
        reload_runtime()
        return redirect(url_for('listing', kind=kind))

    @app.get('/cards/<int:serial>/config.bin')
    @authenticated('admin')
    def card_config(serial):
        card = next((x for x in store.list_rows('tvcas_smartcards') if int(x['serial_no']) == serial), None)
        if not card:
            abort(404)
        binary = build_card_config(card, store.get_settings())
        store.audit(g.actor, 'export_card_config', {'serial_no': serial})
        return Response(binary, mimetype='application/octet-stream', headers={'Content-Disposition': f'attachment; filename="{config_filename(serial)}"'})

    @app.get('/cards/export.csv')
    @authenticated('admin')
    def export_csv():
        role = request.args.get('format', 'admin')
        if role not in CSV_HEADERS:
            abort(400)
        output = io.StringIO(newline='')
        writer = csv.DictWriter(output, CSV_HEADERS[role], delimiter=';', extrasaction='ignore', lineterminator='\n')
        writer.writeheader()
        writer.writerows(sorted(store.list_rows('tvcas_smartcards'), key=lambda r: int(r['serial_no'])))
        store.audit(g.actor, 'export_csv', {'format': role})
        return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="tvcas-{role}.csv"'})

    @app.post('/cards/import.csv')
    @authenticated('admin')
    def import_csv():
        upload = request.files.get('file')
        if not upload:
            raise ValueError('Избери CSV файл')
        try:
            reader = csv.DictReader(io.StringIO(upload.read().decode('utf-8-sig')), delimiter=';')
            if reader.fieldnames not in CSV_HEADERS.values():
                raise ValueError('Невалидна CSV заглавна линия')
            rows = list(reader)
        except UnicodeError:
            raise ValueError('CSV трябва да е UTF-8') from None
        existing = {int(x['serial_no']): x for x in store.list_rows('tvcas_smartcards')}
        prepared = []
        seen = set()
        for row in rows:
            if None in row or any(v is None for v in row.values()):
                raise ValueError('Невалиден брой CSV колони')
            data = _parse_fields(row, CARD_FIELDS)
            serial = data['serial_no']
            if not 2100000000 <= serial <= 2109999999:
                raise ValueError('CSV serial_no трябва да е 2100000000–2109999999')
            if serial in seen:
                raise ValueError('Повторен serial_no в CSV')
            seen.add(serial)
            if serial not in existing and 'key' not in data:
                raise ValueError('Нова карта изисква admin CSV с ключ')
            data = _card_update(existing.get(serial), data)
            prepared.append((data, existing.get(serial, {}).get('id')))
        # All rows are parsed and validated before the first mutation.
        store.save_rows('tvcas_smartcards', prepared)
        store.audit(g.actor, 'import_csv', {'count': len(prepared)})
        card_changed()
        flash(f'Внесени {len(prepared)} карти.', 'success')
        return redirect(url_for('listing', kind='cards'))

    @app.route('/settings', methods=['GET', 'POST'])
    @authenticated('admin')
    def settings_page():
        if request.method == 'POST':
            changes = {}
            for key in ('ident', 'trademark', 'zone', 'php_timezone'):
                if key in request.form:
                    changes[key] = request.form[key]
            for key in ('ecm_key', 'api_key'):
                if request.form.get(key):
                    changes[key] = request.form[key]
            if 'ecm_key' in changes and not re.fullmatch(r'[0-9a-fA-F]{64}', changes['ecm_key']):
                raise ValueError('ECM ключът е 64 шестнадесетични знака')
            if 'ident' in changes and not re.fullmatch(r'[0-9a-fA-F]{4}', changes['ident']):
                raise ValueError('CAID е 4 шестнадесетични знака')
            if changes.get('php_timezone'):
                from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
                try:
                    ZoneInfo(changes['php_timezone'])
                except ZoneInfoNotFoundError:
                    raise ValueError('Невалидна PHP часова зона') from None
            if changes.get('zone') and not re.fullmatch(r'[+-](?:0\d|1[0-4])[0-5]\d', changes['zone']):
                raise ValueError('UI zone трябва да е например +0200')
            for role in ('admin', 'oper'):
                if request.form.get(role + '_password'):
                    changes[role + '_password_hash'] = hash_password(request.form[role + '_password'])
            store.set_settings(changes)
            store.audit(g.actor, 'settings', {'fields': sorted(changes)})
            flash('Настройките са запазени. Съществуващите ECMG ключове са запазени.', 'success')
        cfg = store.get_settings()
        safe = {k: cfg.get(k, '') for k in ('ident', 'trademark', 'zone', 'php_timezone')}
        status = runtime.status() if runtime and hasattr(runtime, 'status') else {'state': 'offline', 'message': 'Генераторите не са стартирани от този уеб процес.'}
        return render_template('settings.html', settings=safe, has_ecm_key=bool(cfg.get('ecm_key')),
                               has_api_key=bool(cfg.get('api_key')), status=status,
                               runtime_enabled=cfg.get('runtime_enabled', False))

    @app.get('/audit')
    @authenticated('admin')
    def audit_log():
        rows = store.list_audit(limit=200)
        return render_template('audit.html', rows=rows)

    @app.get('/api/status')
    @authenticated()
    def api_status():
        return jsonify(runtime.status() if runtime and hasattr(runtime, 'status') else {'state': 'offline'})

    @app.route('/api/<kind>', methods=['GET', 'POST'])
    @app.route('/api/<kind>/<int:row_id>', methods=['GET', 'PATCH', 'DELETE'])
    @authenticated()
    def api_rows(kind, row_id=None):
        if kind not in TABLES:
            abort(404)
        if request.method == 'GET':
            row = store.get_row(TABLES[kind], row_id) if row_id else None
            if row_id and not row:
                abort(404)
            return jsonify(_public(row) if row_id else [_public(x) for x in store.list_rows(TABLES[kind])])
        if g.actor != 'admin':
            abort(403)
        if request.method == 'DELETE':
            store.delete_row(TABLES[kind], row_id)
            saved = {'deleted': row_id}
        else:
            data = _parse_fields(request.get_json(silent=True) or {}, FIELDS[kind])
            if kind == 'cards':
                data = _card_update(store.get_row(TABLES[kind], row_id) if row_id else None, data)
            if kind == 'cards' and row_id is None:
                data.setdefault('key', secrets.token_hex(16).upper())
            if kind == 'ecmg' and row_id is None:
                data['key'] = store.get_settings().get('ecm_key', '')
            saved = _public(store.save_row(TABLES[kind], data, row_id))
        store.audit(g.actor, 'api_' + request.method.lower() + '_' + kind, {'id': row_id or saved.get('id')})
        card_changed() if kind == 'cards' else reload_runtime()
        return jsonify(saved)

    @app.get('/api.php')
    def legacy_api():
        token = store.get_settings().get('api_key', '')
        supplied = request.args.get('api_key', '')
        def error(code):
            return Response(code, status=400, mimetype='text/plain')
        if not token or not hmac.compare_digest(str(token), supplied):
            return error('NOT_VALID_API_KEY')
        try:
            serial = int(request.args.get('serial_no', '0'))
        except ValueError:
            return error('SMARDCARD_NOT_FOUND')
        card = next((x for x in store.list_rows('tvcas_smartcards') if int(x['serial_no']) == serial), None)
        if not card or not serial:
            return error('SMARDCARD_NOT_FOUND')
        allowed = ('name', 'info', 'access_criteria', 'pair', 'start', 'finish')
        changes = {}
        for name in request.args:
            if name.startswith('set'):
                match = re.fullmatch(r'set\[([^\]]+)\]', name)
                if not match or match[1] not in allowed:
                    return error('UNKNOWN_SET_PARAMETER')
                field, value = match[1], request.args[name]
                checks = {'access_criteria': r'[0-9A-Fa-f]{8}', 'pair': r'[01]', 'start': r'\d{10}', 'finish': r'\d{10}'}
                if field in checks and not re.fullmatch(checks[field], value):
                    return error(field.upper() + '_ERROR')
                changes[field] = value
        if changes:
            try:
                original_mask = changes.get('access_criteria')
                changes = _parse_fields(changes, allowed)
                if original_mask is not None:
                    changes['access_criteria'] = original_mask  # Legacy API preserves text case.
                changes = _card_update(card, changes)
                card = store.save_row('tvcas_smartcards', changes, card['id'])
            except ValueError:
                return error('START_ERROR' if 'start' in changes else 'FINISH_ERROR')
            store.audit('API', 'update_card', {'serial_no': serial, 'fields': sorted(changes)})
            card_changed()
        # mysqli text-protocol fetch_assoc returned numbers as strings by default.
        # Keep that wire contract on the legacy endpoint only; JSON APIs stay typed.
        return jsonify({key: None if card.get(key) is None else str(card[key])
                        for key in ('serial_no',) + allowed})

    return app
