"""Explicit audit profiles and host-bound, expiring risk exceptions."""
import copy
from datetime import datetime, timezone
import json
import re

PROFILES = {
    'servidor': 'Criterios habituales; contraseña SSH consultiva y root directo prohibido.',
    'laboratorio': 'Root por llave se advierte para revisión; root yes sigue siendo incumplimiento.',
    'expuesto': 'Contraseña SSH conocida como habilitada incumple el perfil; MFA exige validación adicional.',
}


def expiry(value):
    if not isinstance(value, str):raise ValueError('expires_at debe ser una fecha ISO8601 con zona horaria.')
    try:
        result = datetime.fromisoformat(value[:-1] + '+00:00' if value.endswith('Z') else value)
        if result.tzinfo is None or result.utcoffset() is None:raise ValueError('sin zona horaria')
        return result
    except ValueError as exc:raise ValueError('expires_at inválido o sin zona horaria.') from exc


def validate_document(document):
    if not isinstance(document, dict) or set(document) != {'version', 'exceptions'} or type(document['version']) is not int or document['version'] != 1:
        raise ValueError('El documento requiere version=1 y exceptions; no se aceptan campos desconocidos.')
    entries = document['exceptions']
    if not isinstance(entries, list) or len(entries) > 1000:raise ValueError('exceptions debe ser una lista de hasta 1000 entradas.')
    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'id', 'host', 'reason', 'responsible', 'expires_at'}:
            raise ValueError('Cada excepción requiere id, host, reason, responsible y expires_at.')
        if not all(isinstance(value, str) and value.strip() and len(value) <= 4096 for value in entry.values()):
            raise ValueError('Los campos de excepción deben ser textos no vacíos y acotados.')
        value = {key: data.strip() for key, data in entry.items()}
        if not re.fullmatch(r'CIS-LITE-[0-9]{3}(?:-[A-Z0-9]+)*', value['id']):raise ValueError('ID de excepción inválido; se exige coincidencia exacta.')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', value['host']):raise ValueError('Host inválido; no se admiten comodines.')
        key = (value['host'], value['id'])
        if key in seen:raise ValueError('Excepción duplicada para el mismo host y control.')
        seen.add(key)
        value['expires_at'] = expiry(value['expires_at']).isoformat()
        result.append(value)
    return result


def load(path):
    with path.open('rb') as stream:content = stream.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:raise ValueError('El archivo de excepciones supera 1 MiB.')
    try:return validate_document(json.loads(content.decode('utf-8')))
    except (UnicodeError, json.JSONDecodeError) as exc:raise ValueError('Archivo de excepciones no es JSON UTF-8 válido.') from exc


def evaluate(report, profile='servidor', entries=None, now=None):
    if profile not in PROFILES:raise ValueError('Perfil desconocido.')
    entries = validate_document({'version': 1, 'exceptions': [] if entries is None else entries})
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:raise ValueError('La hora de evaluación requiere zona horaria.')
    data = copy.deepcopy(report)
    for item in data['findings']:
        item['baseline_status'] = item['status']
        item['profile'] = profile
        item['exception'] = {}
        observed = item.get('observed', {})
        family = '-'.join(item['id'].split('-')[:3])
        if profile == 'laboratorio' and family == 'CIS-LITE-003' and item['status'] == 'FAIL' and observed.get('permitrootlogin') in {'without-password', 'prohibit-password'}:
            item.update(status='WARN', remediable=False,
                        expected='Preferir root no; el acceso root por llave requiere revisión del laboratorio.',
                        recommendation='Documente la necesidad de root por llave o configure PermitRootLogin no tras comprobar acceso alternativo.')
        if profile == 'expuesto' and family == 'CIS-LITE-004' and observed.get('passwordauthentication') == 'yes':
            item.update(status='FAIL', severity='high', expected='PasswordAuthentication no para el perfil expuesto.')
        if profile == 'expuesto' and family == 'CIS-LITE-007' and item['status'] == 'INFO':
            item.update(status='WARN', recommendation='Verifique los factores independientes y la implementación de autenticación; una secuencia no certifica MFA.')
        item['policy_status'] = item['status']
    by_id = {item['id']: item for item in data['findings']}
    records = []
    for entry in entries:
        record = dict(entry)
        item = by_id.get(entry['id'])
        if entry['host'] != data['host']:state = 'other_host'
        elif expiry(entry['expires_at']) <= now:state = 'expired'
        elif item is None:state = 'unmatched'
        elif item['status'] not in {'FAIL', 'WARN'}:state = 'not_needed'
        else:state = 'applied'
        record['state'] = state
        if item is not None and entry['host'] == data['host']:
            record['policy_status'] = item['policy_status']
            item['exception'] = dict(record)
        if state == 'applied':
            item['original_recommendation'] = item['recommendation']
            item.update(status='EXCEPTED', remediable=False, recommendation='Excepción vigente: revisar con su responsable antes del vencimiento.')
        records.append(record)
    states = ('PASS', 'FAIL', 'WARN', 'INFO') + (('EXCEPTED',) if any(f['status'] == 'EXCEPTED' for f in data['findings']) else ())
    data['summary'] = {state: sum(item['status'] == state for item in data['findings']) for state in states}
    data['policy'] = {'version': 1, 'profile': profile, 'description': PROFILES[profile],
        'evaluated_at': now.isoformat(), 'exceptions': records,
        'exception_summary': {state: sum(record['state'] == state for record in records) for state in ('applied', 'expired', 'unmatched', 'other_host', 'not_needed')}}
    return data
