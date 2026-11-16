"""Versioned reports, deterministic comparisons and bounded coverage claims."""
from collections import Counter

SCHEMA_VERSION = 1
STATUSES = {'PASS', 'FAIL', 'WARN', 'INFO', 'EXCEPTED'}


def validate(data):
    if not isinstance(data, dict) or data.get('schema_version', 1) != 1:
        raise ValueError('Versión de reporte no soportada')
    if not isinstance(data.get('host'), str) or not isinstance(data.get('findings'), list):
        raise ValueError('Reporte inválido')
    seen = set()
    for item in data['findings']:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or item.get('status') not in STATUSES or item['id'] in seen:
            raise ValueError('Hallazgos inválidos o duplicados')
        seen.add(item['id'])
    return {item['id']: item for item in data['findings']}


def compare(previous, current):
    old, new = validate(previous), validate(current)
    if previous['host'] != current['host'] or previous.get('policy', {}).get('profile', 'servidor') != current.get('policy', {}).get('profile', 'servidor'):
        raise ValueError('Comparación requiere el mismo host y perfil')
    rows = []
    for identifier in sorted(old.keys() | new.keys()):
        before, after = old.get(identifier), new.get(identifier)
        if before is None: change = 'added'
        elif after is None: change = 'removed'
        elif before['status'] == after['status']: change = 'unchanged'
        elif before['status'] == 'FAIL' and after['status'] == 'PASS': change = 'resolved'
        else: change = 'changed'
        rows.append({'id': identifier, 'change': change, 'before': before['status'] if before else None, 'after': after['status'] if after else None})
    return {'previous_generated_at': previous.get('generated_at'), 'changes': rows, 'counts': dict(Counter(row['change'] for row in rows))}


def enrich(data, elapsed):
    validate(data)
    counts = Counter(item['status'] for item in data['findings'])
    data['schema_version'] = SCHEMA_VERSION
    data['execution'] = {'duration_seconds': round(elapsed, 6), 'mode': 'read_only_audit'}
    data['coverage'] = {'total': len(data['findings']), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'review': counts['WARN'] + counts['INFO'], 'excepted': counts['EXCEPTED'], 'failed_by_severity': dict(Counter(item['severity'] for item in data['findings'] if item['status'] == 'FAIL')), 'limitation': 'WARN/INFO requieren revisión; no equivalen todos a errores de ejecución. No mide conformidad CIS ni cobertura completa del host.'}
    return data
