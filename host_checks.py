"""Read-only backend and service probes. Unknown or partial evidence never passes."""
import json
import re


def firewall_extensions(run, which, finding, include_ipv4=False):
    results = []
    def emit(suffix, title, status, evidence, expected):
        results.append(finding('CIS-LITE-006-' + suffix, title, status, 'high', evidence,
            'Revise reglas, interfaces y persistencia; no active ni reemplace reglas sin validar el acceso.', expected=expected))
    nft = which('nft')
    coverage = set()
    evidence = 'nft no disponible; filtrado no verificado'
    if nft:
        code, out, err = run([nft, '-j', 'list', 'ruleset'])
        evidence = f'código={code}; {err or "consulta JSON"}'
        if code == 0:
            try:
                data = json.loads(out)
                entries = data['nftables']
                if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
                    raise ValueError('estructura nftables inválida')
                chains = [item['chain'] for item in entries if 'chain' in item]
                if not all(isinstance(chain, dict) for chain in chains):
                    raise ValueError('cadena inválida')
                observed = []
                for chain in chains:
                    if chain.get('hook') != 'input':
                        continue
                    family, policy = chain.get('family'), chain.get('policy')
                    observed.append(f'{family}:{chain.get("name")}:{policy}')
                    if policy == 'drop':
                        coverage.update({'IPv4', 'IPv6'} if family == 'inet' else ({'IPv4'} if family == 'ip' else ({'IPv6'} if family == 'ip6' else set())))
                evidence = '; '.join(observed) or 'sin cadenas input identificables'
            except (ValueError, TypeError, KeyError) as exc:
                evidence = f'JSON inconcluso: {exc}'
                coverage.clear()
    emit('NFT', 'nftables: políticas input IPv4/IPv6', 'PASS' if coverage == {'IPv4', 'IPv6'} else 'WARN',
         evidence + '; no evalúa reglas completas, prioridades, forwarding ni persistencia',
         'Identificar políticas input drop para IPv4 e IPv6; aprobación limitada a ese criterio.')
    firewalld = which('firewall-cmd')
    status, details = 'WARN', 'firewall-cmd no disponible'
    if firewalld:
        code, out, err = run([firewalld, '--state'])
        details = f'estado: {out or err}; código={code}'
        if code == 0 and out == 'running':
            code, out, err = run([firewalld, '--get-active-zones'])
            zones = [line.strip() for line in out.splitlines() if line and not line[0].isspace()]
            valid = code == 0 and 0 < len(zones) <= 32 and all(re.fullmatch(r'[A-Za-z0-9_-]+', zone) for zone in zones)
            targets = []
            if valid:
                for zone in zones:
                    rc, value, error = run([firewalld, '--zone=' + zone, '--get-target'])
                    targets.append(f'{zone}:{value if rc == 0 else "desconocido"}')
                    valid = valid and rc == 0 and value in {'DROP', 'REJECT'}
                status = 'PASS' if valid else 'WARN'
            details += '; zonas=' + (','.join(targets) if targets else 'no evaluables')
    emit('FIREWALLD', 'firewalld: zonas activas', status, details + '; runtime, no acredita reglas ni persistencia',
         'Gestor running y todas las zonas activas con target DROP/REJECT; alcance limitado al target.')
    for suffix, binary in ([('IPV4', 'iptables')] if include_ipv4 else []) + [('IPV6', 'ip6tables')]:
        executable = which(binary)
        status, details = 'WARN', binary + ' no disponible'
        if executable:
            code, out, err = run([executable, '-S'])
            policies = [line.split() for line in out.splitlines() if line.split()[:2] == ['-P', 'INPUT']]
            status = 'PASS' if code == 0 and policies == [['-P', 'INPUT', 'DROP']] else 'WARN'
            details = f'código={code}; ' + ('; '.join(' '.join(p) for p in policies) if code == 0 else err or out)
        emit(suffix, binary + ': política INPUT', status, details + '; no evalúa reglas completas ni persistencia', 'Una única política INPUT DROP consultada correctamente.')
    return results


SERVICES = {
    'TELNET': (['telnet.socket', 'telnet.service', 'telnetd.service'], {'telnetd', 'in.telnetd'}, {('tcp', 23)}),
    'RSH': (['rsh.socket', 'rsh.service', 'rlogin.socket', 'rlogin.service'], {'rshd', 'in.rshd', 'rlogind', 'in.rlogind'}, {('tcp', 514), ('tcp', 513)}),
    'REXEC': (['rexec.socket', 'rexec.service'], {'rexecd', 'in.rexecd'}, {('tcp', 512)}),
    'TFTP': (['tftp.socket', 'tftp.service', 'tftpd.service'], {'tftpd', 'in.tftpd'}, {('udp', 69)}),
    'XINETD': (['xinetd.service'], {'xinetd'}, set()),
}


def parse_listeners(output):
    ports = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in {'tcp', 'udp'}:
            raise ValueError('salida ss no reconocida')
        address, separator, port = parts[4].rpartition(':')
        if not separator or not port.isdigit() or not 0 <= int(port) <= 65535:
            raise ValueError('puerto no reconocido')
        ports.add((parts[0], int(port)))
    return ports


def services(run, which, finding):
    ss, ps, systemctl = which('ss'), which('ps'), which('systemctl')
    ports, process_names, listeners_ok, processes_ok = set(), set(), False, False
    if ss:
        code, out, _ = run([ss, '-H', '-lntu'])
        if code == 0:
            try:
                ports = parse_listeners(out)
                listeners_ok = True
            except ValueError:
                pass
    if ps:
        code, out, _ = run([ps, '-eo', 'comm='])
        if code == 0 and out.strip():
            process_names = {line.strip().rsplit('/', 1)[-1] for line in out.splitlines()}
            processes_ok = True
    results = []
    for label, (units, daemons, conventional_ports) in SERVICES.items():
        active, enabled, units_ok = [], [], bool(systemctl)
        observations = []
        if systemctl:
            for unit in units:
                code, out, _ = run([systemctl, 'show', unit, '--property=LoadState,ActiveState,UnitFileState'])
                values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
                load, state, boot = (values.get(k) for k in ('LoadState', 'ActiveState', 'UnitFileState'))
                if code != 0 or load not in {'loaded', 'not-found', 'masked'} or state not in {'active', 'inactive', 'failed'}:
                    units_ok = False
                if load != 'not-found' and boot not in {'enabled', 'enabled-runtime', 'disabled', 'static', 'indirect', 'masked', 'masked-runtime', 'generated', 'transient', 'alias', 'linked', 'linked-runtime'}:
                    units_ok = False
                if load != 'not-found' and state == 'active':
                    active.append(unit)
                if boot in {'enabled', 'enabled-runtime'}:
                    enabled.append(unit)
                if state == 'failed':
                    units_ok = False
                observations.append(f'{unit}={load}/{state}/{boot}')
        running = sorted(daemons & process_names)
        listening = sorted(conventional_ports & ports)
        if active or running:
            status = 'FAIL'
        elif enabled or listening or not (units_ok and listeners_ok and processes_ok):
            status = 'WARN'
        else:
            status = 'PASS'
        evidence = '; '.join(observations) + f'; procesos={running}; puertos convencionales={listening}; ss_completo={listeners_ok}; ps_consultable={processes_ok}'
        results.append(finding('CIS-LITE-005-' + label, 'Servicio heredado ' + label, status, 'medium', evidence,
            'Revise unidades, procesos y puertos antes de deshabilitar; un puerto convencional no identifica por sí solo el servicio.',
            expected='Sin unidad/proceso heredado activo, sin habilitación al arranque ni escucha convencional bajo la visibilidad disponible.'))
    return results
