"""Six-protocol rendering, public TLS deployment and maintenance.

No live operations on import. Reuses the non-overwriting legacy lifecycle.
"""
import base64
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import time
import urllib.parse
import uuid
from common import download_asset, endpoint, secure_write, server_configs

SERVICES = ('mpn-xray', 'mpn-hysteria', 'mpn-extra')
CERT_UNITS = ('mpn-certificate.service', 'mpn-certificate.timer')
MARKER = 'multi-protocol-node/v2-six'
PORT_DEFAULTS = {'reality_port': 443, 'trojan_port': 8443, 'hysteria_port': 24443,
                 'tuic_port': 8443, 'anytls_port': 9443, 'ss_port': 8388}


def bindings(values, acme=False):
    tcp = [values[k] for k in ('reality_port', 'trojan_port', 'anytls_port', 'ss_port')]
    udp = [values[k] for k in ('hysteria_port', 'tuic_port', 'ss_port')]
    if acme:
        tcp += [80]
    if any(type(p) is not int or not 1 <= p <= 65535 for p in tcp + udp):
        raise ValueError('Ports must be integers from 1 to 65535')
    if len(set(tcp)) != len(tcp) or len(set(udp)) != len(udp):
        raise ValueError('Two services claim the same transport/port (TCP80 is reserved for ACME)')
    return {'tcp': tcp, 'udp': udp}


def tls_name(m):
    return m.get('tls_name') or m['host']


def configs(m, private_key, root):
    xray, hysteria = server_configs(m, private_key, root)
    # Keep SS in Xray. REALITY and the other TCP/QUIC protocols share sing-box,
    # matching the cross-core interoperability path verified during deployment.
    xray['inbounds'] = [x for x in xray['inbounds'] if x['protocol'] == 'shadowsocks']
    cert, key = root / 'public-fullchain.pem', root / 'public-key.pem'
    hysteria['tls'] = {'cert': str(cert), 'key': str(key)}
    tls = {'enabled': True, 'certificate_path': str(cert), 'key_path': str(key), 'min_version': '1.3'}
    inbound = [
        {'type': 'vless', 'tag': 'reality', 'listen': '::', 'listen_port': m['reality_port'],
         'users': [{'uuid': m['uuid'], 'flow': 'xtls-rprx-vision'}],
         'tls': {'enabled': True, 'server_name': m['target'], 'reality': {'enabled': True,
             'handshake': {'server': m['target'], 'server_port': 443},
             'private_key': private_key, 'short_id': [m['short_id']]}}},
        {'type': 'trojan', 'tag': 'trojan', 'listen': '::', 'listen_port': m['trojan_port'],
         'users': [{'password': m['trojan_password']}], 'tls': tls},
        {'type': 'anytls', 'tag': 'anytls', 'listen': '::', 'listen_port': m['anytls_port'],
         'users': [{'password': m['anytls_password']}], 'tls': tls},
        {'type': 'tuic', 'tag': 'tuic', 'listen': '::', 'listen_port': m['tuic_port'],
         'users': [{'uuid': m['tuic_uuid'], 'password': m['tuic_password']}],
         'congestion_control': 'bbr', 'zero_rtt_handshake': False, 'tls': dict(tls, alpn=['h3'])}]
    singbox = {'log': {'level': 'warn'}, 'inbounds': inbound, 'outbounds': [{'type': 'direct', 'tag': 'direct'}],
               'route': {'rules': [{'ip_is_private': True, 'action': 'reject'}], 'final': 'direct'}}
    return {'xray.json': xray, 'hysteria.json': hysteria, 'sing-box.json': singbox}


def outbounds(m):
    ip = m['host']; tls = {'enabled': True, 'server_name': tls_name(m), 'insecure': False}
    return [
        {'type': 'vless', 'tag': '01-REALITY', 'server': ip, 'server_port': m['reality_port'],
         'uuid': m['uuid'], 'flow': 'xtls-rprx-vision', 'tls': {'enabled': True, 'server_name': m['target'],
             'utls': {'enabled': True, 'fingerprint': 'chrome'},
             'reality': {'enabled': True, 'public_key': m['public_key'], 'short_id': m['short_id']}}},
        {'type': 'trojan', 'tag': '02-Trojan', 'server': ip, 'server_port': m['trojan_port'],
         'password': m['trojan_password'], 'tls': tls},
        {'type': 'hysteria2', 'tag': '03-Hysteria2', 'server': ip, 'server_port': m['hysteria_port'],
         'password': m['hy_password'], 'tls': tls},
        {'type': 'tuic', 'tag': '04-TUIC', 'server': ip, 'server_port': m['tuic_port'],
         'uuid': m['tuic_uuid'], 'password': m['tuic_password'], 'congestion_control': 'bbr',
         'zero_rtt_handshake': False, 'tls': dict(tls, alpn=['h3'])},
        {'type': 'anytls', 'tag': '05-AnyTLS', 'server': ip, 'server_port': m['anytls_port'],
         'password': m['anytls_password'], 'tls': tls},
        {'type': 'shadowsocks', 'tag': '06-Shadowsocks', 'server': ip, 'server_port': m['ss_port'],
         'method': 'chacha20-ietf-poly1305', 'password': m['ss_password']}]


def links(m):
    q = urllib.parse.urlencode
    esc = lambda value: urllib.parse.quote(value, safe='')
    addr = lambda port: endpoint(m['host'], port)
    sni = tls_name(m)
    reality = q({'encryption': 'none', 'security': 'reality', 'sni': m['target'], 'fp': 'chrome',
                 'pbk': m['public_key'], 'sid': m['short_id'], 'type': 'tcp', 'flow': 'xtls-rprx-vision'})
    ss_auth = base64.urlsafe_b64encode(('chacha20-ietf-poly1305:' + m['ss_password']).encode()).decode().rstrip('=')
    return {
        '01-REALITY': f"vless://{m['uuid']}@{addr(m['reality_port'])}?{reality}#Node-REALITY",
        '02-Trojan': f"trojan://{esc(m['trojan_password'])}@{addr(m['trojan_port'])}?" + q({'security': 'tls', 'sni': sni, 'type': 'tcp'}) + '#Node-Trojan',
        '03-Hysteria2': f"hysteria2://{esc(m['hy_password'])}@{addr(m['hysteria_port'])}/?" + q({'sni': sni, 'insecure': '0'}) + '#Node-Hysteria2',
        '04-TUIC': f"tuic://{m['tuic_uuid']}:{esc(m['tuic_password'])}@{addr(m['tuic_port'])}?" + q({'sni': sni, 'alpn': 'h3', 'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'allow_insecure': '0'}) + '#Node-TUIC',
        '05-AnyTLS': f"anytls://{esc(m['anytls_password'])}@{addr(m['anytls_port'])}/?" + q({'sni': sni, 'insecure': '0'}) + '#Node-AnyTLS',
        '06-Shadowsocks': f"ss://{ss_auth}@{addr(m['ss_port'])}#Node-SS"}


def client_profile(m):
    obs = outbounds(m)
    return {'log': {'level': 'warn'}, 'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': 10808}],
            'outbounds': [{'type': 'selector', 'tag': 'Select', 'outbounds': [o['tag'] for o in obs],
                           'default': '01-REALITY'}] + obs, 'route': {'final': 'Select'}}


def mihomo_profile(m):
    proxies = []
    for ob in outbounds(m):
        p = {'name': ob['tag'], 'type': ob['type'], 'server': m['host'], 'port': ob['server_port']}
        if ob['type'] == 'vless':
            p.update({'uuid': m['uuid'], 'flow': 'xtls-rprx-vision', 'network': 'tcp', 'tls': True,
                      'udp': True, 'servername': m['target'], 'client-fingerprint': 'chrome',
                      'reality-opts': {'public-key': m['public_key'], 'short-id': m['short_id']}})
        elif ob['type'] == 'shadowsocks':
            p.update({'type': 'ss', 'cipher': 'chacha20-ietf-poly1305', 'password': m['ss_password'], 'udp': True})
        else:
            p.update({'password': ob['password'], 'skip-cert-verify': False})
            p['servername' if ob['type'] == 'tuic' else 'sni'] = tls_name(m)
            if ob['type'] == 'tuic':
                p.update({'uuid': m['tuic_uuid'], 'alpn': ['h3'], 'congestion-controller': 'bbr', 'udp-relay-mode': 'native'})
        proxies.append(p)
    # JSON is valid YAML 1.2, avoiding an extra YAML runtime dependency.
    # SS is explicitly opt-in, not automatically selected by latency tests.
    preferred = [p['name'] for p in proxies if p['type'] != 'ss']
    return {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'proxies': proxies,
            'proxy-groups': [{'name': 'Select', 'type': 'select', 'proxies': ['01-REALITY', 'Auto'] + [p['name'] for p in proxies if p['name'] != '01-REALITY']},
                             {'name': 'Auto', 'type': 'url-test', 'proxies': preferred,
                              'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50}],
            'rules': ['MATCH,Select']}


def check_provided(args, run):
    cert, key = Path(args.cert_file), Path(args.key_file)
    if not cert.is_file() or not key.is_file():
        raise ValueError('Provided certificate and key must exist on the target server')
    name = args.tls_name or args.host
    try:
        ipaddress.ip_address(name); identity = ['-verify_ip', name]
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9.-]+', name) or name.startswith('-'):
            raise ValueError('Invalid TLS hostname')
        identity = ['-verify_hostname', name]
    run('openssl', 'verify', *identity, '-untrusted', str(cert), str(cert))
    run('openssl', 'x509', '-in', str(cert), '-checkend', '86400', '-noout')
    public_cert = run('openssl', 'x509', '-in', str(cert), '-pubkey', '-noout').stdout.strip()
    public_key = run('openssl', 'pkey', '-in', str(key), '-pubout').stdout.strip()
    if public_cert != public_key:
        raise ValueError('Certificate and private key do not match')


def issue_certificate(args, root, lock, run):
    if args.tls_mode == 'provided':
        for src, dst in [(args.cert_file, 'public-fullchain.pem'), (args.key_file, 'public-key.pem')]:
            secure_write(root / dst, Path(src).read_text())
        return
    download_asset(lock['acme.sh'], root / 'acme.sh')
    (root / 'acme').mkdir(mode=0o700)
    # All ACME state stays inside our owned directory. No global cron/profile changes.
    secure_write(root / 'acme/account.conf', "AUTO_UPGRADE='0'\n")
    cmd = ['/bin/sh', str(root / 'acme.sh'), '--home', str(root / 'acme')]
    run(*cmd, '--issue', '--server', 'letsencrypt', '--standalone', '-d', args.host,
        '--certificate-profile', 'shortlived', '--days', '2', '--keylength', 'ec-256', timeout=600)
    run(*cmd, '--install-cert', '-d', args.host, '--ecc', '--key-file', str(root / 'public-key.pem'),
        '--fullchain-file', str(root / 'public-fullchain.pem'), timeout=90)


def unit_contents(root):
    commands = [f'{root}/xray run -config {root}/xray.json', f'{root}/hysteria server -c {root}/hysteria.json',
                f'{root}/sing-box run -c {root}/sing-box.json']
    units = {}
    for name, cmd in zip(SERVICES, commands):
        units[name + '.service'] = f'''[Unit]
Description=Multi Protocol Node ({name})
After=network-online.target
Wants=network-online.target
[Service]
ExecStart={cmd}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''
    return units


def cert_units(root):
    return {'mpn-certificate.service': f'''[Unit]
Description=Renew Multi Protocol Node IP certificate
After=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/sh {root}/acme.sh --cron --home {root}/acme
UMask=0077
TimeoutStartSec=600
''', 'mpn-certificate.timer': '''[Unit]
Description=Check Multi Protocol Node certificate every six hours
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true
Unit=mpn-certificate.service
[Install]
WantedBy=timers.target
'''}


def install(args, api):
    api.preflight(args)
    root, units_dir, run = api.ROOT, api.UNIT_DIR, api.run
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(api.platform.machine())
    if not arch:
        raise ValueError('Unsupported server architecture')
    lock = json.loads(Path(args.lock).read_text())
    created = []
    root.mkdir(mode=0o700)
    try:
        for name in ('xray', 'hysteria', 'sing-box'):
            download_asset(lock[name]['assets']['linux-' + arch], root / name,
                           zip_member='xray' if name == 'xray' else None,
                           tar_member='sing-box' if name == 'sing-box' else None)
        private, public = api.parse_keys(run(str(root / 'xray'), 'x25519').stdout)
        m = {'schema': 2, 'profile': 'six', 'host': args.host, 'target': args.target, 'tls_mode': args.tls_mode,
             'tls_name': args.host if args.tls_mode == 'public-ip' else (args.tls_name or args.host),
             'uuid': str(uuid.uuid4()), 'short_id': secrets.token_hex(8), 'public_key': public,
             'tuic_uuid': str(uuid.uuid4()), **{k: getattr(args, k) for k in PORT_DEFAULTS}}
        for key in ('ss_password', 'hy_password', 'trojan_password', 'anytls_password', 'tuic_password'):
            m[key] = secrets.token_urlsafe(32)
        issue_certificate(args, root, lock, run)
        for name, config in configs(m, private, root).items():
            secure_write(root / name, json.dumps(config, indent=2))
        run(str(root / 'xray'), 'run', '-test', '-config', str(root / 'xray.json'))
        run(str(root / 'sing-box'), 'check', '-c', str(root / 'sing-box.json'))
        secure_write(root / 'client.json', json.dumps(m, indent=2))
        secure_write(root / 'versions.json', json.dumps(lock, indent=2))
        contents = unit_contents(root)
        if args.tls_mode == 'public-ip':
            contents.update(cert_units(root))
        for name, body in contents.items():
            unit = units_dir / name
            with unit.open('x') as f:
                created.append(unit)
                f.write(body)
            unit.chmod(0o644)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', *SERVICES)
        time.sleep(3)
        run('systemctl', 'is-active', '--quiet', *SERVICES)
        if args.tls_mode == 'public-ip':
            run('/bin/sh', str(root / 'acme.sh'), '--home', str(root / 'acme'), '--install-cert', '-d', args.host,
                '--ecc', '--key-file', str(root / 'public-key.pem'), '--fullchain-file', str(root / 'public-fullchain.pem'),
                '--reloadcmd', 'systemctl restart mpn-hysteria mpn-extra', timeout=90)
            run('systemctl', 'enable', '--now', 'mpn-certificate.timer')
            run('systemctl', 'start', 'mpn-certificate.service', timeout=600)
        secure_write(root / 'managed-units.json', json.dumps(list(contents)))
        secure_write(root / 'managed-by', MARKER)
        print('Six protocols configured; verify all six from outside this VPS.')
    except BaseException:
        # Stop renewal before proxy services; never remove unrelated units.
        for unit in reversed(created):
            run('systemctl', 'disable', '--now', unit.name, check=False)
            unit.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload', check=False)
        shutil.rmtree(root)
        raise


def uninstall(api):
    root, directory, run = api.ROOT, api.UNIT_DIR, api.run
    names = json.loads((root / 'managed-units.json').read_text())
    permitted = {s + '.service' for s in SERVICES} | set(CERT_UNITS)
    required = {s + '.service' for s in SERVICES}
    if not isinstance(names, list) or len(names) != len(set(names)) or not required <= set(names) <= permitted:
        raise ValueError('Invalid owned-unit manifest; inspect manually')
    for name in names:
        f = directory / name
        if f.is_symlink() or not f.is_file():
            raise ValueError('Managed unit changed: ' + name)
        content = f.read_text()
        expected = 'Unit=mpn-certificate.service' if name.endswith('.timer') else (
            f'ExecStart=/bin/sh {root}/acme.sh' if name == 'mpn-certificate.service' else f'ExecStart={root}/')
        if expected not in content:
            raise ValueError('Unit ownership changed: ' + name)
    for name in sorted(names, key=lambda n: (not n.endswith('.timer'), not n.startswith('mpn-certificate'))):
        run('systemctl', 'disable', '--now', name)
    for name in names:
        (directory / name).unlink()
    run('systemctl', 'daemon-reload')
    shutil.rmtree(root)
    print('Removed owned proxy services, renewal timer and certificate state; SSH/firewall untouched.')
