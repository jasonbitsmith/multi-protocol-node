#!/usr/bin/env python3
"""Run on a Debian/Ubuntu systemd host. Refuses to overwrite an installation."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from common import ROOT, SERVICES, download_asset, secure_write, server_configs, validate_options

UNIT_DIR = Path('/etc/systemd/system')
MARKER = 'multi-protocol-node/v1'


def run(*args, check=True, timeout=30, **kw):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=timeout, **kw)


def preflight(args):
    import six_protocols as six
    extended = getattr(args, 'profile', 'three') == 'six'
    validate_options(args.host, args.target, (args.reality_port, args.hysteria_port, args.ss_port))
    if ipaddress.ip_address(args.host).version != 4:
        raise ValueError('This release requires a public IPv4 address')
    release = Path('/etc/os-release').read_text()
    if not any(line in release.splitlines() for line in ('ID=debian', 'ID=ubuntu')):
        raise RuntimeError('Only Debian/Ubuntu are supported')
    if not Path('/run/systemd/system').exists():
        raise RuntimeError('A running systemd is required')
    for cmd in ('curl', 'openssl', 'ss', 'systemctl'):
        if not shutil.which(cmd):
            raise RuntimeError('Missing prerequisite: ' + cmd)
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError(f'{ROOT} already exists; use status/export, never overwrite')
    units = list(six.SERVICES) + list(six.CERT_UNITS) if extended else list(SERVICES)
    for service in units:
        unit_name = service if service.endswith(('.service', '.timer')) else service + '.service'
        if (UNIT_DIR / unit_name).exists() or run('systemctl', 'cat', service, check=False).returncode == 0:
            raise RuntimeError('Existing unit: ' + service)
    ports_by_proto = (six.bindings(vars(args), args.tls_mode == 'public-ip') if extended else
                      {'tcp': [args.reality_port, args.ss_port], 'udp': [args.hysteria_port, args.ss_port]})
    if extended:
        if args.tls_mode == 'public-ip':
            if not shutil.which('socat'):
                raise RuntimeError('public-ip certificates require socat for HTTP-01 on TCP80')
            if args.tls_name or args.cert_file or args.key_file:
                raise ValueError('public-ip mode does not accept provided certificate options')
        else:
            if not args.cert_file or not args.key_file:
                raise ValueError('provided mode requires --cert-file and --key-file on the target server')
            six.check_provided(args, run)
    for proto, ports in ports_by_proto.items():
        flag = '-lntH' if proto == 'tcp' else '-lnuH'
        for port in ports:
            if run('ss', flag, f'sport = :{port}').stdout.strip():
                raise RuntimeError(f'{proto.upper()} {port} is occupied')
    # Never flush or silently replace an existing firewall. Explicit review bypass
    # only acknowledges that the operator has already opened required ports.
    if not args.firewall_reviewed:
        if shutil.which('nft') and run('nft', 'list', 'ruleset').stdout.strip():
            raise RuntimeError('Existing nftables rules: review ports, then use --firewall-reviewed')
        for cmd in ('iptables', 'ip6tables'):
            if shutil.which(cmd):
                rules = run(cmd, '-S').stdout.splitlines()
                if any(line.startswith('-A ') or (line.startswith('-P ') and not line.endswith(' ACCEPT')) for line in rules):
                    raise RuntimeError('Existing firewall rules: review ports, then use --firewall-reviewed')
    tls = run('openssl', 's_client', '-connect', args.target + ':443', '-servername', args.target,
              '-tls1_3', '-alpn', 'h2', '-verify_return_error', input='')
    if 'ALPN protocol: h2' not in tls.stdout:
        raise RuntimeError('Target must negotiate TLS 1.3 with h2 from this server')


def parse_keys(text):
    values = {a.lower().replace(' ', ''): b.strip() for a, b in
              (line.split(':', 1) for line in text.splitlines() if ':' in line)}
    public = values.get('password(publickey)') or values.get('password') or values.get('publickey')
    if not values.get('privatekey') or not public:
        raise ValueError('Unrecognized Xray x25519 output')
    return values['privatekey'], public


def install(args):
    if getattr(args, 'profile', 'three') == 'six':
        import six_protocols as six
        return six.install(args, sys.modules[__name__])
    return install_three(args)


def install_three(args):
    preflight(args)
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported server architecture')
    lock = json.loads(Path(args.lock).read_text())
    installed_units = []
    ROOT.mkdir(mode=0o700)
    try:
        for name in ('xray', 'hysteria'):
            download_asset(lock[name]['assets']['linux-' + arch], ROOT / name, 'xray' if name == 'xray' else None)
            print(name + ': checksum verified', flush=True)
        private, public = parse_keys(run(str(ROOT / 'xray'), 'x25519').stdout)
        m = {'schema': 1, 'host': args.host, 'target': args.target, 'reality_port': args.reality_port,
             'hysteria_port': args.hysteria_port, 'ss_port': args.ss_port, 'uuid': str(uuid.uuid4()),
             'short_id': secrets.token_hex(8), 'public_key': public,
             'ss_password': secrets.token_urlsafe(32), 'hy_password': secrets.token_urlsafe(32)}
        run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve', '-nodes',
            '-keyout', str(ROOT / 'hy.key'), '-out', str(ROOT / 'hy.crt'), '-days', '3650',
            '-subj', '/CN=mpn-node', '-addext', 'subjectAltName=DNS:mpn-node,IP:' + args.host)
        der = subprocess.check_output(['openssl', 'x509', '-in', str(ROOT / 'hy.crt'), '-outform', 'DER'])
        m['hy_pin'] = hashlib.sha256(der).hexdigest()
        xray, hysteria = server_configs(m, private)
        secure_write(ROOT / 'xray.json', json.dumps(xray, indent=2))
        secure_write(ROOT / 'hysteria.json', json.dumps(hysteria, indent=2))
        checked = run(str(ROOT / 'xray'), 'run', '-test', '-config', str(ROOT / 'xray.json'))
        # Upstream warns about several overused target domains; do not silently deploy them.
        if 'likelihood' in checked.stdout + checked.stderr and 'blocked' in checked.stdout + checked.stderr:
            raise RuntimeError('Xray warned about this REALITY target; choose another eligible hostname')
        secure_write(ROOT / 'client.json', json.dumps(m, indent=2))
        secure_write(ROOT / 'versions.json', json.dumps(lock, indent=2))
        commands = [f'{ROOT}/xray run -config {ROOT}/xray.json', f'{ROOT}/hysteria server -c {ROOT}/hysteria.json']
        for name, command in zip(SERVICES, commands):
            unit = UNIT_DIR / (name + '.service')
            # Exclusive create so concurrent/unrelated units are never overwritten.
            with unit.open('x') as f:
                installed_units.append(unit)
                f.write(f'''[Unit]
Description=Multi Protocol Node ({name})
After=network-online.target
Wants=network-online.target
[Service]
ExecStart={command}
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
''')
            unit.chmod(0o644)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', *SERVICES)
        time.sleep(3)
        run('systemctl', 'is-active', '--quiet', *SERVICES)
        secure_write(ROOT / 'managed-by', MARKER)
        print('Services active and enabled. Run external verification before declaring success.')
    except BaseException:
        for unit in installed_units:
            run('systemctl', 'disable', '--now', unit.stem, check=False)
            unit.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload', check=False)
        shutil.rmtree(ROOT)
        raise


def uninstall():
    marker = ROOT / 'managed-by'
    if ROOT.is_symlink() or not marker.is_file():
        raise RuntimeError('Ownership marker missing; refusing deletion')
    import six_protocols as six
    if marker.read_text() == six.MARKER:
        return six.uninstall(sys.modules[__name__])
    if marker.read_text() != MARKER:
        raise RuntimeError('Ownership marker unknown; refusing deletion')
    for name in SERVICES:
        unit = UNIT_DIR / (name + '.service')
        if unit.is_symlink() or not unit.is_file() or f'ExecStart={ROOT}/' not in unit.read_text():
            raise RuntimeError('Unit changed; inspect manually: ' + name)
    run('systemctl', 'disable', '--now', *SERVICES)
    for name in SERVICES:
        (UNIT_DIR / (name + '.service')).unlink()
    run('systemctl', 'daemon-reload')
    shutil.rmtree(ROOT)
    print('Removed only managed units and /opt/multi-protocol-node; firewall and SSH untouched.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('install')
    p.add_argument('--host', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--profile', choices=['six', 'three'], default='six')
    p.add_argument('--reality-port', type=int, default=443)
    p.add_argument('--hysteria-port', type=int, default=24443)
    p.add_argument('--ss-port', type=int, default=8388)
    p.add_argument('--trojan-port', type=int, default=8443)
    p.add_argument('--tuic-port', type=int, default=8443)
    p.add_argument('--anytls-port', type=int, default=9443)
    p.add_argument('--tls-mode', choices=['public-ip', 'provided'], default='public-ip')
    p.add_argument('--tls-name')
    p.add_argument('--cert-file')
    p.add_argument('--key-file')
    p.add_argument('--lock', default=str(Path(__file__).with_name('versions.lock.json')))
    p.add_argument('--firewall-reviewed', action='store_true')
    sub.add_parser('status')
    sub.add_parser('uninstall')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root on the target server')
    os.umask(0o077)
    with open('/run/lock/multi-protocol-node.lock', 'w') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'install':
            install(args)
        elif args.action == 'uninstall':
            uninstall()
        else:
            import six_protocols as six
            marker = ROOT / 'managed-by'
            extended = marker.is_file() and marker.read_text() == six.MARKER
            services = six.SERVICES if extended else SERVICES
            if extended and 'mpn-certificate.timer' in json.loads((ROOT / 'managed-units.json').read_text()):
                services = (*services, 'mpn-certificate.timer')
            result = run('systemctl', 'is-active', *services, check=False)
            print(result.stdout.strip())
            enabled = run('systemctl', 'is-enabled', *services, check=False)
            print(enabled.stdout.strip())
            cert_status = 0
            if extended:
                cert = run('openssl', 'x509', '-in', str(ROOT / 'public-fullchain.pem'),
                           '-noout', '-dates', '-checkend', '86400', check=False)
                print(cert.stdout.strip()); cert_status = cert.returncode
            return result.returncode or enabled.returncode or cert_status
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        # Do not echo a subprocess's command arguments/configuration (may hold secrets).
        print('ERROR: ' + (str(exc) if not isinstance(exc, subprocess.SubprocessError)
                           else 'A server command failed; inspect local service logs.'), file=sys.stderr)
        sys.exit(1)
