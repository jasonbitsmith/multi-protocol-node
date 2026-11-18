"""Configuration generation and verified downloads. No live operations on import."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
import zipfile
import io
import tarfile

ROOT = Path('/opt/multi-protocol-node')
SERVICES = ('mpn-xray', 'mpn-hysteria')
PRIVATE_NETWORKS = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                    '192.168.0.0/16', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']


def validate_options(host, target, ports):
    # Literal public address only: no scheme, shell expressions or DNS ambiguity.
    address = ipaddress.ip_address(host)
    if not address.is_global:
        raise ValueError('A globally routable server IP is required')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', target):
        raise ValueError('REALITY target must be a DNS hostname, not a URL')
    if len(ports) != 3 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('Ports must be integers from 1 to 65535')
    reality, hysteria, ss = ports
    if reality == ss or hysteria == ss:
        raise ValueError('SS needs both TCP and UDP; its port must be distinct')


def secure_write(path, value):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(value)


def download_asset(asset, destination, zip_member=None, tar_member=None):
    url = asset['url']
    if not (url.startswith('https://github.com/') or re.fullmatch(
            r'https://raw.githubusercontent.com/acmesh-official/acme.sh/[0-9a-f]{40}/acme.sh', url)):
        raise ValueError('Only pinned GitHub release URLs are accepted')
    with urllib.request.urlopen(url, timeout=90) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != asset['sha256']:
        raise ValueError('Release checksum mismatch; refusing to execute')
    if zip_member:
        # Never extract an upstream archive tree into the filesystem.
        data = zipfile.ZipFile(io.BytesIO(data)).read(zip_member)
    if tar_member:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            matches = [m for m in archive.getmembers() if m.isfile() and
                       m.name.split('/')[-1] == tar_member]
            if len(matches) != 1:
                raise ValueError('Archive must contain exactly one regular executable')
            data = archive.extractfile(matches[0]).read()
    with open(destination, 'xb') as f:
        f.write(data)
    Path(destination).chmod(0o700)


def server_configs(m, private_key, root=ROOT):
    reality = {'tag': 'reality', 'listen': '0.0.0.0', 'port': m['reality_port'],
               'protocol': 'vless', 'settings': {'clients': [{'id': m['uuid'], 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
               'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                   'target': m['target'] + ':443', 'serverNames': [m['target']],
                   'privateKey': private_key, 'shortIds': [m['short_id']]}}}
    ss = {'tag': 'shadowsocks', 'listen': '0.0.0.0', 'port': m['ss_port'], 'protocol': 'shadowsocks',
          'settings': {'method': 'chacha20-ietf-poly1305', 'password': m['ss_password'], 'network': 'tcp,udp'}}
    xray = {'log': {'loglevel': 'warning'}, 'inbounds': [reality, ss],
            'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
            'routing': {'rules': [{'type': 'field', 'ip': PRIVATE_NETWORKS, 'outboundTag': 'block'}]}}
    hysteria = {'listen': ':' + str(m['hysteria_port']),
                'tls': {'cert': str(root / 'hy.crt'), 'key': str(root / 'hy.key')},
                'auth': {'type': 'password', 'password': m['hy_password']},
                'ignoreClientBandwidth': True,
                'acl': {'inline': ['reject(' + n + ')' for n in PRIVATE_NETWORKS]},
                'masquerade': {'type': 'string', 'string': {'content': 'Not Found', 'statusCode': 404}}}
    return xray, hysteria


def endpoint(host, port):
    return ('[' + host + ']' if ':' in host else host) + ':' + str(port)


def share_links(m):
    if m.get('profile') == 'six':
        from six_protocols import links
        return links(m)
    q = urllib.parse.urlencode({'encryption': 'none', 'security': 'reality', 'sni': m['target'],
        'fp': 'chrome', 'pbk': m['public_key'], 'sid': m['short_id'], 'type': 'tcp', 'flow': 'xtls-rprx-vision'})
    vless = f"vless://{m['uuid']}@{endpoint(m['host'], m['reality_port'])}?{q}#Node-REALITY"
    auth = base64.urlsafe_b64encode(('chacha20-ietf-poly1305:' + m['ss_password']).encode()).decode().rstrip('=')
    ss = f"ss://{auth}@{endpoint(m['host'], m['ss_port'])}#Node-SS"
    # Self-signed certificate is authenticated by its exact SHA-256 pin.
    # Importers that drop pinSHA256 MUST NOT use this URI.
    q = urllib.parse.urlencode({'sni': 'mpn-node', 'insecure': '1', 'pinSHA256': m['hy_pin']})
    hy = f"hysteria2://{urllib.parse.quote(m['hy_password'], safe='')}@{endpoint(m['host'], m['hysteria_port'])}/?{q}#Node-Hysteria2"
    return {'01-REALITY': vless, '02-Shadowsocks': ss, '03-Hysteria2-pinned': hy}


def client_configs(m, ports=(18281, 18282, 18283), ca_path=None):
    reality = {'protocol': 'vless', 'settings': {'vnext': [{'address': m['host'], 'port': m['reality_port'],
        'users': [{'id': m['uuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'serverName': m['target'], 'fingerprint': 'chrome', 'password': m['public_key'], 'shortId': m['short_id']}}}
    ss = {'protocol': 'shadowsocks', 'settings': {'servers': [{'address': m['host'], 'port': m['ss_port'],
        'method': 'chacha20-ietf-poly1305', 'password': m['ss_password']}]}}
    configs = {}
    for name, port, outbound in [('reality', ports[0], reality), ('shadowsocks', ports[1], ss)]:
        configs[name] = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
            'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}], 'outbounds': [outbound]}
    tls = {'sni': 'mpn-node', 'insecure': ca_path is None, 'pinSHA256': m['hy_pin']}
    if ca_path:
        tls['ca'] = str(ca_path)
    configs['hysteria2'] = {'server': endpoint(m['host'], m['hysteria_port']), 'auth': m['hy_password'],
        'tls': tls, 'socks5': {'listen': '127.0.0.1:' + str(ports[2])}}
    return configs
