"""Optional local binary smoke test. No VPS access or customer credentials.

python tests/smoke_binaries.py --xray /path/to/xray --hysteria /path/to/hysteria
Validates Xray configuration and authenticates Hy2 on loopback using a generated
certificate, including a negative pin test. Does not measure external reachability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/multi-protocol-node/scripts'))
from common import client_configs, secure_write, server_configs
from server import parse_keys
from test_node import metadata


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--xray', required=True); p.add_argument('--hysteria', required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix='mpn-smoke-') as tmp:
        root = Path(tmp)
        m = metadata(); m['host'] = '127.0.0.1'
        m['reality_port'] = free_port(); m['ss_port'] = free_port(); m['hysteria_port'] = free_port(socket.SOCK_DGRAM)
        private, m['public_key'] = parse_keys(subprocess.check_output([args.xray, 'x25519'], text=True))
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve',
            '-nodes', '-keyout', str(root / 'hy.key'), '-out', str(root / 'hy.crt'), '-days', '1',
            '-subj', '/CN=mpn-node', '-addext', 'subjectAltName=DNS:mpn-node'], check=True, capture_output=True)
        der = subprocess.check_output(['openssl', 'x509', '-in', str(root / 'hy.crt'), '-outform', 'DER'])
        m['hy_pin'] = hashlib.sha256(der).hexdigest()
        x, h = server_configs(m, private, root)
        h['listen'] = '127.0.0.1:' + str(m['hysteria_port'])
        secure_write(root / 'xray.json', json.dumps(x))
        subprocess.run([args.xray, 'run', '-test', '-config', str(root / 'xray.json')], check=True, capture_output=True)
        print('Xray server schema: PASS')
        secure_write(root / 'server.json', json.dumps(h))
        with (root / 'server.log').open('w') as log:
            server = subprocess.Popen([args.hysteria, 'server', '-c', str(root / 'server.json')], stdout=log, stderr=log)
            try:
                time.sleep(.5)
                for good_pin in (True, False):
                    port = free_port()
                    cfg = client_configs(m, (free_port(), free_port(), port), root / 'hy.crt')['hysteria2']
                    if not good_pin:
                        cfg['tls']['pinSHA256'] = '00' * 32
                    secure_write(root / 'client.json', json.dumps(cfg))
                    with (root / 'client.log').open('w') as client_log:
                        client = subprocess.Popen([args.hysteria, 'client', '-c', str(root / 'client.json')],
                                                  stdout=client_log, stderr=client_log)
                        try:
                            connected = False
                            for _ in range(75):
                                if client.poll() is not None:
                                    break
                                try:
                                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                        connected = True
                                    break
                                except OSError:
                                    time.sleep(.2)
                            if good_pin:
                                assert connected and client.poll() is None, 'Valid certificate could not connect: ' + (root / 'client.log').read_text() + (root / 'server.log').read_text()
                            else:
                                assert not connected and client.poll() not in (None, 0), 'Bad pin was not rejected'
                        finally:
                            stop(client)
                    if not good_pin:
                        assert 'pinned hash' in (root / 'client.log').read_text(), 'Failure was not certificate pin rejection'
                    print('Hy2 ' + ('CA + valid pin' if good_pin else 'wrong pin rejected') + ': PASS')
            finally:
                stop(server)


if __name__ == '__main__':
    main()
