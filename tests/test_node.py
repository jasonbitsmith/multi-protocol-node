import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import urllib.parse
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/multi-protocol-node/scripts'
sys.path.insert(0, str(SCRIPTS))
import common
import node
import server


def metadata():
    # Documentation-only data, never a deployed node or credential.
    return {'host': '203.0.113.10', 'target': 'www.example.com', 'uuid': '00000000-0000-4000-8000-000000000001',
            'short_id': '0000000000000001', 'public_key': 'fixture-public-key', 'ss_password': 'fixture-ss-password',
            'hy_password': 'fixture-hy-password', 'hy_pin': 'ab' * 32,
            'reality_port': 443, 'hysteria_port': 443, 'ss_port': 8388}


class ConfigurationTests(unittest.TestCase):
    def test_reality_and_hy_share_port_but_ss_cannot(self):
        common.validate_options('8.8.8.8', 'www.example.com', (443, 443, 8388))
        for ports in [(443, 443, 443), (443, 8388, 8388), (0, 443, 8388), (443, 65536, 8388)]:
            with self.assertRaises(ValueError):
                common.validate_options('8.8.8.8', 'www.example.com', ports)

    def test_rejects_private_hosts_and_injected_targets(self):
        for host in ['127.0.0.1', '192.168.0.1', '203.0.113.1', 'example.com', '1.1.1.1;id']:
            with self.assertRaises(ValueError):
                common.validate_options(host, 'www.example.com', (443, 443, 8388))
        for target in ['-x', 'example.com;id', 'https://example.com', 'example.com\n', 'a..com']:
            with self.assertRaises(ValueError):
                common.validate_options('8.8.8.8', target, (443, 443, 8388))

    def test_secret_separation_and_authentication(self):
        m = metadata()
        xray, hy = common.server_configs(m, 'fixture-private-key')
        self.assertEqual(xray['inbounds'][0]['settings']['clients'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(hy['auth']['password'], m['hy_password'])
        exported = json.dumps(common.client_configs(m)) + json.dumps(common.share_links(m))
        self.assertNotIn('fixture-private-key', exported)
        self.assertIn(m['hy_pin'], exported)

    def test_hy_pin_survives_uri_encoding_and_ca_export(self):
        m = metadata(); m['hy_password'] = 'fixture:with/@ characters'
        uri = common.share_links(m)['03-Hysteria2-pinned']
        parsed = urllib.parse.urlsplit(uri)
        self.assertEqual(urllib.parse.unquote(parsed.username), m['hy_password'])
        self.assertEqual(urllib.parse.parse_qs(parsed.query)['pinSHA256'], [m['hy_pin']])
        tls = common.client_configs(m, ca_path='hy.crt')['hysteria2']['tls']
        self.assertFalse(tls['insecure'])
        self.assertEqual(tls['ca'], 'hy.crt')
        self.assertEqual(tls['pinSHA256'], m['hy_pin'])

    def test_xray_key_output_variants(self):
        for label in ['Password (PublicKey)', 'Password', 'PublicKey']:
            self.assertEqual(server.parse_keys('PrivateKey: private\n' + label + ': public'), ('private', 'public'))
        with self.assertRaises(ValueError):
            server.parse_keys('unexpected output')


class ArtifactTests(unittest.TestCase):
    def test_checksum_failure_writes_no_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'binary'
            asset = {'url': 'https://github.com/example/release', 'sha256': '0' * 64}
            with patch('common.urllib.request.urlopen', return_value=io.BytesIO(b'corrupt')):
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    common.download_asset(asset, dest)
            self.assertFalse(dest.exists())

    def test_archive_cannot_extract_traversal_entries(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('xray', b'expected')
            z.writestr('../escaped', b'bad')
        data = buf.getvalue()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'binary'
            a = {'url': 'https://github.com/example/release', 'sha256': hashlib.sha256(data).hexdigest()}
            with patch('common.urllib.request.urlopen', return_value=io.BytesIO(data)):
                common.download_asset(a, dest, 'xray')
            self.assertEqual(dest.read_bytes(), b'expected')
            self.assertEqual({p.name for p in Path(tmp).iterdir()}, {'binary'})

    def test_export_allowlist_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            common.secure_write(p / 'client.json', json.dumps(metadata()))
            common.secure_write(p / 'hy.crt', 'fixture-certificate')
            common.secure_write(p / 'server-private.key', 'must-not-export')
            node.export(p)
            with zipfile.ZipFile(p / 'client-bundle.zip') as z:
                self.assertIsNone(z.testzip())
                self.assertNotIn('client-bundle/client.json', z.namelist())
                self.assertNotIn('must-not-export', ''.join(z.read(n).decode(errors='ignore') for n in z.namelist()))
                defaults = z.read('client-bundle/default-import.txt').decode()
                self.assertIn('vless://', defaults)
                self.assertIn('ss://', defaults)
                self.assertNotIn('hysteria2://', defaults)
            self.assertEqual((p / 'client.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                node.export(p)

    def test_secure_write_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p / 'original').write_text('preserve')
            (p / 'link').symlink_to(p / 'original')
            with self.assertRaises(OSError):
                common.secure_write(p / 'link', 'replace')
            self.assertEqual((p / 'original').read_text(), 'preserve')


class LifecycleTests(unittest.TestCase):
    def test_preflight_failure_never_creates_install_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'new-install'
            with patch.object(server, 'ROOT', root), patch.object(server, 'preflight', side_effect=RuntimeError('occupied')):
                with self.assertRaisesRegex(RuntimeError, 'occupied'):
                    server.install(SimpleNamespace())
            self.assertFalse(root.exists())

    def test_download_failure_rolls_back_only_new_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); root = p / 'new-install'; unrelated = p / 'unrelated'
            unrelated.write_text('preserve')
            lock = p / 'lock.json'; lock.write_text(json.dumps({'xray': {'assets': {'linux-amd64': {}}}}))
            with patch.object(server, 'ROOT', root), patch.object(server, 'preflight'), \
                    patch.object(server.platform, 'machine', return_value='x86_64'), \
                    patch.object(server, 'download_asset', side_effect=ValueError('checksum')), patch.object(server, 'run'):
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    server.install(SimpleNamespace(lock=str(lock)))
            self.assertFalse(root.exists())
            self.assertEqual(unrelated.read_text(), 'preserve')

    def test_uninstall_refuses_unowned_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p / 'keep').write_text('preserve')
            with patch.object(server, 'ROOT', p), patch.object(server, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'Ownership'):
                    server.uninstall()
                run.assert_not_called()
            self.assertTrue((p / 'keep').exists())

    def test_service_start_failure_cleans_new_units_not_existing_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); root = p / 'install'; units = p / 'units'; units.mkdir()
            (units / 'unrelated.service').write_text('preserve')
            lock = p / 'lock.json'
            lock.write_text(json.dumps({n: {'assets': {'linux-amd64': {}}} for n in ('xray', 'hysteria')}))
            def command(*args, **kwargs):
                if args[1:] == ('x25519',):
                    return SimpleNamespace(stdout='PrivateKey: private\nPublicKey: public', stderr='')
                if args[:3] == ('systemctl', 'enable', '--now'):
                    raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(stdout='', stderr='')
            opts = SimpleNamespace(lock=str(lock), host='203.0.113.10', target='www.example.com',
                                   reality_port=443, hysteria_port=443, ss_port=8388)
            with patch.object(server, 'ROOT', root), patch.object(server, 'UNIT_DIR', units), \
                    patch.object(server, 'preflight'), patch.object(server.platform, 'machine', return_value='x86_64'), \
                    patch.object(server, 'download_asset'), patch.object(server, 'run', side_effect=command), \
                    patch.object(server.subprocess, 'check_output', return_value=b'fixture-cert'):
                with self.assertRaises(subprocess.CalledProcessError):
                    server.install(opts)
            self.assertFalse(root.exists())
            self.assertEqual([x.name for x in units.iterdir()], ['unrelated.service'])
            self.assertEqual((units / 'unrelated.service').read_text(), 'preserve')

    def test_lock_has_complete_verified_platforms(self):
        data = json.loads((SCRIPTS / 'versions.lock.json').read_text())
        for name in ('xray', 'hysteria'):
            self.assertFalse(data[name]['prerelease'])
            self.assertEqual(set(data[name]['assets']), {'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64'})
            for asset in data[name]['assets'].values():
                self.assertRegex(asset['sha256'], r'^[0-9a-f]{64}$')
                self.assertTrue(asset['url'].startswith('https://github.com/'))


if __name__ == '__main__':
    unittest.main()
