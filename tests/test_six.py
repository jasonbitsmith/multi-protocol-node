import io
import json
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.parse
import zipfile
from test_node import metadata, SCRIPTS
import common
import node
import server
import six_protocols as six


def six_metadata():
    return dict(metadata(), profile='six', schema=2, tls_mode='public-ip', tls_name='203.0.113.10',
                **{k: v for k, v in six.PORT_DEFAULTS.items()},
                trojan_password='fixture-trojan', anytls_password='fixture-anytls', tuic_password='fixture-tuic',
                tuic_uuid='00000000-0000-4000-8000-000000000002')


class SixConfigurationTests(unittest.TestCase):
    def test_collision_checks_are_transport_specific(self):
        six.bindings(six.PORT_DEFAULTS, acme=True)  # Trojan TCP8443 and TUIC UDP8443 coexist.
        for changes in [{'trojan_port': 443}, {'tuic_port': 24443}, {'anytls_port': 80}, {'ss_port': 8443}]:
            with self.assertRaises(ValueError):
                six.bindings(dict(six.PORT_DEFAULTS, **changes), acme=True)

    def test_protocols_and_security_defaults(self):
        m = six_metadata(); cfg = six.configs(m, 'fixture-private', Path('/fixture'))
        self.assertEqual([i['protocol'] for i in cfg['xray.json']['inbounds']], ['shadowsocks'])
        self.assertEqual({i['type'] for i in cfg['sing-box.json']['inbounds']}, {'vless', 'trojan', 'tuic', 'anytls'})
        tuic = next(i for i in cfg['sing-box.json']['inbounds'] if i['type'] == 'tuic')
        self.assertFalse(tuic['zero_rtt_handshake'])
        for ob in six.outbounds(m):
            if ob['type'] not in ('vless', 'shadowsocks'):
                self.assertFalse(ob['tls']['insecure'])
                self.assertEqual(ob['tls']['server_name'], m['host'])
        self.assertNotIn('fixture-private', json.dumps(six.outbounds(m)))

    def test_provided_name_applies_to_every_tls_client(self):
        m = dict(six_metadata(), tls_mode='provided', tls_name='node.example.com')
        for ob in six.outbounds(m):
            if ob['type'] not in ('vless', 'shadowsocks'):
                self.assertEqual(ob['tls']['server_name'], 'node.example.com')
        for name, link in six.links(m).items():
            if name not in ('01-REALITY', '06-Shadowsocks'):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
                self.assertEqual(q['sni'], ['node.example.com'])
                self.assertNotIn(['1'], [q.get('insecure'), q.get('allow_insecure')])
                self.assertNotIn('pinSHA256', q)

    def test_auto_group_excludes_ss_and_verifies_certificates(self):
        c = six.mihomo_profile(six_metadata())
        auto = next(g for g in c['proxy-groups'] if g['name'] == 'Auto')
        self.assertEqual(len(auto['proxies']), 5)
        self.assertNotIn('06-Shadowsocks', auto['proxies'])
        self.assertEqual(c['proxy-groups'][0]['proxies'][0], '01-REALITY')
        for p in c['proxies']:
            if p['type'] not in ('ss', 'vless'):
                self.assertFalse(p['skip-cert-verify'])

    def test_export_contains_six_links_but_no_private_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); common.secure_write(p / 'client.json', json.dumps(six_metadata()))
            (p / 'public-key.pem').write_text('never-export-this-private-key')
            (p / 'account.conf').write_text('never-export-this-acme-account')
            node.export(p)
            with zipfile.ZipFile(p / 'client-bundle.zip') as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(len(z.read('client-bundle/all-protocols.txt').decode().splitlines()), 6)
                defaults = z.read('client-bundle/default-import.txt').decode()
                self.assertIn('vless://', defaults); self.assertIn('trojan://', defaults)
                self.assertNotIn('ss://', defaults.replace('vless://', ''))
                joined = '\n'.join(z.read(n).decode(errors='ignore') for n in z.namelist())
                self.assertNotIn('never-export', joined)
                self.assertFalse(any(n.endswith(('.pem', '.key', '.crt')) for n in z.namelist()))
                self.assertEqual(len(json.loads(z.read('client-bundle/Clash-Mihomo.yaml'))['proxies']), 6)

    def test_tar_symlinks_are_not_executables(self):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode='w:gz') as t:
            m = tarfile.TarInfo('dir/sing-box'); m.type = tarfile.SYMTYPE; m.linkname = '/etc/passwd'; t.addfile(m)
        data = b.getvalue()
        with tempfile.TemporaryDirectory() as tmp, patch('common.urllib.request.urlopen', return_value=io.BytesIO(data)):
            with self.assertRaises(ValueError):
                common.download_asset({'url': 'https://github.com/example/release', 'sha256': hashlib.sha256(data).hexdigest()},
                                      Path(tmp) / 'binary', tar_member='sing-box')


class SixLifecycleTests(unittest.TestCase):
    def fixture(self, p, fail=None):
        units = p / 'units'; units.mkdir(); (units / 'unrelated.service').write_text('preserve')
        root = p / 'root'
        args = SimpleNamespace(host='203.0.113.10', target='www.example.com', tls_mode='public-ip',
                               tls_name=None, profile='six', lock=str(SCRIPTS / 'versions.lock.json'), **six.PORT_DEFAULTS)
        def run(*cmd, **kwargs):
            if fail and cmd[:len(fail)] == fail:
                raise subprocess.CalledProcessError(1, cmd)
            return SimpleNamespace(stdout='', stderr='', returncode=0)
        api = SimpleNamespace(ROOT=root, UNIT_DIR=units, run=Mock(side_effect=run), preflight=Mock(),
                              platform=SimpleNamespace(machine=lambda: 'x86_64'), parse_keys=lambda s: ('private', 'public'))
        return args, api

    def test_certificate_failure_leaves_no_units_or_install_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, api = self.fixture(Path(tmp))
            with patch.object(six, 'download_asset'), patch.object(six, 'issue_certificate', side_effect=RuntimeError('CA failed')):
                with self.assertRaisesRegex(RuntimeError, 'CA failed'):
                    six.install(args, api)
            self.assertFalse(api.ROOT.exists())
            self.assertEqual([p.name for p in api.UNIT_DIR.iterdir()], ['unrelated.service'])

    def test_renewal_failure_cleans_all_proxy_and_timer_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, api = self.fixture(Path(tmp), ('systemctl', 'start', 'mpn-certificate.service'))
            with patch.object(six, 'download_asset'), patch.object(six, 'issue_certificate'), patch.object(six.time, 'sleep'):
                with self.assertRaises(subprocess.CalledProcessError):
                    six.install(args, api)
            self.assertFalse(api.ROOT.exists())
            self.assertEqual([p.name for p in api.UNIT_DIR.iterdir()], ['unrelated.service'])
            stops = [c.args[3] for c in api.run.call_args_list if c.args[:3] == ('systemctl', 'disable', '--now')]
            self.assertEqual(stops[0], 'mpn-certificate.timer')
            self.assertIn('mpn-extra.service', stops)

    def test_complete_lifecycle_owns_and_removes_renewal_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, api = self.fixture(Path(tmp))
            with patch.object(six, 'download_asset'), patch.object(six, 'issue_certificate'), patch.object(six.time, 'sleep'):
                six.install(args, api)
            self.assertEqual((api.ROOT / 'managed-by').read_text(), six.MARKER)
            self.assertEqual(len(json.loads((api.ROOT / 'managed-units.json').read_text())), 5)
            six.uninstall(api)
            self.assertFalse(api.ROOT.exists())
            self.assertEqual([p.name for p in api.UNIT_DIR.iterdir()], ['unrelated.service'])

    def test_tampered_unit_blocks_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, api = self.fixture(Path(tmp))
            with patch.object(six, 'download_asset'), patch.object(six, 'issue_certificate'), patch.object(six.time, 'sleep'):
                six.install(args, api)
            (api.UNIT_DIR / 'mpn-extra.service').write_text('ExecStart=/someone-elses-service')
            api.run.reset_mock()
            with self.assertRaisesRegex(ValueError, 'ownership'):
                six.uninstall(api)
            api.run.assert_not_called(); self.assertTrue(api.ROOT.exists())

    def test_provided_key_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p / 'cert').write_text('fixture'); (p / 'key').write_text('fixture')
            args = SimpleNamespace(cert_file=str(p / 'cert'), key_file=str(p / 'key'), tls_name='node.example.com', host='203.0.113.10')
            run = Mock(side_effect=[SimpleNamespace(stdout=''), SimpleNamespace(stdout=''),
                                   SimpleNamespace(stdout='one public key'), SimpleNamespace(stdout='another public key')])
            with self.assertRaisesRegex(ValueError, 'do not match'):
                six.check_provided(args, run)


if __name__ == '__main__':
    unittest.main()
