#!/usr/bin/env python3
"""Local SSH orchestrator, client export and end-to-end verification."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from common import ROOT, client_configs, download_asset, secure_write, share_links, validate_options

HERE = Path(__file__).resolve().parent


def ssh_command(args, command):
    return ['ssh', '-p', str(args.ssh_port), '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=15', args.ssh, command]


def remote(args):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]*', args.ssh):
        raise ValueError('Use an SSH alias or user@IPv4; SSH options belong in ~/.ssh/config')
    if not 1 <= args.ssh_port <= 65535:
        raise ValueError('Invalid SSH port')
    if args.action == 'install':
        validate_options(args.host, args.target, (args.reality_port, args.hysteria_port, args.ss_port))
        if args.profile == 'six':
            from six_protocols import bindings
            bindings(vars(args), args.tls_mode == 'public-ip')
    # mktemp allocates a private directory. Transport delegates authentication to OpenSSH.
    tmp = subprocess.check_output(ssh_command(args, 'mktemp -d /tmp/mpn.XXXXXXXX'), text=True).strip()
    if not re.fullmatch(r'/tmp/mpn\.[a-zA-Z0-9]+', tmp):
        raise RuntimeError('Unexpected SSH output; no remote command executed')
    try:
        files = [str(HERE / n) for n in ('server.py', 'common.py', 'six_protocols.py', 'versions.lock.json')]
        subprocess.run(['scp', '-P', str(args.ssh_port), '-o', 'StrictHostKeyChecking=yes',
                        *files, args.ssh + ':' + tmp + '/'], check=True)
        cmd = ['python3', tmp + '/server.py', args.action]
        if args.action == 'install':
            cmd += ['--host', args.host, '--target', args.target, '--reality-port', str(args.reality_port),
                    '--hysteria-port', str(args.hysteria_port), '--ss-port', str(args.ss_port), '--profile', args.profile]
            if args.profile == 'six':
                cmd += ['--trojan-port', str(args.trojan_port), '--tuic-port', str(args.tuic_port),
                        '--anytls-port', str(args.anytls_port), '--tls-mode', args.tls_mode]
                for flag, value in [('--tls-name', args.tls_name), ('--cert-file', args.cert_file), ('--key-file', args.key_file)]:
                    if value is not None:
                        cmd += [flag, value]
            if args.firewall_reviewed:
                cmd.append('--firewall-reviewed')
        subprocess.run(ssh_command(args, shlex.join(cmd)), check=True)
    finally:
        subprocess.run(ssh_command(args, 'rm -rf -- ' + shlex.quote(tmp)), check=False)


def fetch(args):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]*', args.ssh) or not 1 <= args.ssh_port <= 65535:
        raise ValueError('Invalid SSH destination')
    out = Path(args.output).resolve()
    if out.exists():
        raise ValueError('Output exists; choose a new private directory')
    out.mkdir(parents=True, mode=0o700)
    try:
        for name in ('client.json',):
            subprocess.run(['scp', '-P', str(args.ssh_port), '-o', 'StrictHostKeyChecking=yes',
                            args.ssh + ':' + str(ROOT / name), str(out / name)], check=True)
            (out / name).chmod(0o600)
        m = json.loads((out / 'client.json').read_text())
        if m.get('profile') != 'six':
            subprocess.run(['scp', '-P', str(args.ssh_port), '-o', 'StrictHostKeyChecking=yes',
                            args.ssh + ':' + str(ROOT / 'hy.crt'), str(out / 'hy.crt')], check=True)
            (out / 'hy.crt').chmod(0o600)
        export(out)
    except BaseException:
        shutil.rmtree(out)
        raise


def export(out):
    m = json.loads((out / 'client.json').read_text())
    if m.get('profile') == 'six':
        return export_six(out, m)
    client = out / 'client-bundle'
    client.mkdir(mode=0o700)  # Deliberately refuse overwriting a previous export.
    links = share_links(m)
    for name, link in links.items():
        secure_write(client / (name + '.txt'), link + '\n')
    # Safe default clipboard import excludes Hy2 because some apps discard the pin.
    secure_write(client / 'default-import.txt', links['01-REALITY'] + '\n' + links['02-Shadowsocks'] + '\n')
    qr_available = True
    try:
        import qrcode
    except ImportError:
        qr_available = False
    if qr_available:
        for name, link in links.items():
            qrcode.make(link).save(client / (name + '.png'))
    else:
        print('QR dependency absent; links exported. Install requirements-export.txt before fetch for QR images.')
    shutil.copyfile(out / 'hy.crt', client / 'hy.crt')
    hy = client_configs(m, ports=(10806, 10807, 10808), ca_path='hy.crt')['hysteria2']
    hy['http'] = {'listen': '127.0.0.1:10809'}
    secure_write(client / 'hysteria-client.json', json.dumps(hy, indent=2))
    notes = '''# 个人使用说明 / Personal-use guide

主用：01 REALITY；兼容备用：02 Shadowsocks；UDP 备选：03 Hysteria 2。
三者使用同一台服务器，不构成独立线路容灾。导出不代表已经通过验证。

## iPhone
使用支持相应协议的最新版 Shadowrocket，扫描二维码，或复制 txt 整行链接后从剪贴板添加。
先选择 REALITY 并开启连接；需要时再切换 SS。
## Windows
从 https://github.com/2dust/v2rayN/releases 获取 v2rayN，导入 default-import.txt，选择 REALITY，开启系统代理。
## Hysteria 2 的证书校验
03 的链接使用自签名证书 + pinSHA256。insecure=1 仅替代公共 CA 校验，必须保留并验证指纹。
如果客户端导入时丢失 pinSHA256，不要继续使用该节点，也不要只开启“跳过证书验证”。
可靠替代：从 https://github.com/apernet/hysteria/releases 获取官方程序，
与 hy.crt、hysteria-client.json 放在同一目录，运行：
    hysteria client -c hysteria-client.json
Windows 使用 hysteria.exe。该配置启用自定义 CA + 指纹校验，提供本机 SOCKS5 10808 / HTTP 10809。
UDP 超时但 REALITY 正常时，先用 REALITY，再换 Wi-Fi/蜂窝网络检查。

这些链接、二维码和配置都是访问凭证，不要公开。目录不含 SSH 密码或服务端私钥。
服务未设置额外流量配额；供应商套餐额度仍然有效。
'''
    secure_write(client / 'README.txt', notes + '\nCertificate SHA-256: ' + m['hy_pin'] + '\n')
    # Explicit allowlist; never package admin metadata, logs or source directories.
    allowed = {n + '.txt' for n in links} | {n + '.png' for n in links} | {
        'default-import.txt', 'hy.crt', 'hysteria-client.json', 'README.txt'}
    with zipfile.ZipFile(out / 'client-bundle.zip', 'x', zipfile.ZIP_DEFLATED) as z:
        for f in sorted(client.iterdir()):
            if f.name in allowed:
                z.write(f, 'client-bundle/' + f.name)
    print('Client package saved: ' + str(out / 'client-bundle.zip'))


def export_six(out, m):
    from six_protocols import client_profile, mihomo_profile
    client = out / 'client-bundle'
    client.mkdir(mode=0o700)
    links = share_links(m)
    allowed = set()
    try:
        import qrcode
    except ImportError:
        qrcode = None
    for name, link in links.items():
        secure_write(client / (name + '.txt'), link + '\n'); allowed.add(name + '.txt')
        if qrcode:
            qrcode.make(link).save(client / (name + '.png')); allowed.add(name + '.png')
    files = {
        'default-import.txt': links['01-REALITY'] + '\n' + links['02-Trojan'] + '\n',
        'all-protocols.txt': '\n'.join(links.values()) + '\n',
        'sing-box.json': json.dumps(client_profile(m), ensure_ascii=False, indent=2),
        'Clash-Mihomo.yaml': json.dumps(mihomo_profile(m), ensure_ascii=False, indent=2),
        'README.txt': '''个人使用说明（六协议）
主用 REALITY，TCP 备用 Trojan；UDP 正常时可测试 Hysteria 2 / TUIC。
AnyTLS 需新版客户端支持；Shadowsocks 仅作兼容备用，不具备前向保密。
所有 TLS 节点都启用证书验证，不要开启“跳过证书验证”。
iPhone：支持对应协议的 Shadowrocket 扫码或导入链接。Windows：最新版 v2rayN 从剪贴板导入，并选择相应核心。
Mihomo：导入 Clash-Mihomo.yaml。默认 REALITY，Auto 只测速前五个协议，SS 必须手动选择。
sing-box.json：本机 HTTP/SOCKS 10808；不是手机 TUN 配置，不会自动覆盖每个 App。
配置默认全代理，没有承诺国内直连或 DNS 防泄漏；按你的应用/路由需求调整，并实际验证。
六种协议共用一台服务器，不是六条独立线路。导出不代表已通过外部验证。
公网证书必须及时续期。public-ip 模式由服务器定时检查；provided 模式需要自行维护证书部署。
所有链接/二维码都是访问凭证，请私密保存。包内不包含 SSH 密码、服务端私钥或 ACME 账号。
'''}
    for name, content in files.items():
        secure_write(client / name, content); allowed.add(name)
    with zipfile.ZipFile(out / 'client-bundle.zip', 'x', zipfile.ZIP_DEFLATED) as z:
        for name in sorted(allowed):
            z.write(client / name, 'client-bundle/' + name)
    print('Six-protocol personal bundle: ' + str(out / 'client-bundle.zip'))


def verify(args):
    directory = Path(args.directory).resolve()
    m = json.loads((directory / 'client.json').read_text())
    system = {'Darwin': 'darwin', 'Linux': 'linux'}.get(platform.system())
    arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(platform.machine())
    if not system or not arch or not shutil.which('curl'):
        raise ValueError('Verification needs Linux/macOS, curl, amd64/arm64')
    lock = json.loads((HERE / 'versions.lock.json').read_text())
    results = {}
    extended = m.get('profile') == 'six'
    with tempfile.TemporaryDirectory(prefix='mpn-verify-') as tmp:
        work = Path(tmp)
        for name in (('sing-box',) if extended else ('xray', 'hysteria')):
            download_asset(lock[name]['assets'][system + '-' + arch], work / name,
                           zip_member='xray' if name == 'xray' else None,
                           tar_member='sing-box' if name == 'sing-box' else None)
        # Allocate different free local ports; later verify process is still alive.
        sockets = []
        count = 6 if extended else 3
        for _ in range(count):
            s = socket.socket(); s.bind(('127.0.0.1', 0)); sockets.append(s)
        ports = [s.getsockname()[1] for s in sockets]
        if extended:
            from six_protocols import outbounds
            configs = {ob['tag']: {'log': {'level': 'warn'},
                'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}],
                'outbounds': [ob], 'route': {'final': ob['tag']}}
                for ob, port in zip(outbounds(m), ports)}
        else:
            configs = client_configs(m, ports, directory / 'hy.crt')
        for s in sockets:
            s.close()
        for (name, config), port in zip(configs.items(), ports):
            conf = work / (name + '.json')
            secure_write(conf, json.dumps(config))
            cmd = ([str(work / 'sing-box'), 'run', '-c', str(conf)] if extended else
                   ([str(work / 'hysteria'), 'client', '-c', str(conf)] if name == 'hysteria2'
                   else [str(work / 'xray'), 'run', '-config', str(conf)]))
            with (work / (name + '.log')).open('w') as log:
                proc = subprocess.Popen(cmd, stdout=log, stderr=log)
                try:
                    ready = False
                    for _ in range(150):
                        if proc.poll() is not None:
                            break
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                ready = True
                            break
                        except OSError:
                            time.sleep(.2)
                    if not ready:
                        results[name] = {'ok': False, 'reason': 'Client failed or handshake timed out'}
                        continue
                    response = subprocess.run(['curl', '-fsS', '--proxy', f'socks5h://127.0.0.1:{port}',
                        '--max-time', '25', 'https://www.cloudflare.com/cdn-cgi/trace'], capture_output=True, text=True, timeout=30)
                    trace = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
                    results[name] = {'ok': response.returncode == 0 and bool(trace.get('ip')) and proc.poll() is None,
                                     'exit_ip': trace.get('ip'), 'location': trace.get('loc')}
                except (subprocess.TimeoutExpired, OSError) as exc:
                    results[name] = {'ok': False, 'reason': type(exc).__name__}
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
                    print(name + ': ' + ('PASS' if results.get(name, {}).get('ok') else 'FAIL'))
        secure_write(directory / 'verification.json', json.dumps(results, indent=2))
    return 0 if len(results) == count and all(r['ok'] for r in results.values()) else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    for action in ('install', 'status', 'uninstall', 'fetch'):
        p = subs.add_parser(action)
        p.add_argument('--ssh', required=True, help='Root SSH alias or root@IPv4, already in known_hosts')
        p.add_argument('--ssh-port', type=int, default=22)
        if action == 'install':
            p.add_argument('--host', required=True, help='Server public IPv4')
            p.add_argument('--target', required=True, help='REALITY target hostname; no default')
            p.add_argument('--profile', choices=['six', 'three'], default='six')
            p.add_argument('--reality-port', type=int, default=443)
            p.add_argument('--hysteria-port', type=int, default=24443)
            p.add_argument('--ss-port', type=int, default=8388)
            p.add_argument('--trojan-port', type=int, default=8443)
            p.add_argument('--tuic-port', type=int, default=8443)
            p.add_argument('--anytls-port', type=int, default=9443)
            p.add_argument('--tls-mode', choices=['public-ip', 'provided'], default='public-ip')
            p.add_argument('--tls-name')
            p.add_argument('--cert-file', help='Existing full chain path on the target server')
            p.add_argument('--key-file', help='Existing private key path on the target server')
            p.add_argument('--firewall-reviewed', action='store_true')
        if action == 'fetch':
            p.add_argument('--output', required=True, help='New private output directory')
    p = subs.add_parser('verify')
    p.add_argument('--directory', required=True)
    args = parser.parse_args()
    if args.action == 'verify':
        return verify(args)
    if args.action == 'fetch':
        fetch(args)
    else:
        remote(args)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('ERROR: ' + (str(exc) if not isinstance(exc, subprocess.SubprocessError)
                           else 'Command failed; inspect preceding SSH/service output.'), file=sys.stderr)
        sys.exit(1)
