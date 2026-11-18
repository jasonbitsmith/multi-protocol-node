# Operations and limits

## Six-protocol mode (default)

Six protocols use `mpn-xray` (SS), `mpn-hysteria` (Hy2), and `mpn-extra` (sing-box: REALITY/Trojan/TUIC/AnyTLS). Defaults: TCP443 REALITY, TCP8443 Trojan, UDP24443 Hy2, UDP8443 TUIC, TCP9443 AnyTLS, TCP/UDP8388 SS. TCP80 must be free and reachable for public-ip certificate issuance and renewal.

Public-IP mode uses a pinned acme.sh script and stores its state inside `/opt/multi-protocol-node/acme`; it does not alter global cron or shell profiles. `mpn-certificate.timer` checks every six hours. Renewal restarts Hy2 and sing-box. Check `journalctl -u mpn-certificate` and `systemctl list-timers mpn-certificate.timer`. Certificate issuance publishes the IP to the CA/CT logs. Never mask certificate errors by skipping verification.

Provided mode requires existing target-server certificate/key paths; the installer validates trust, name, key match and at least one day of validity before copying. Configure your existing certificate manager to replace `/opt/multi-protocol-node/public-fullchain.pem` and `public-key.pem` securely, then run `systemctl restart mpn-hysteria mpn-extra`. This mode creates no renewal timer; source-file updates alone do not update the copied files.

`status` checks proxy units, renewal timer when installed, and certificate lifetime (fails within 24 hours of expiry). `uninstall` checks a manifest and ownership before deleting all managed units, timer and ACME state. It never deletes provided source files. No in-place migration from three-protocol or manually extended deployments is performed.

Six-mode exports include six links, sing-box and Mihomo profiles. The default import is REALITY + Trojan; automatic selection excludes SS. Verification uses sing-box and returns failure if any of the six HTTPS checks fail. See [protocol choice](protocol-choice.md) for security and network recommendations.

## Legacy three-protocol mode

The following details apply to `--profile three` and existing v1 installations unless stated otherwise.

## Prerequisites and ports

Run orchestration on Linux/macOS with Python 3.10+ and OpenSSH. On Windows use WSL; Windows proxy clients can consume the exported links without WSL. Target: Debian/Ubuntu, systemd, Python 3.10+, `curl`, `openssl`, `iproute2` (`ss`). Install missing prerequisites with the host's package manager only within authorized scope. No control panel is required.

New default ports: TCP 443 (REALITY), UDP 24443 (Hy2; existing v1 installs may use 443), TCP/UDP 8388 (SS). Cloud/provider firewalls are separate from host firewall rules. Allow only the chosen inbound ports while preserving SSH access. The installer neither edits nor flushes firewall rules. `--firewall-reviewed` means an operator already reviewed them, not that they are correct.

SSH defaults to port 22, including when using an alias; pass `--ssh-port` explicitly for other ports. SSH host fingerprints must already be trusted. Password-based OpenSSH may prompt multiple times. Prefer an existing configured key/agent but never introduce new access rights implicitly.

## What is installed

- `/opt/multi-protocol-node/`: binaries, locked versions, private server configs, keys, exportable client metadata and certificate; root-only directory.
- `mpn-xray.service`: REALITY + Shadowsocks; `mpn-hysteria.service`: Hysteria 2. Both restart on failure and start at boot.
- Dedicated services run as root with systemd filesystem restrictions, to bind privileged ports. They are not containers and not an exhaustive hardened-host solution.
- Default deny rules reject common private/loopback/link-local destination IPs. They are not a comprehensive SSRF or DNS-rebinding defense; do not distribute access to untrusted strangers on a sensitive network.
- No public subscription endpoint, web panel or automatic upstream updater is installed.

The pinned binary versions and SHA-256 sums live in `scripts/versions.lock.json`. Downloads execute only after verification against this lock; a compromised upstream release and lock update remain supply-chain risks. To upgrade, review upstream release notes and checksums, edit the lock, run tests, and test on a disposable server before planning an existing server migration. Client links should not be rotated incidentally.

## Certificates and clients

REALITY authenticates with its public key and short ID. It does not require the owner to register a domain or renew a public certificate; choosing a target does not mean the target endorses the proxy.

Hy2 creates a dedicated self-signed EC certificate, valid for 3650 days, with a fixed client pin. Its validity is finite. Replacing it requires redistributing the new certificate/pin to all clients. The pinned URI includes `insecure=1` because public CA trust is replaced by the exact fingerprint. Some URI importers drop `pinSHA256`; never use those importers for this URI. The exported official client config instead sets `insecure=false`, `ca=hy.crt`, and the same fingerprint. Client application/version compatibility must be checked separately.

Shadowsocks uses chacha20-ietf-poly1305 for compatibility, not forward secrecy. Xray emits a deprecation warning for this protocol. Keep it as a fallback; evaluate removal or a replacement when upstream support changes.

## Diagnostics

Read-only host checks:

```sh
systemctl status mpn-xray mpn-hysteria --no-pager
journalctl -u mpn-xray -u mpn-hysteria -n 80 --no-pager
ss -lntup
```

Logs can expose client addresses or destinations; redact before posting issues.

`verify` starts isolated local proxy processes on ephemeral loopback ports. It checks HTTPS through each protocol, records observed exit IP/location, and removes processes/configs on normal completion or Python exceptions. It does not test sustained throughput, every website, UDP relay inside SS, or actual iPhone imports. Results go to the private `verification.json` file. A local VPN/proxy can affect the path.

- Hy2 timeout with working TCP: try another network/vantage point, then check UDP firewall and server journal. Do not call all protocols broken or disable certificate verification.
- REALITY fails: verify target reachability, client key/short ID/SNI/flow, host port and the client version.
- Port occupied or managed directory exists: inspect ownership; use different ports for an unrelated deployment. Do not delete another service.
- Installation error: own new units/directory are removed on ordinary exceptions. A hard power loss or SIGKILL can leave partial files; inspect them before manual recovery. Do not claim an atomic transaction across OS crashes.
- Rerun: `install` is deliberately non-overwriting, not a configuration reconciler. Existing successful installs use `status`/`fetch`.

## Uninstall

`node.py uninstall --ssh ROOT_ALIAS` stops/disables only the two managed units, verifies the ownership marker/unit paths and removes the managed directory. Local client exports remain private and must be removed separately if unwanted. Removal disconnects all users of this installation.

## Official references

- [Xray releases](https://github.com/XTLS/Xray-core/releases)
- [REALITY](https://github.com/XTLS/REALITY)
- [Hysteria server configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Hysteria client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria URI format](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Surge VLESS support](https://manual.nssurge.com/policies/vless.html)
