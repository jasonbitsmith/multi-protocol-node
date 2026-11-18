# Operations and limits

## Prerequisites and ports

Run orchestration on Linux/macOS with Python 3.10+ and OpenSSH. On Windows use WSL; Windows proxy clients can consume the exported links without WSL. Target: Debian/Ubuntu, systemd, Python 3.10+, `curl`, `openssl`, `iproute2` (`ss`). Install missing prerequisites with the host's package manager only within authorized scope. No control panel is required.

Default ports: TCP 443 (REALITY), UDP 443 (Hy2), TCP/UDP 8388 (SS). Cloud/provider firewalls are separate from host firewall rules. Allow only the chosen inbound ports while preserving SSH access. The installer neither edits nor flushes firewall rules. `--firewall-reviewed` means an operator already reviewed them, not that they are correct.

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
