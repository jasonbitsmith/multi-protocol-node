---
name: multi-protocol-node
description: Deploy VLESS REALITY Vision, Hysteria 2 and a Shadowsocks compatibility fallback on a personally used, authorized Debian or Ubuntu VPS; export private device configuration bundles and verify connectivity. Use for multi-protocol proxy node setup or maintenance, not unrelated DNS, panels, monitoring or personal routing changes.
---

# Multi Protocol Node

Deploy three authenticated protocols for personal use on one server, using the bundled Python scripts. Read [operations.md](references/operations.md) for prerequisites, diagnostics and boundaries before deployment. The scripts do not need this skill installed to run.

## Determine the intended server

- Reuse the user's authorized server and existing SSH access. Obtain only missing SSH destination/port, public IPv4 and intended clients. Do not confuse a login password with an SSH private key.
- Inspect active services, occupied ports and existing firewall rules. Existing installations are not fresh servers: preserve them and choose unused ports or stop to resolve an actual conflict.
- Choose a REALITY target reachable from the VPS with TLS 1.3 and h2. The installer checks this and refuses targets flagged by Xray. No domain is universally safe, and no anti-blocking guarantee is possible.
- The scripts support Debian/Ubuntu with systemd, Python 3.10+, OpenSSL, curl and ss; amd64/arm64. Use an existing root SSH session/config. Never add SSH keys, reset passwords, disable a firewall or change unrelated client profiles as an implicit prerequisite.

## Deploy within the user's request

Resolve paths relative to this skill directory. Commands below use `scripts/node.py`.

1. Confirm the SSH host key against a trusted server/provider source and establish the connection normally. Scripts require an existing trusted `known_hosts` entry; do not disable host key checks. Authentication stays with OpenSSH, never a password argument or repository file.
2. Run `python3 scripts/node.py install --ssh ROOT_ALIAS --host PUBLIC_IPV4 --target TARGET_HOST`. Optional port flags are `--reality-port`, `--hysteria-port`, `--ss-port`; use `--ssh-port` when not 22.
3. The installer refuses existing managed files or occupied ports and rolls back files/units it creates if installation fails. Do not turn refusal into deletion or blind reruns. If firewall rules exist, inspect/adjust only the authorized rules, then use `--firewall-reviewed`; this flag does not open ports.
4. Run `python3 scripts/node.py fetch --ssh ROOT_ALIAS --output PRIVATE_NEW_DIRECTORY`. Optional QR generation requires `requirements-export.txt`; credentials must stay outside public source control.
5. Run `python3 scripts/node.py verify --directory PRIVATE_NEW_DIRECTORY` from outside the VPS. A service being active or a QR code existing is not evidence that the node works. A failed protocol returns a nonzero exit status. Distinguish verified protocols, untested clients and network-specific failures.

## Configure personal devices safely

- Recommend REALITY first, Shadowsocks as a compatibility fallback. Shadowsocks lacks forward secrecy; do not label it the most secure option. Hysteria 2 is an alternative only where UDP works.
- The Hy2 share URI uses a self-signed certificate with an exact `pinSHA256`. Never use a client configuration that drops the pin and merely skips verification. Default batch imports exclude Hy2 for this reason. The official client JSON uses both the exported CA and fingerprint.
- For the user’s own devices, privately transfer only `client-bundle.zip` or its contents. The server private keys and SSH credentials must never be exported. Links/QRs are themselves access credentials, not public documentation.
- Describe actual tests, startup state, where the private bundle is stored and the steps the user must take on their own devices. Do not imply iPhone synchronization or application import has happened unless observed.
- Do not install extra panels, WARP, DNS records, monitoring, or modify the operator's own Surge unless requested separately.

## Maintenance

Use `status` for service state and `fetch` for a new export. There is no in-place update command: preserve credentials and plan upgrades explicitly. `uninstall` deletes only the owned directory/units, but also revokes every client on this installation; execute it only when removal is requested. It does not remove server firewall rules or local bundles.
