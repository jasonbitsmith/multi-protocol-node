# Multi Protocol Node

**把一台 VPS 配成三种协议，并交付可验证的客户端资料。**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

面向自有或获授权的 Debian / Ubuntu 服务器，提供 **Codex Skill + 独立 Python 工具**。兼容搬瓦工、DMIT 等普通 VPS，不绑定服务商，不要求购买域名。

| 协议 | 默认端口 | 用途 |
|---|---|---|
| VLESS + REALITY + XTLS Vision | TCP 443 | 推荐主用，无需自行申请域名证书 |
| Hysteria 2 | UDP 443 | UDP 网络可用时的备选，固定证书指纹 |
| Shadowsocks AEAD | TCP / UDP 8388 | 兼容备用，chacha20-ietf-poly1305 |

多协议不等于多线路：三者仍共用一台服务器。不会承诺“永不被封”或某协议一定更快。SS 不具备前向保密，当前 Xray 已提示其弃用；本项目保留它仅用于兼容。

## 提供什么

- 检查平台、端口和已有防火墙，拒绝覆盖已有部署。
- 固定 Xray / Hysteria 版本，校验发布文件 SHA-256 后才执行。
- 独立随机凭证、开机自启、服务异常重启；普通安装失败会清理本次新建资源。
- 导出链接、可选二维码、证书和客户说明；服务端私钥与 SSH 密码不进入交付包。
- 从外部通过三个实际代理连接请求 HTTPS，记录成功与失败，不把“服务启动”当成“能用”。

不会自动装面板、开 SSH 免密、改个人 Surge、购买域名、添加 DNS、开启 WARP 或调整供应商防火墙。

## 方式一：作为 Skill 使用

```sh
git clone https://github.com/jasonbitsmith/multi-protocol-node.git
mkdir -p ~/.codex/skills
cp -R multi-protocol-node/skills/multi-protocol-node ~/.codex/skills/
```

若同名 Skill 已存在，请先比较版本，不要盲目覆盖。重新打开或刷新支持 Skill 的会话，然后输入：

> 使用 $multi-protocol-node，帮我在已授权的 VPS 上配置多协议节点。已有 SSH 别名为 my-vps，客户使用 Windows 和 iPhone。先检查旧服务，再部署并做外部验证。

Skill 本身不授予服务器访问权限；沿用使用者已有的 SSH 登录方式。其他能够读取 `SKILL.md` 的代理也可以按说明调用脚本。

## 方式二：直接运行

本地：Linux/macOS、Python 3.10+、OpenSSH、curl。Windows 操作者可用 WSL。

服务器：Debian/Ubuntu、systemd、Python 3.10+、OpenSSL、curl、iproute2，支持 amd64/arm64；本版本要求公网 IPv4。缺失依赖可在确认目标机器后安装：

```sh
apt-get update
apt-get install -y python3 curl openssl iproute2 ca-certificates
```

先正常 SSH 登录，核对主机指纹。以下使用已经配置好的 root SSH 别名 `my-vps`。非 22 端口需要给每个远程命令加 `--ssh-port 实际端口`。

```sh
cd multi-protocol-node
python3 -m venv .venv
. .venv/bin/activate
# 可选；安装后 fetch 会附带二维码
pip install -r skills/multi-protocol-node/requirements-export.txt

# 将两个占位值替换为真实公网 IPv4 和经确认合适的 REALITY 目标主机名。
python skills/multi-protocol-node/scripts/node.py install \
  --ssh my-vps --host YOUR_PUBLIC_IPV4 --target YOUR_REALITY_TARGET

# 在仓库外保存私密资料。目录必须是新的，防止覆盖已有客户凭证。
python skills/multi-protocol-node/scripts/node.py fetch \
  --ssh my-vps --output "$HOME/private-node-exports/my-vps"

# 必须在 VPS 外运行；任一协议失败则退出码非零。
python skills/multi-protocol-node/scripts/node.py verify \
  --directory "$HOME/private-node-exports/my-vps"
```

脚本不提供 REALITY 目标的通用默认值：目标须从服务器可达、支持 TLS 1.3 / h2；被 Xray 明确警告的目标会被拒绝。有关选择与失败排查，见 [运维说明](skills/multi-protocol-node/references/operations.md)。

端口可改：`--reality-port 8443 --hysteria-port 8443 --ss-port 8388`。TCP 和 UDP 可共用端口号，SS 则占用两者。已有防火墙时会要求先检查，`--firewall-reviewed` 只确认已检查，不会替你开放端口。供应商安全组也须允许对应端口。

## 客户交付

只发 `client-bundle.zip`。里面包含：

- REALITY、Shadowsocks、Hysteria 2 各自链接；安装二维码依赖后也有二维码。
- 默认批量导入文件（REALITY + SS）。
- 官方 Hysteria 客户端配置与公开证书。
- iPhone / Windows 操作说明。

**Hysteria 2 必须保留证书指纹校验。** 自签名链接使用 `insecure=1` 与 `pinSHA256` 配对；若某客户端丢弃指纹，不能仅靠“跳过证书验证”使用它。所以默认批量导入不含 Hy2。另一种方式是使用包内官方客户端配置，它同时启用自定义 CA 和指纹校验。

导出包、节点链接和二维码都是访问凭证，请勿提交到公开仓库。客户端版本是否完整支持相关参数，需要在实际设备上检查；生成文件不代表已经在手机导入或同步。

## 查看与卸载

```sh
python skills/multi-protocol-node/scripts/node.py status --ssh my-vps
# 只在确实需要移除此安装时执行；会断开使用这些节点的全部客户端。
python skills/multi-protocol-node/scripts/node.py uninstall --ssh my-vps
```

安装位置为 `/opt/multi-protocol-node`，服务为 `mpn-xray` / `mpn-hysteria`。卸载会检查所有权标记，仅移除本项目的服务和目录，不修改 SSH、防火墙或其他服务。本版本不做自动更新或覆盖升级。

## 验证范围

部署方案已在 Ubuntu amd64 VPS 上验证过三个协议的外部 HTTPS 连通性；这来自整理前的实际部署。公开版脚本增加了参数化、失败回滚和包导出保护，有离线自动化测试；**尚不代表所有发行版、架构、手机客户端的完整端到端认证**。

```sh
python -m unittest discover -s tests -v
# 可选：使用自己下载并校验过的官方二进制做本机冒烟测试。
python tests/smoke_binaries.py --xray /path/to/xray --hysteria /path/to/hysteria
```

测试覆盖：端口冲突、参数拒绝、密钥输出兼容、错误校验和、压缩包路径安全、私钥不进入客户包、证书 pin 保留、失败回滚和未归属安装的卸载保护。附带的 CI 模板只运行离线测试，不访问或部署真实客户服务器。

本机真实二进制冒烟测试验证过 Xray 配置，以及 Hy2 的 CA + 正确指纹握手和错误指纹拒绝。它只监听临时本机端口，不等于远端公网连通性验证。

如需启用 GitHub Actions，将 `examples/github-actions-tests.yml` 复制为 `.github/workflows/tests.yml` 并提交。推送该文件需要 GitHub 凭据具有工作流写入权限；初始发布未启用自动 CI。

## 项目结构

```text
skills/multi-protocol-node/
  SKILL.md                     AI 代理入口
  agents/openai.yaml           Codex 元数据
  scripts/node.py              SSH 部署、导出和验证
  scripts/server.py            服务器安装、状态、卸载
  scripts/common.py            配置与下载校验
  scripts/versions.lock.json   上游版本与 SHA-256
  references/operations.md     运维、限制与官方参考
tests/                        离线行为测试
```

## 贡献与许可

欢迎提交脱敏的问题报告或 PR，附操作系统、架构、客户端版本、失败阶段和已遮蔽凭证的日志。不要提交真实服务器地址、账号密码、私钥、订阅或二维码。

项目脚本与文档使用 [MIT License](LICENSE)。Xray、Hysteria、qrcode 等上游组件保留各自许可证；本仓库不分发它们的二进制。仅管理自有或明确获授权的服务器，并遵守适用规定和服务商条款。
