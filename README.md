# Relayward Xray Plugin

[中文](#中文) | [English](#english)

[![CI](https://github.com/qqqasdwx/relayward-plugin-xray/actions/workflows/ci.yml/badge.svg)](https://github.com/qqqasdwx/relayward-plugin-xray/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/qqqasdwx/relayward-plugin-xray)](https://github.com/qqqasdwx/relayward-plugin-xray/releases)
[![License](https://img.shields.io/github/license/qqqasdwx/relayward-plugin-xray)](LICENSE)

## 中文

这是维护者个人使用的 [Relayward](https://github.com/Relayward/relayward) Xray 运行时插件。中心插件负责管理页面、配置编排、服务发布和订阅渲染；节点插件负责安装、验证和监督官方 Xray 进程。

本项目只实现已经明确使用的组合，不以覆盖全部 Xray 功能为目标。

### 功能

- Linux AMD64 中心和节点制品
- Debian/systemd 与 Alpine/OpenRC 节点
- VLESS + RAW + REALITY + Vision 入站
- Shadowsocks 2022 AES-128-GCM 与 AES-256-GCM 入站
- 系统默认直连、指定本机 IPv4/IPv6、SOCKS5 和 Shadowsocks 2022 出口线路
- 按来源 IP、授权、入站、网络、嗅探协议、目标 IP、域名和目标端口匹配的有序访问规则
- 访问规则阻断或指定出口线路
- VLESS 按订阅端点和出口线路展开 URI、Mihomo 与 sing-box 节点
- Shadowsocks 按订阅端点展开 URI、Mihomo 与 sing-box 节点
- 授权启停、累计流量、最近在线活动和动态来源 IP 封禁
- 监听状态、本机地址枚举和真实出口探测
- 官方 Xray 版本列表、受限下载、制品大小与 SHA-256 校验
- `xray run -test`、进程切换和失败时保留上一健康配置
- 简体中文与英文管理页面、明暗主题和响应式布局

### 安装要求

- 已运行的 Relayward 中心
- 已注册且在线的 Relayward Agent
- 中心和节点均为 Linux AMD64
- 节点可以通过 HTTPS 访问 GitHub Releases
- 节点防火墙、云防火墙和 NAT 已按实际入站开放端口

Relayward 和本插件不会修改宿主机防火墙、云防火墙、NAT 或中转机配置。

### 安装插件

在 Relayward 的插件页面添加以下 GitHub 仓库，并选择一个已发布版本：

```text
https://github.com/qqqasdwx/relayward-plugin-xray
```

公开仓库不需要 GitHub Token。安装前 Relayward 会显示插件请求的权限：

- `core.authorizations.read`：读取节点授权，用于配置按授权匹配的访问规则。
- `core.network_diagnostics.read`：读取入站监听状态和订阅端点端口诊断。
- `core.node_plugins.configure`：读取和发布节点的 Xray 插件配置。
- `core.node_plugins.diagnose`：读取节点地址并按出口线路执行探测。
- `core.services.write`：发布可绑定到授权的 Xray 入站服务。

安装完成后，插件状态应为 active 和 healthy。

### 首次配置

1. 在 Relayward 中打开一个在线节点的详情页，进入 **Xray**。
2. 在 **运行时** 中选择官方 Xray 版本。
3. 在 **入站** 中添加 VLESS REALITY 或 Shadowsocks 2022。新入站默认使用 `20000-29999` 的随机端口；VLESS 伪装目标默认是 `www.tesla.com:443`。
4. 按需在 **出口线路** 中增加指定 IPv4/IPv6、SOCKS5 或 Shadowsocks 2022 线路，并使用出口探测确认实际出口。
5. 按需在 **访问规则** 中创建有序规则。第一条匹配规则生效。
6. 保存配置并等待节点实例应用新代数、Xray 状态恢复 healthy。
7. 在 Relayward 节点详情中配置订阅端点和公网端口覆盖。
8. 创建用户和节点授权，将授权绑定到 Xray 入站服务。
9. 获取订阅并使用真实客户端连接，确认流量、在线活动和授权状态正常。

### 行为说明

VLESS 固定使用 RAW、REALITY、Vision 和 route-only 的 HTTP/TLS/QUIC 嗅探。每个入站独立生成 REALITY 私钥和 16 位十六进制 Short ID。无效 REALITY 握手进入自动生成的回环 tunnel；只有伪装目标对应的 SNI 可以转发，其余流量阻断。

每个 VLESS 授权与出口线路组合使用独立订阅 UUID。默认线路使用 route `0`，其他线路使用唯一 route；Xray 从 UUID 中读取 route 后选择对应出口，未知 route 会被阻断。Shadowsocks 不复制出口线路，未命中访问规则时走默认线路。

访问规则在同一字段内使用 OR，在不同字段之间使用 AND，并按页面顺序匹配。运行时优先保证本地 API、REALITY SNI 防护、出口探测和 Relayward 动态来源 IP 封禁，然后才执行管理员访问规则和订阅线路路由。

节点插件从官方 `XTLS/Xray-core` Release 下载 `Xray-linux-64.zip`。插件只接受具有有效 GitHub SHA-256 digest、大小在限制内且下载地址与官方 tag 完全一致的制品。Xray 不包含在本插件的 Release 中。

### 访问采集

节点默认开启详细访问采集，可在 **运行时 → 详细访问采集** 中停用。托管授权的 Xray access 记录被转换成 `connection` 事件；在线 IP 快照单独标记为 `activity`，用于本地 IP 限制，不代表逐次访问。内部 API、出口探测和未认证的 REALITY 回落流量不计入用户连接。

文件偏移和待发送事件在同一私有状态文件中提交，重启后继续读取。日志在采集时达到 16 MiB 后轮转，通过 LoggerService 重新打开；原始日志使用 64 MiB 磁盘预算，检查时超预算的数据会截断并明确上报缺失。预算是周期检查限制，突发写入可在检查间隔内暂时超过预算。已入队的日志消费完成后删除，队列满时保留未读取数据并报告不完整；丢失标记保持 24 小时。

采集状态为 `collecting`、`disabled` 或 `incomplete`，由 Agent 独立上报。日志通常没有完整 URL 或可靠的嗅探协议；目标 IP 不会被猜测为域名。原始日志和事件不得写入应用信息日志。

### 开发

```sh
GOWORK=/root/relayward-workspace/tmp/go.work go test ./...
GOWORK=/root/relayward-workspace/tmp/go.work go vet ./...
GOWORK=/root/relayward-workspace/tmp/go.work go build ./...

npm --prefix ui ci
npm --prefix ui run typecheck
npm --prefix ui run lint
npm --prefix ui test
npm --prefix ui run build

./scripts/build-release.sh 0.0.0-dev /tmp/relayward-plugin-xray-release
```

0.x 版本的插件配置格式可能发生破坏性变化。生产发布前应使用正式 Release 制品在 Debian 和 Alpine 节点完成验收。

## English

This repository provides the maintainer's personal Xray runtime plugin for [Relayward](https://github.com/Relayward/relayward). The center plugin owns the administration UI, configuration orchestration, service publication, and subscription rendering. The node plugin installs, validates, and supervises an official Xray process.

The project intentionally supports a focused deployment profile instead of exposing every Xray option.

### Features

- Linux AMD64 artifacts for Debian/systemd and Alpine/OpenRC nodes
- VLESS + RAW + REALITY + Vision inbounds
- Shadowsocks 2022 AES-128-GCM and AES-256-GCM inbounds
- system-default direct, selected local IPv4/IPv6, SOCKS5, and Shadowsocks 2022 egress lines
- ordered access rules matching source IPs, authorizations, inbounds, networks, sniffed protocols, destination IPs, domains, and ports
- block or selected-egress actions
- VLESS subscription expansion across Relayward endpoints and enabled egress lines
- Shadowsocks subscription expansion across Relayward endpoints
- URI, Mihomo, and sing-box subscription contributions
- authorization control, cumulative traffic, recent activity, and dynamic source-IP blocking
- listener diagnostics, node address discovery, and real egress probing
- official Xray release discovery, bounded downloads, exact size and SHA-256 verification
- native Xray configuration checks, process replacement, and preservation of the last healthy runtime on failure
- responsive Simplified Chinese and English administration UI with light and dark themes

### Requirements and installation

The plugin requires a running Relayward center and an enrolled, online Relayward Agent. Both center and nodes must be Linux AMD64, and nodes need outbound HTTPS access to GitHub Releases.

Add the following public repository in Relayward's plugin page and select a published release. No GitHub token is required:

```text
https://github.com/qqqasdwx/relayward-plugin-xray
```

Review and approve these permissions:

- `core.authorizations.read`
- `core.network_diagnostics.read`
- `core.node_plugins.configure`
- `core.node_plugins.diagnose`
- `core.services.write`

Open an online node's Xray page, select an official Xray version, configure inbounds, optional egress lines and access rules, then save. Configure public subscription endpoints in Relayward's node settings, create a user and node authorization, and bind the authorization to the published Xray service.

Relayward and this plugin do not change host or provider firewalls, NAT mappings, or relay configuration. Those paths must expose the configured public ports independently.

### Access collection

Detailed access collection is enabled by default and can be disabled in **Runtime**. Managed Xray access records become `connection` observations; online-IP snapshots are `activity` observations for local IP enforcement. Internal API traffic, egress probes and unauthenticated REALITY fallback traffic are excluded.

Log offsets and queued events commit together. Collection rotates files at 16 MiB using LoggerService and enforces a 64 MiB raw-log budget at polling time. Bursts can exceed the budget between polls. Over-budget data is truncated with an explicit 24-hour gap marker; unread backlog reports incomplete coverage. Collection reports `collecting`, `disabled` or `incomplete` independently of access events. Logs do not provide full URLs or reliable sniffed protocols, and source logs remain private.

### Development commands

Use the commands in the Chinese development section above. Release bundles contain the manifest, separate Linux AMD64 center and node binaries, the sandboxed UI archive, and `SHA256SUMS`. Xray itself is downloaded from official `XTLS/Xray-core` releases and is not bundled.

Configuration compatibility may change during the 0.x series. Validate production candidates with release artifacts on both Debian and Alpine nodes.

## License

This plugin is licensed under GPL-3.0. Xray-core is an independent project distributed under MPL-2.0.
