# 正式制品验收记录

## 验证范围

2026-09-08 至 2026-09-09 使用以下制品完成定向集成验证：

- 中心：`Relayward/relayward` 提交 `fcc9d6d` 的 GHCR `dev` 镜像，镜像摘要 `sha256:f76cc28f1ce5df547c78b18b0fdd0eecfb7159f1ea50cf94744c26c991fae0ea`。
- Agent：正式 Release `0.2.0`。
- 个人 Xray 插件：正式 Release `0.5.2`。
- Xray：官方 `26.7.28`。
- 节点：Debian 12/systemd 与 Alpine 3.21.7/OpenRC，均为 AMD64；Alpine 经 NAT 映射业务端口。
- 客户端：sing-box `1.14.0`、Xray `26.7.28`。

中心 [Actions 34075487501](https://github.com/Relayward/relayward/actions/runs/34075487501) 全部通过。中心使用 CI 镜像，本记录不代表中心正式版本已经发布。

## 已验证

| 场景 | 结果 |
| --- | --- |
| Debian VLESS 默认出口、指定本机 IPv4 出口 | HTTPS 请求成功，出口为节点 IPv4 |
| Debian Shadowsocks 2022 AES-256 | 使用当前订阅，从开发机 sing-box 和 Alpine Xray 客户端请求成功 |
| Alpine VLESS + REALITY + Vision | 通过 NAT 对外端口成功请求，出口与节点直接请求一致 |
| Alpine 禁用、重新启用授权 | 新连接分别被阻断、恢复成功 |
| Alpine 设置低于已用流量的配额、移除配额 | 新连接分别被阻断、恢复成功 |
| Alpine 删除服务绑定 | 节点最终移除入站用户，旧订阅无法新建连接 |
| Alpine OpenRC 重启 Agent | 重启后 VLESS 请求成功，插件恢复 healthy |
| Alpine 流量回传 | 中心收到非零上下行累计值和有效观察时间 |
| 节点最终状态 | 两节点插件均为正式 0.5.2，实际配置代次与期望代次一致 |

这些连接检查覆盖 TCP/HTTPS，不代表 UDP 已验收。阻断检查使用新请求，不证明既有长连接会立即断开。

## 环境与时序发现

Debian UFW 最初未放行新增 Shadowsocks 端口。抓包显示 SYN 到达节点但未得到应答；补齐业务端口规则并使用当前订阅后，两个独立客户端均成功。新增入站必须同时核对宿主防火墙和 NAT/云防火墙。

删除服务绑定是异步下发：固定等待三秒时，新请求曾仍成功；节点入站用户移除后，同一客户端新请求被阻断。该次检查未测出准确收敛耗时，不能将 API 成功视为节点已经完成应用。

Alpine 重启后仅有一个受管 Xray 进程。节点文件系统约 549 MiB，其中已用约 106 MiB；这只是占用快照，不是压力测试。

## 尚未完成的阶段 5 检查

- 两个环境均无可用公网 IPv6，指定 IPv6 出口未实测。
- 本轮未完整复测 SOCKS5/SS 出口、访问规则、UDP 和动态 IP 封禁。
- 本轮未完整复测中心中断、插件/Xray 单独异常退出、升级失败恢复和配置回滚。
- 尚缺策略收敛耗时，以及代表性授权规模下 CPU、内存和遥测开销的正式制品测量。

上述未完成项不能用基础连通测试替代。阶段 5 保持进行中。
