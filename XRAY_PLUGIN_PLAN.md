# Relayward 个人 Xray 插件实施计划

## 目标

本仓库提供维护者自用的 Relayward Xray 运行时插件。插件在 Relayward 节点上安装并管理官方 Xray，向中心提供入站配置、出口线路、访问规则、订阅片段、授权控制、流量统计和运行诊断。

实现只覆盖已经明确使用的 Linux AMD64 场景，不追求完整复刻 3x-ui，也不暴露任意 Xray JSON。Relayward 中心不运行 Xray；所有 Xray 进程、配置和运行时 API 都由节点插件管理。

## 范围

### 支持

- VLESS + RAW + REALITY + Vision 入站
- Shadowsocks 2022 AES-128-GCM 和 AES-256-GCM 入站
- 系统默认直连、指定本机 IPv4/IPv6、SOCKS5 和 Shadowsocks 2022 出口线路
- 按来源 IP、授权、入站、网络、嗅探协议、目标 IP、域名和目标端口匹配的有序访问规则
- 访问规则阻断或指定出口线路
- VLESS 按订阅端点和启用的出口线路展开客户端节点
- Shadowsocks 按订阅端点展开客户端节点
- Relayward 授权启停、累计流量、最近在线活动和动态来源 IP 封禁
- 官方 Xray 版本列表、下载、摘要校验、配置测试、切换和失败恢复
- Linux AMD64 上的 Debian/systemd 与 Alpine/OpenRC 节点

### 不支持

- 任意 Xray 协议、传输层、安全层和原始 JSON
- 通用 DNS 配置、证书生命周期、WARP、WireGuard、Balancer 或 Observatory
- Windows、macOS、ARM 或在中心内运行 Xray
- 一个入口对应多个 Xray 进程
- 将非 VLESS 入站按出口线路复制为多个订阅节点

## 部署模型

```text
Relayward 中心
  |- 中心插件：页面、配置编排、订阅渲染、服务发布
  `- Relayward Agent 长连接
       `- 节点插件
            |- 官方 Xray 安装与进程监督
            |- 本地 Handler / Routing / Stats API
            `- 节点网络与出口诊断
```

每个节点插件实例管理一个 Xray 进程。一个进程可包含多个入站、内部 REALITY tunnel、出口诊断入口和出口线路。服务使用稳定的 `service_id` 与 Relayward 授权、遥测和订阅绑定。

## 完整操作流程

1. 管理员在 Relayward 安装插件并确认插件权限。
2. 管理员进入在线节点的 Xray 页面，从官方发布列表选择 Xray 版本。
3. 管理员创建一个或多个入站。监听端口默认随机生成在 `20000-29999`，VLESS 伪装目标默认是 `www.tesla.com:443`。
4. 管理员按需增加出口线路。直连线路可使用系统默认路由，也可从节点上报的本机 IPv4/IPv6 中选择源地址。
5. 管理员按从上到下的顺序配置访问规则。规则内同一字段使用 OR，不同字段之间使用 AND，第一条命中后停止。
6. 管理员在 Relayward 节点详情中配置订阅端点和每个服务的公网端口覆盖。端点不属于 Xray 插件配置。
7. 管理员创建用户与节点授权，将授权绑定到已发布的入站服务。
8. 保存 Xray 配置。中心插件生成内部秘密并发布新配置，节点插件下载或复用对应官方 Xray、执行 `xray run -test`，成功后替换运行进程。
9. Relayward 按授权绑定、订阅端点和插件贡献生成 URI、Mihomo 与 sing-box 订阅。
10. 运行期间，Agent 同步授权状态、动态封禁和遥测；管理员可以检查监听状态并按出口线路执行真实出口探测。

## 页面结构

插件页面只出现在节点详情中，包含以下一级页面：

- **概览**：启用的入站、出口线路、访问规则、配置代数和监听状态。
- **入站**：VLESS REALITY 与 Shadowsocks 2022 的列表、创建、编辑、启停和删除。
- **出口线路**：线路列表、出口探测、直连源地址选择、SOCKS5 与 Shadowsocks 2022 凭据。
- **访问规则**：有序规则列表、启停、排序、来源、目标和动作配置。
- **运行时**：官方 Xray 版本选择、配置状态和节点上报的可用网络地址。

所有单选项使用获得焦点即展开的可搜索选择框；搜索输入位于浮层内。保存按钮只在配置发生实际变化时启用，保存前显示变更确认。

## 配置模型

中心页面可编辑的配置只有四个顶层字段：

```json
{
  "xray_version": "26.8.1",
  "services": [],
  "egress_lines": [],
  "access_rules": []
}
```

插件保存时增加内部管理字段：

- 固定本地 API 端口
- 节点凭据种子
- 每个 VLESS 入站的 REALITY 私钥和 Short ID
- 每个 Shadowsocks 2022 入站的服务器密钥
- 出口代理密码

这些秘密保存在 Relayward 的加密插件配置中，不返回给页面。编辑同一 ID、同一类型的对象时保留其秘密；新建或改变类型时生成新秘密。

### 入站

所有入站固定监听全部本机接口，并启用 route-only 的 HTTP、TLS、QUIC 嗅探。

VLESS 固定使用 RAW、REALITY、Vision、`decryption: none`、一个 16 位十六进制 Short ID 和 `minClientVer: 1.0.0`。REALITY 的无效握手进入自动生成的回环 tunnel；只有与伪装目标完全一致的 SNI 可以转发，其他流量全部阻断。fallback 双向流量在每条连接传输 10 MiB 后限速为 1 MiB/s，并允许 5 MiB/s 突发。

Shadowsocks 只支持 2022 AES-128-GCM 和 AES-256-GCM，固定同时监听 TCP 与 UDP。每个授权获得独立派生用户密钥。

### 出口线路

`default` 是不可删除、不可停用、路由值固定为 `0` 的默认线路。其他线路具有唯一内部 ID 和 VLESS route 值。

VLESS 订阅 UUID 编码线路 route；Xray 在用户匹配前提取该值，并按对应线路转发。未知 route 会被阻断。Shadowsocks 不编码线路信息，未命中管理员规则时使用默认线路。

### 访问规则

访问规则的动作是阻断或选择一个启用的出口线路。授权条件会转换为对应服务的内部 Xray 用户标识。规则不能覆盖 Relayward 动态来源 IP 封禁，也不能绕过 REALITY tunnel 的 SNI 防护。

运行时路由顺序固定为：

1. Relayward 本地 API
2. REALITY tunnel SNI 允许与阻断
3. 出口探测入口
4. Relayward 动态来源 IP 封禁
5. 管理员访问规则
6. VLESS 订阅线路路由
7. 未知 VLESS route 阻断
8. Xray 默认使用首个出口，即 `default` 线路

## 分阶段交付

### 阶段 1：共享契约与诊断链路

状态：本地实现完成。

- 中心读取节点授权。
- 中心调用节点插件诊断。
- Agent 转发 `network.addresses` 与 `egress.probe`。
- SDK 定义权限、capability、RPC 校验和 conformance fixture。

验收：SDK、中心、Agent 和插件对同一契约完成编译与单元测试；权限和 capability 使用规范排序。

### 阶段 2：个人配置模型与 Xray 生成

状态：本地实现完成。

- 删除通用 DNS、旧静态路由和全量 Xray 入站字段。
- 实现两种入站、三种出口线路和访问规则。
- 实现 REALITY tunnel、SNI 防护、fallback 限速和 VLESS route。
- 严格拒绝未知配置字段和无效组合。

验收：配置、Xray JSON、路由优先级、秘密保留、官方 Xray 配置检查均有自动化覆盖。

### 阶段 3：订阅、授权与运行时

状态：本地实现完成。

- VLESS 按端点与出口线路展开订阅。
- Shadowsocks 按端点展开订阅。
- 授权启停、动态封禁、流量、活动和重启恢复沿用稳定运行链路。
- 实现本机地址枚举与按线路出口探测。

验收：URI、Mihomo、sing-box、服务控制、遥测和诊断测试通过。

### 阶段 4：管理页面

状态：本地实现与浏览器验收完成。

- 页面按概览、入站、出口线路、访问规则和运行时组织。
- 官方 GitHub Releases 版本列表替代手工输入。
- 所有单选下拉框使用统一的可搜索 Combobox。
- 支持简体中文、英文、明暗主题和 320px 最小宽度。

验收：类型检查、lint、前端单测和生产构建通过；在使用 Relayward UI SDK v1 消息协议的 iframe 中完成桌面与 320px、中文与英文、明暗主题、键盘和弹窗焦点测试。

### 阶段 5：发布制品与真实节点验收

状态：待执行。

- 使用正式 release artifact 在 Debian/systemd 与低资源 Alpine/OpenRC 节点部署。
- 验证真实 VLESS、Shadowsocks、IPv4/IPv6 指定出口、SOCKS5/SS 出口和访问规则。
- 验证中心中断、Agent/插件/Xray 重启、升级失败恢复、配置回滚、授权禁用、配额和动态封禁。
- 记录空闲 CPU、内存、配置切换时间和代表性授权规模下的遥测开销。

验收：上述场景均使用正式制品通过，且不存在未说明的配置兼容或运行依赖后，才进入首个生产支持版本。
