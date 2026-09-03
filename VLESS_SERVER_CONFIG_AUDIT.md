# VLESS 服务端配置审计

## 目的

本文档定义个人 Xray 插件实际支持的 VLESS 服务端配置范围。审计以 `XTLS/Xray-core` 服务端实际接受的配置为准，并区分 Xray 配置、Relayward 管理数据和订阅端点数据。

参考基线：`XTLS/Xray-core` `c1958dba`，审计日期为 2026-08-29。

当前进度：静态入站字段、REALITY tunnel、订阅端点、出口线路和节点诊断均已完成实现。由 Relayward 授权动态生成的 `clients` 使用独立运行时控制链路，不作为静态入站字段保存。

## 入站外层字段

当前 Xray VLESS 入站的外层结构如下：

```json
{
  "listen": "",
  "port": 10556,
  "protocol": "vless",
  "tag": "vless-main",
  "settings": {},
  "streamSettings": {},
  "sniffing": {}
}
```

| 字段 | 是否使用 | 使用场景 | 个人插件当前状态 | 审计结论 |
| --- | --- | --- | --- | --- |
| `listen` | 是 | 控制入站监听的本机网络接口 | 仅接受明确的规范 IP 地址 | 不提供页面选项，不作为用户配置保存；生成 Xray 配置时使用监听全部本机接口的语义 |
| `port` | 是 | 客户端连接节点的本地监听端口 | 支持单个数字端口 | 只支持单端口；使用随机高位端口，页面提供重新随机按钮 |
| `protocol` | 是 | 选择 VLESS 入站实现 | 支持 | 固定为 `vless`，不提供编辑入口 |
| `tag` | 是 | 供路由、运行时用户管理和流量统计识别入站 | 使用 `service_id` | 由插件生成不可变标识，不要求管理员填写 |
| `settings` | 是 | VLESS 用户和协议参数 | 部分支持 | 内部字段单独审计 |
| `streamSettings` | 是 | 传输层和 REALITY 参数 | 部分支持 | 内部字段单独审计 |
| `sniffing` | 是 | HTTP、TLS 和 QUIC 嗅探及路由 | 支持 | 内部字段单独审计 |

当前 Xray 不再包含旧文档中的入站 `allocate` 字段，个人插件不实现该字段。

## 端口要求

每个 VLESS 入站只使用一个 TCP 监听端口。个人插件不支持 Xray 原生的端口范围、端口列表和 `env:` 端口表达式。

页面提供随机端口按钮：

- 创建入站时生成一个随机高位端口。
- 每次点击按钮都生成一个不同的候选端口。
- 候选范围固定为 `20000-29999`，避开常见服务端口和 Linux 常见的默认临时端口范围。
- 排除同一草稿内其他受管入站使用的端口，并在服务端保存时再次验证所有受管监听冲突。
- 随机高位端口只能减少常见端口上的无差别探测噪声，不能阻止完整端口扫描，也不能作为安全边界。

端口占用状态分为两层：

1. 页面可以立即判断候选端口是否与当前 Relayward 配置中的端口冲突。
2. 已保存且运行中的入站通过 Relayward 节点诊断显示本地监听状态和订阅端点可达性。创建弹窗尚不能对任意候选端口执行操作系统占用探测，因此新端口最终仍以 Xray 配置测试和实际绑定结果为准。

端口探测结果只代表检查时刻，不是预留机制，也不能消除检查后到启动前的竞争窗口。

## 监听地址要求

VLESS 入站固定监听全部本机网络接口，页面不显示监听地址选项。目标实现应直接使用 Xray 的 AnyIP 语义，不要求管理员填写 `0.0.0.0`。

该设置只决定 Xray 监听哪些本机接口，不负责云防火墙、宿主机防火墙、NAT 映射或中转机访问控制。

## Relayward 附加字段

以下字段不是 Xray 服务端配置，但 Relayward 管理和生成订阅时需要使用：

| 字段 | 作用 | 与 3x-ui 的对应关系 | 当前结论 |
| --- | --- | --- | --- |
| `display_name` | 在后台、订阅和客户端配置中显示入站名称 | 对应 3x-ui 的“入站备注”，不对应“主机” | 保留，页面名称使用“入站名称”或“备注” |
| Relayward 节点端点 | 写入订阅的公网域名或 IP，可为同一节点配置多个 | 对应 3x-ui“主机”的“地址” | 由 Relayward 核心保存和管理，插件只在生成订阅时消费 |
| 节点端点的服务端口覆盖 | 按 `service_id` 覆盖该端点写入订阅的公网端口 | 对应 3x-ui“主机”的“端口” | 没有对应项时使用入站监听端口 |

3x-ui 的“主机”是一个完整订阅端点，除地址和端口外，还可以包含备注、SNI、Host 头、路径、指纹和其他客户端覆盖项。Relayward 节点端点只描述到达物理节点的公网入口；SNI、指纹和协议参数仍由具体运行时插件生成。

## 节点订阅端点要求

每个物理节点可保存多个 Relayward 节点端点。端点包含显示名称、类型、公网地址和按 `service_id` 保存的公网端口覆盖；入站自身只保存实际监听端口。

订阅端点属于 Relayward 核心节点配置，不属于 Xray 原生服务端字段或插件持久配置：

- 直连端点引用 Agent 探测并上报的公网 IPv4 或 IPv6。
- NAT 端点保存管理员填写的固定公网 IP 或域名，并可为不同入站配置公网端口覆盖。
- 外部 DDNS 端点引用由其他系统维护的域名。
- 托管 DDNS 端点由 Relayward 中心根据 Agent 上报地址更新 DNS 记录。
- 一个授权绑定的服务会按全部可用端点展开；例如同一节点配置 IPv4 和 IPv6 两个端点时，订阅生成两个客户端节点。
- 某端点没有对应入站的端口覆盖时，订阅使用该入站的监听端口。
- 地址和端口必须对应真实可达的直连、中转、NAT 映射或其他入口；插件只生成客户端配置，不建立中转、端口映射或 CDN。

### 管理界面

Relayward 节点详情提供“订阅端点”页面，集中管理公网地址、DDNS 和各服务的公网端口覆盖。Xray 插件页面只管理 Xray 实际监听和协议配置。

主机地址允许手动输入域名或 IP，同时提供当前节点探测到的公网 IPv4 和 IPv6 作为候选值供管理员选择。公网 IP 候选应满足以下要求：

- 候选值来自节点主动探测并上报的结果，中心保存其探测时间和地址族。
- 页面明确区分“节点探测值”和管理员手动填写值，不在保存时强制覆盖管理员输入。
- 节点可能位于 NAT、中转或多出口网络之后；探测到的出口 IP 不代表该地址和端口一定可从公网入站访问。
- 中心观察到的 Agent 连接源 IP 只能作为辅助信息，不能冒充节点确认的公网 IP。
- 选择候选 IP 后，各端点仍可按入站填写公网端口覆盖；NAT 映射端口可以与 Xray 本地监听端口不同。
- 没有探测结果、结果过期或节点离线时，页面不阻止手动配置主机地址。

## 出口线路与订阅展开

出口线路不是 VLESS 入站字段。个人插件单独管理系统默认直连、指定本机 IPv4/IPv6、SOCKS5 和 Shadowsocks 2022 出口线路，并为每条启用的线路分配唯一 VLESS route。

同一 VLESS 授权会按“可用订阅端点 × 启用出口线路”生成客户端节点。线路 route 编码在订阅 UUID 中，Xray 在用户匹配前读取该值并选择对应出口；未知 route 会被阻断。访问规则优先于订阅线路，因此管理员仍可对命中的流量强制阻断或改用其他出口。

Shadowsocks 2022 不使用 VLESS route，也不按出口线路复制订阅节点。其未命中访问规则的流量使用默认出口线路。

## VLESS `settings`

### `decryption`

个人插件固定生成：

```json
"decryption": "none"
```

`decryption` 控制 VLESS 协议层的服务端解密方式，不控制 REALITY。当前部署使用 VLESS、Vision 和 REALITY，传输数据仍由 REALITY 加密；个人插件不额外启用 VLESS Encryption，也不在页面提供该字段。

VLESS Encryption 需要服务端 `decryption` 与客户端 `encryption` 成对配置，并要求客户端核心支持。它提供独立于 REALITY 的 VLESS 协议层加密，包括基于 ML-KEM-768 与 X25519 的混合密钥交换。该能力不用于端口隐藏、访问控制、订阅防泄漏或客户端数量限制。

### `fallbacks`

个人插件不支持、不生成 VLESS `fallbacks`。

该字段用于将无法作为正常 VLESS 请求处理的连接，按 TLS SNI、ALPN 或首包路径转发到其他 TCP 地址、端口或 Unix Socket，主要用于让 VLESS 与网站或其他服务复用监听端口。

当前部署使用 VLESS、RAW TCP 和 REALITY。REALITY 的 `target` 负责处理未通过 REALITY 验证的连接，且没有让网站或 WebSocket 服务与 VLESS 共用监听端口的需求，因此不需要额外的 VLESS fallback。`fallbacks` 不能替代 REALITY `target`。

### `flow`

个人插件不生成入站级 `settings.flow`，页面不提供该字段。

该字段只是在解析静态 `clients` 时，为没有单独填写 `flow` 的 VLESS 用户提供默认值。Relayward 根据授权通过 Xray API 动态添加用户，动态用户不会继承入站配置解析阶段的默认值，因此该字段不能作为 Vision 的实际配置来源。

不生成 `settings.flow` 不代表停用 Vision。个人插件在动态添加需要 Vision 的 VLESS 用户时明确设置 `xtls-rprx-vision`。

### `testseed`

个人插件不生成 `testseed`，页面不提供该字段，使用 Xray 内置的 Vision 填充参数。

`testseed` 控制 Vision 对数据包添加随机填充时使用的阈值、基础长度和随机范围，用于弱化固定包长及首包特征。当前部署使用的 `[900, 500, 900, 256]` 与 Xray 内置默认值完全相同，显式写入不会改变行为。

### 最终结构

暂不审计由 Relayward 授权动态生成的 VLESS 用户。静态入站配置的 `settings` 最终只保留 Xray 要求明确设置的字段：

```json
{
  "decryption": "none"
}
```

## `streamSettings`

### 传输方式与安全层

个人插件固定生成：

```json
{
  "method": "raw",
  "security": "reality"
}
```

页面不提供传输方式或安全层选择。当前 Xray 使用 `method` 作为传输方式字段，并继续接受旧字段名 `network`；个人插件只生成当前规范字段 `method`。当前 Xray 将 `raw` 作为原 `tcp` 传输的新名称，仍兼容 `tcp` 别名；个人插件生成服务端配置时使用当前规范名称 `raw`。订阅输出继续遵循各客户端格式对 TCP 传输的表示方式，不因服务端字段改名而改变连接协议。

个人插件不支持 XHTTP、gRPC、WebSocket、HTTPUpgrade、mKCP、Hysteria、TLS 或无安全层的 VLESS 入站。

### `address` 与 `port`

个人插件不生成 `streamSettings.address` 或 `streamSettings.port`。这两个字段用于 XHTTP `downloadSettings` 等需要在嵌套流配置中指定连接目标的场景，不控制普通 VLESS 入站监听地址和端口。

VLESS 入站实际监听位置只由入站外层的 `listen` 和 `port` 决定，避免在两处保存重复配置。

### `rawSettings`

个人插件使用当前规范字段名 `rawSettings`，不生成旧名称 `tcpSettings`。

个人插件不支持 RAW HTTP 伪装头，也不生成 `header`。省略该字段时 Xray 默认使用无额外头部的原始 TCP 数据，与 `header.type: "none"` 等价。

保留 `acceptProxyProtocol` 作为入站开关并默认关闭。只有节点前方明确存在会发送 PROXY Protocol 的 TCP 代理或负载均衡器时才可开启，用于让 Xray 获取代理传递的原始客户端 IP。NAT、iptables 转发或普通 TCP 转发不等于 PROXY Protocol；错误开启会导致不携带 PROXY Protocol 头的普通连接失败。

默认关闭时可以省略整个 `rawSettings`。开启时生成：

```json
{
  "rawSettings": {
    "acceptProxyProtocol": true
  }
}
```

### REALITY 调试字段

个人插件固定关闭并省略 `realitySettings.show`，不提供页面配置。该字段会向标准输出打印 REALITY 握手细节，包括连接地址、Session ID、部分认证密钥和验证结果，只适合 Xray 协议实现的临时调试。

个人插件不支持、不生成 `realitySettings.masterKeyLog`。该字段会把 REALITY/TLS 会话密钥写入文件，以便结合抓包在 Wireshark 中解密外层连接。它不能解密用户与目标网站之间独立的 HTTPS，也不能获取完整 URL，因此不用于风控；持续保存该文件还会产生敏感密钥泄漏风险。

### REALITY 伪装目标与配套 tunnel

页面保留一个面向管理员的“REALITY 伪装目标”配置，默认使用 `www.tesla.com:443`。该值不直接写入 `realitySettings.target`；个人插件为每个 VLESS REALITY 入站自动生成一个仅监听回环地址的配套 tunnel，并把 REALITY `target` 指向 tunnel 的内部端口。

生成结构如下：

```text
无效 REALITY 连接
-> 127.0.0.1 上的配套 tunnel
-> 嗅探 TLS SNI
   |- SNI 精确等于伪装目标域名 -> direct -> 伪装目标
   `- 其他 SNI、无 SNI 或无法嗅探 -> blocked
```

配套 tunnel 的监听端口和 tag 根据 VLESS 入站自动分配与生成，属于插件内部实现，不在页面暴露，也不能脱离所属入站单独管理。内部入站固定使用：

```json
{
  "listen": "127.0.0.1",
  "protocol": "tunnel",
  "settings": {
    "rewriteAddress": "www.tesla.com",
    "rewritePort": 443,
    "allowedNetwork": "tcp"
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["tls"],
    "routeOnly": true
  },
  "streamSettings": {
    "method": "raw",
    "security": "none",
    "rawSettings": {
      "acceptProxyProtocol": true
    }
  }
}
```

当前结构不需要 `portMap`，`followRedirect: false` 使用默认值并省略。配套 tunnel 固定使用 RAW、`security: "none"`，并接收来自 REALITY 的 PROXY Protocol v2。插件按顺序生成一条精确允许目标 SNI 的 direct 规则和一条阻断该 tunnel 其余流量的兜底规则。`routeOnly: true` 保证嗅探结果只用于路由判断，实际出站目标仍固定为配置的伪装目标。

REALITY 服务端最终生成：

```json
{
  "target": "127.0.0.1:<内部端口>",
  "xver": 2
}
```

`type` 由 Xray 根据本地目标自动判断，不生成。`xver` 固定为 `2`，由 REALITY 把它实际看到的客户端地址通过 PROXY Protocol v2 传给配套 tunnel；tunnel 只在回环监听上固定接收该头，从而保留无效 REALITY 握手的来源地址。公网 RAW 入站是否接收上游代理发送的 PROXY Protocol 仍由入站的 `acceptProxyProtocol` 独立控制，两者方向不同。

### REALITY `serverNames`

“REALITY 伪装目标”是目标地址、服务端允许 SNI、配套 tunnel 放行 SNI 和订阅下发 SNI 的唯一配置来源。页面不单独提供 `serverNames` 列表。

伪装目标必须使用域名和端口。个人插件提取目标域名并生成唯一允许值。默认配置 `www.tesla.com:443` 时生成：

```json
{
  "serverNames": ["www.tesla.com"]
}
```

配套 tunnel 只放行同一个精确 SNI，订阅默认下发同一个 `serverName`。个人插件不支持为一个入站配置多个 REALITY `serverNames`，避免伪装目标、服务端验证、tunnel 路由和客户端订阅出现不一致。

### REALITY 密钥

每个 VLESS REALITY 入站在创建时由个人插件自动生成一把独立的 X25519 私钥。`privateKey` 是 Xray 服务端必填的敏感配置，稳定保存并下发给对应节点，不在普通页面明文展示，也不允许管理员分别手工填写私钥和公钥。

REALITY `publicKey` 由 `privateKey` 唯一派生，不属于服务端 `realitySettings`。个人插件按需计算公钥，并在生成订阅时写入客户端配置，不把它保存为第二份可编辑配置。

密钥不会随普通入站编辑自动改变。页面可以提供需要明确确认的独立轮换操作；轮换会立即使所有仍使用旧公钥的客户端失效，客户端必须重新获取订阅。

### REALITY `shortIds`

每个 VLESS REALITY 入站在创建时由个人插件自动生成一个随机的 16 位十六进制 `shortId`，稳定保存并自动写入服务端配置和客户端订阅。页面不提供 `shortIds` 列表编辑，也不为不同用户分配不同值；具体用户仍由 VLESS UUID 识别。

`shortId` 是 REALITY 握手的入口标识。服务端在放行连接进入 VLESS 之前，会结合 REALITY 密钥、时间和版本检查客户端携带的值；不匹配的连接进入伪装目标处理流程。它不替代 VLESS 用户认证，也不用于流量统计或配额。

个人插件不生成 3x-ui 使用的 2、4、6、8、10、12、14、16 位混合候选列表。多个允许值不构成用户隔离，短值还会降低该标识的随机空间。执行 REALITY 密钥轮换时同时生成新的 `shortId`，普通入站编辑不改变它。

### REALITY 客户端版本与时间

个人插件明确生成：

```json
{
  "minClientVer": "1.0.0"
}
```

当前 Xray 在省略 `minClientVer` 时默认只接受版本不低于 `26.3.27` 的 REALITY 客户端。部分非 Xray 核心上报较低的兼容版本，例如当前 sing-box 上报 `1.8.1`。个人插件需要兼容 Xray、sing-box 和 Mihomo，因此使用 `1.0.0` 覆盖 Xray 默认下限。允许旧实现可能带来更明显的旧版 TLS 指纹；这是多核心兼容所接受的取舍。

个人插件不支持、不生成 `maxClientVer`，避免未来客户端升级后因最高版本限制而失效。

个人插件固定关闭并省略 `maxTimeDiff`。该字段按毫秒限制客户端与服务端时间误差，可减少过期握手重放，但会使时钟不准确的客户端直接无法连接；在现有双层认证下收益有限，不引入这项客户端时钟依赖。

### REALITY ML-DSA-65

个人插件不支持、不生成服务端 `mldsa65Seed`，也不向客户端订阅生成对应的 `mldsa65Verify`，页面不展示这两个字段。

ML-DSA-65 为 REALITY 伪造证书增加抗量子数字签名。服务端使用 Seed 签名，客户端使用派生的 Verify 数据确认签名；它保护证书认证，不负责加密流量，也不同于 VLESS Encryption。当前 sing-box 不支持该验证字段，Mihomo 也不作为稳定支持目标，因此启用它会破坏个人插件要求的多核心兼容性。

### REALITY fallback 限速

个人插件为每个 VLESS REALITY 入站固定生成双向 fallback 限速：

```json
{
  "limitFallbackUpload": {
    "afterBytes": 10485760,
    "bytesPerSec": 1048576,
    "burstBytesPerSec": 5242880
  },
  "limitFallbackDownload": {
    "afterBytes": 10485760,
    "bytesPerSec": 1048576,
    "burstBytesPerSec": 5242880
  }
}
```

该限制只作用于没有通过 REALITY 验证并被转发到伪装目标的连接，不影响正常 VLESS 流量。每条连接前 10 MiB 不限速，之后持续限制为 1 MiB/s，并允许最多 5 MiB 的短时突发。上传表示无效客户端到伪装目标，下载表示伪装目标到无效客户端。

限速按连接独立计算，不能替代节点级总带宽限制或 DDoS 防护。参数由个人插件固定管理，不在普通页面提供配置。

## 入站嗅探

个人插件为 VLESS 入站固定生成：

```json
{
  "enabled": true,
  "destOverride": ["http", "tls", "quic"],
  "routeOnly": true
}
```

嗅探读取连接开始阶段的数据，用于提取明文 HTTP Host、TLS SNI 和 QUIC 握手域名。它通常只能获得域名和协议，不能获得 HTTPS 完整 URL。

`routeOnly: true` 使嗅探结果只参与路由和风控判断，不覆盖客户端提交的实际连接目标。个人插件不支持 `metadataOnly`、`domainsExcluded`、`ipsExcluded` 或 FakeDNS 嗅探，不在普通页面提供嗅探开关。

## 套接字选项

个人插件不支持、不生成通用 `streamSettings.sockopt`，页面不展示 Linux 套接字调优项。普通公网 VLESS、RAW 和 REALITY 入站使用节点操作系统及 Xray 的默认网络行为。

`sockopt` 主要用于透明代理、策略路由、多网卡绑定、链式拨号、特殊 DNS 与双栈策略，以及逐套接字覆盖 TCP Fast Open、Keepalive、拥塞控制、窗口、MSS 或 MPTCP。当前部署没有这些需求；节点级 BBR 和其他网络优化继续由操作系统管理。

公网入站接收上游 PROXY Protocol 是保留的明确例外，由入站的 `rawSettings.acceptProxyProtocol` 独立配置；配套 tunnel 的同名设置属于插件固定的内部链路。两者都不需要引入整套 `sockopt`。

## FinalMask

个人插件不支持、不生成 `streamSettings.finalmask`，页面不展示相关配置。

`finalmask` 用于在特殊网络封锁环境中对最终 TCP 或 UDP 流量进行额外伪装，通常要求客户端使用匹配的实现和配置。它不是标准 VLESS、RAW 与 REALITY 入站建立连接所必需的能力；更重要的是，当前 Xray-core 的 `finalmask.tcp` 与 REALITY 组合存在首次连接即可触发进程崩溃的已知问题。个人插件固定使用 REALITY，因此不生成这一不兼容组合。
