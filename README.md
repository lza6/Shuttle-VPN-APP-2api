# Shuttle VPN (Super VPN 2.3.246) — 逆向 + 节点收割 + SOCKS5 代理池

把 `com.shuttlevpn.free.proxy.gaming`（PowerVPN SDK 白标，Play 商店名 **Super VPN**）
的节点目录完整还原，并做成一条「APK → 节点凭证 → OpenVPN 隧道 → SOCKS5 端口 →
new-api 代理池」的可跑流水线。

> ⚠️ 合规：节点是上游商业 VPN 的自有服务器，凭证由上游签发。逆向披露属于安全研究，
> **把别人的服务器挂进自己的生产池属于盗用基础设施**。本仓库用于协议研究 / 自有链路验证，
> 请勿大规模用于生产。详见 `docs/REVERSE_REPORT.md` 第 5 节。

---

## 状态

| 环节 | 状态 | 证据 |
|---|---|---|
| 协议还原（API + 加密 + 目录结构） | ✅ 完成 | `docs/PROTOCOL.md` |
| 加密层（DES + AES） | ✅ **100% 静态还原**（Unicorn 模拟 7 个 builder 拿到全部 key/IV），无需设备 | `docs/REVERSE_REPORT.md` §2.1、`tools/powercrypto.py` |
| 目录抓取 | ✅ 线上 + 内置 双份 | 130 条节点 / 110 唯一 host |
| 纯离线收割（无设备） | ✅ 端到端实测：线上目录 18+3、内置 48/42/19 → **110 唯一 host，密码与设备 oracle **110/110 逐条一致** | `tools/harvest.py`（默认离线模式） |
| 每节点密码解密 | ✅ 110/110 | 32 字符 hex |
| OpenVPN 握手测活 | ✅ 220 配置 → 10 存活 | 4.5% |
| 真实隧道出口校验 | ✅ 4 端点数据面正常 | 出口 IP = 节点 IP |
| SOCKS5 池层（netns + microsocks + fail-closed） | ✅ 8 隧道常驻 | 端口 44000+i |
| 本地压测 | ✅ 两轮 | 见下表 |
| Demo 面板 | ✅ 实测通过（HTTP 200 + JSON） | `demo/server.py` :8961 |
| new-api 对接 | ✅ 从 Windows 实测走通 SOCKS5 出口 | `docs/NEWAPI_INTEGRATION.md` |

## 实测数据

**测活**（WSL / openvpn 2.6.19，只验 TLS 控制信道 + 账号，`--dev null`）

| 轮次 | 配置数 | 并发 | 超时 | UP | 存活率 |
|---|---|---|---|---|---|
| R1 | 220 | 10 | connect 5s / poll 12s | 10 | 4.5% |
| R2 | 220 | 14 | connect 8s / poll 25s | 10 | 4.5%（存活集合会漂移） |

存活 host：`142.202.48.20`(US/GTHost, tcp+udp)、`162.251.62.100`(US/GTHost, tcp+udp) 数据面正常；
`149.7.16.252`(GB)、`152.67.194.13`(KR)、`169.197.143.32`(US)、`193.123.87.23`(AE) 握手成功但数据面
不通或时通时断 —— **握手成功 ≠ 可用**。

**压测**（`tools/bench.py`，走 SOCKS5，真实 HTTPS 请求 `api.ipify.org` + 2 MB 下载测速）

| 端点 | 协议 | 并发×轮次 | 成功率 | P50 | P95 | 吞吐 | 出口 IP |
|---|---|---|---|---|---|---|---|
| 44000 | tcp | 4×3 (12 req) | 100% | 2694 ms | 2930 ms | 4.32 Mbps | 142.202.48.20 |
| 44001 | udp | 4×3 | 100% | **1354 ms** | 1646 ms | **6.51 Mbps** | 142.202.48.20 |
| 44005 | tcp | 4×3 | 100% | 2483 ms | 2815 ms | 4.09 Mbps | 162.251.62.100 |
| 44006 | udp | 4×3 | 100% | **1293 ms** | 1396 ms | **5.86 Mbps** | 162.251.62.100 |
| 44001 | udp | 8×4 (32 req) | 100% | 1468 ms | 1816 ms | 5.19 Mbps | 142.202.48.20 |
| 44006 | udp | 8×4 (32 req) | 100% | 1421 ms | 1526 ms | 6.41 Mbps | 162.251.62.100 |

结论：**UDP/800 明显优于 TCP/8080**（延迟低约一半、吞吐高约 40%，典型 TCP-over-TCP 代价）；
8 并发下零失败，单隧道 5–6.5 Mbps。延迟 1.3–2.7 s 是「中国出口 → 美国节点 → 再出网」的跨境
往返，不是本地网络问题。

## 快速开始

```bash
# 0) 依赖（只需要网络；加密常量已内置）
pip install pycryptodome            # 只有 --device 模式才需要 frida==16.5.9

# 1) 抓目录 + 解密凭证 + 生成每节点 .ovpn（不需要任何设备！）
python3 tools/harvest.py --assets <apk解包目录>/assets --out output

# 2) 全量测活（只验握手，几分钟）
bash tools/scan.sh 14 8 25 | tee output/scan.txt
# -> 从 UP 行生成 output/nodes_alive.json（见 docs/REVERSE_REPORT.md §6）

# 3) 起 SOCKS5 池（每条隧道一个 netns）
sudo python3 tools/pool_layer.py up output/nodes_alive.json --max 10
sudo python3 tools/pool_layer.py status

# 4) 压测
python3 tools/bench.py --ports 44000-44009 --conc 8 --rounds 4

# 5) 面板
python3 demo/server.py 8961     # http://127.0.0.1:8961

# 6) 给 new-api 生成代理清单
python3 tools/gen_newapi_pool.py --host 172.17.0.1 --out /opt/new-api/proxies/shuttle.txt
```

## 架构

```
new-api (容器/宿主)
   │ socks5://<host>:44000+i
   ▼
pool_layer.py TCP 中继 (0.0.0.0:44000+i)
   │
   ▼
netns vpnI ── microsocks 10.200.x.y:34000+i
   │            ▲
   │            └ iptables: veth 只放行「VPN 服务器 /32 + 宿主网关」，隧道断即全断（fail-closed）
   ▼
tun0 (OpenVPN, 服务端 push 0.0.0.0/1 + 128.0.0.0/1)
   ▼
上游节点 → 互联网出口
```

## 仓库结构

```
docs/PROTOCOL.md            协议/加密/目录/最小实现手册（对接方先看这个）
docs/REVERSE_REPORT.md      完整逆向报告 + 踩坑 + 合规判定 + 验证日志
docs/NEWAPI_INTEGRATION.md  new-api 代理池对接（容器网络三方案 + 三层验证）
tools/powercrypto.py        ★ DES + AES 离线编解码（自校验）
tools/emu.py                Unicorn 模拟器：跑 .so 里的混淆 builder 提取常量
tools/rpc_bridge.js         Frida RPC 兜底（App 若换加密层时用）
tools/harvest.py            抓目录 + 解密 enpass + 生成每节点 ovpn（默认离线）
tools/scan.sh               OpenVPN 握手测活（并行）
tools/pool_layer.py         netns + microsocks + fail-closed 的 SOCKS5 池层
tools/bench.py              SOCKS5 压测（延迟/成功率/吞吐/出口 IP）
tools/gen_newapi_pool.py    生成 new-api 的代理清单
demo/server.py + index.html 面板（池状态 / 单点探测 / 整池压测）
samples/nodes.public.json   脱敏节点快照（110 条，含握手存活标记）
```

运行期产物（`output/`、凭证、ovpn、日志）全部 gitignore。

## 路线图

- [x] ~~纯静态还原 DES/AES key+IV~~ 已完成（Unicorn 模拟，见 `docs/REVERSE_REPORT.md` §2.1）→ 收割不再依赖设备
- [ ] 把 scan/隧道健康检查做成守护进程（双阈值摘除 + 自动重连）
- [ ] 上游 `protocol2`（DProxy/DXProxy/DSProxy/TCP/UDP 通道）与 `nut_port` 的还原（本版本走的是 OpenVPN，其他通道未启用）
- [ ] IKEv2（strongswan）通道还原

## 协议速查（详见 docs/PROTOCOL.md）

```
GET {base}/superwg.php?v=urlencode( base64_nopad( DES_CBC_PKCS5("m=init" + query) ) )
base ∈ api.fastcloud.me | api.pm-img.com | api.itranslator.info | api.supershell.me | 193.108.117.109 | 193.108.118.25
key/IV = 编译期常量（DES key 20190826 / IV 00514321；AES key 2019082620190826 / IV 0051432100514321）
完整性校验: signatures[0].hashCode() == 1057427404
节点: {host, enpass(加密密码), load, ...}   密文解密后 user=superike / pass=enpass明文
连接: OpenVPN, remote <host> 800 udp 或 <host> 8080 tcp, tls-crypt + ca 模板在 assets/privacy_policy.txt(加密)
```
