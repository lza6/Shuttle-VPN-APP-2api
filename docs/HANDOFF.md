# 交接单 — Shuttle VPN 池接入 new-api

> 给「对接会话」的唯一必读文档。照着敲即可，不需要重新逆向、不需要设备。
> 深度细节另见 `PROTOCOL.md`（协议）/ `REVERSE_REPORT.md`（逆向过程）/ `NEWAPI_INTEGRATION.md`（容器网络细节）。

---

## 0. 一句话现状

上游节点目录已 100% 还原（110 个唯一 host + 每节点 OpenVPN 密码），加解密全静态；
本仓库能把它们跑成一组 SOCKS5 端口，new-api 直接把端口写进 `TRYINGOPEN_PROXY_FILE` 就能用。
**new-api 侧不需要改任何业务代码。**

## 1. 你要交付的东西

| 目标 | 判定标准 |
|---|---|
| 池跑起来 | `pool_layer.py status` 里每条隧道都有 `exit.ip`，且 **等于节点 IP、不等于本机出口 IP** |
| new-api 认识这些出口 | `/api/twoapi/proxy_pool` 能看到 `source=residential` 的条目，数量 = 隧道数 |
| 真流量能出去 | 发一条真实 relay 请求，**上游侧看到的来源 IP = 节点 IP** |

> 只看池快照有条目 **不算打通**。必须做出口 IP 校验（`https://api.ipify.org`）。

---

## 2. 环境要求

- Linux 或 WSL2（root）：要 `netns` / `veth` / `iptables` / `openvpn` / `microsocks`
- Python 3.9+，`pip install pycryptodome`
- **不需要** root 手机 / 模拟器 / Frida（那是 `--device` 兜底模式才用）

一次性装依赖（Debian/Ubuntu）：

```bash
sudo apt-get update && sudo apt-get install -y openvpn microsocks iptables iproute2
pip install pycryptodome
```

---

## 3. 六步跑通

```bash
git clone https://github.com/lza6/Shuttle-VPN-APP-2api && cd Shuttle-VPN-APP-2api

# ① 拿节点凭证 + 生成每节点 ovpn（纯 Python，无需设备）
python3 tools/harvest.py --assets <apk解包>/assets --out output
#    没有 APK？只跑线上目录也行： python3 tools/harvest.py --out output
#    实测输出： nodes with credentials: 110 (unique hosts)

# ② 测活：只保留真正能完成 TLS 握手的
bash tools/scan.sh 14 8 25 | tee output/scan.txt        # 并行14 / connect 8s / poll 25s
grep '^UP' output/scan.txt | awk '{print $2}'           # 形如 142.202.48.20_udp
```

```bash
# ③ 组 nodes_alive.json（把 ② 的 UP 行填进来；udp->800, tcp->8080）
cat > output/nodes_alive.json <<'JSON'
[
 {"host":"142.202.48.20",  "port":800,  "proto":"udp", "cfg":"output/cfg/142.202.48.20_udp.ovpn"},
 {"host":"142.202.48.20",  "port":8080, "proto":"tcp", "cfg":"output/cfg/142.202.48.20_tcp.ovpn"},
 {"host":"162.251.62.100","port":800,  "proto":"udp", "cfg":"output/cfg/162.251.62.100_udp.ovpn"},
 {"host":"162.251.62.100","port":8080, "proto":"tcp", "cfg":"output/cfg/162.251.62.100_tcp.ovpn"}
]
JSON
```

```bash
# ④ 起池（前台跑 = 常驻；每隧道一个 netns，宿主端口 44000+i）
sudo python3 tools/pool_layer.py up output/nodes_alive.json --max 10
sudo python3 tools/pool_layer.py status        # 另开一个终端看

# ⑤ 生成 new-api 的代理清单（--host 见第 5 节）
python3 tools/gen_newapi_pool.py --host 172.17.0.1 --out /opt/new-api/proxies/shuttle.txt

# ⑥ new-api 配环境变量并重启
#    TRYINGOPEN_PROXY_FILE=/opt/new-api/proxies/shuttle.txt
```

清单长这样（文件里 `#` 后面是注释，解析器会跳过）：

```
socks5://172.17.0.1:44000  # 142.202.48.20:8080/tcp US 142.202.48.20
socks5://172.17.0.1:44001  # 142.202.48.20:800/udp US 142.202.48.20
```

---

## 4. 三层验收（复制粘贴）

```bash
# 隧道层
sudo ip netns exec vpn0 unshare -m --propagation private sh -c \
  'mount --bind /tmp/shuttle_pool_resolv.conf /etc/resolv.conf; curl -s https://api.ipify.org'

# 池层
curl -x socks5h://127.0.0.1:44000 https://api.ipify.org

# new-api 池快照
curl -s http://127.0.0.1:3000/api/twoapi/proxy_pool | head -c 600

# 业务层：随便发一条 relay 请求，在**上游侧**核对来源 IP
```

三条的 IP 必须**相同且等于节点 IP**；本机自己的出口 IP 用
`curl -s --noproxy '*' https://api.ipify.org` 单独取一次做对照。

---

## 5. `--host` 到底填什么（首次对接最常见的失败点）

`pool_layer.py` 跑在宿主/WSL 的网络命名空间，端口绑 `0.0.0.0:44000+i`。**new-api 在容器里时，容器内的 `127.0.0.1` 是容器自己的 loopback，连不到宿主。**

| new-api 跑在哪 | 清单里的 host | 额外配置 |
|---|---|---|
| Docker Compose（推荐） | `host.docker.internal` | compose 加 `extra_hosts: ["host.docker.internal:host-gateway"]` |
| Docker + `network_mode: host` | `127.0.0.1` | 无 |
| Windows 原生进程 | `127.0.0.1` | 无（WSL2 会把宿主端口转发到 Windows localhost，已实测） |
| 与池同机但走局域网 IP | WSL 的 `192.168.x.x` | 放行 Windows 防火墙 |

---

## 6. 已知约束（务必按这个来，否则会误判）

1. **上游按源 IP 限流**：连续扫描/重连多了会被 `TLS key negotiation failed`（60s 无响应）挡住，等几分钟自愈。
   → 扫描并发 ≤ 14、两次扫描间隔 ≥ 10 分钟；`pool_layer.py` 已内置 3 次退避重试。
2. **存活率只有 ~4.5%**：220 个「host×transport」里通常 10 个能握手，其中数据面真通的更少。
   **握手成功 ≠ 可用**，必须出口 IP 校验。
3. **节点集合会漂移**：同一 host 的 udp/tcp 独立存活，几小时前后结果可能不同 → 定期重跑 ②。
4. **`pool_layer.py` 必须常驻**（前台/systemd/supervisor）。进程一停，端口全没。
5. **`--route-nopull` 不要用**：会握手成功但 tun RX=0。池层已按「服务端 push 路由」正确配置，别改。
6. **fail-closed 规则别删**：netns 内 `iptables -A OUTPUT -o vethXp ! -d <VPN服务器>/32 ! -d <宿主网关>/32 -j DROP`。
   删了隧道断线时会回落宿主真实 IP（泄漏）。
7. **端口数少 → 冷却会拖垮整池**：`TRYINGOPEN_USE_COOLDOWN_MAP`（0/30/90/300/900s 递增）配
   `TRYINGOPEN_PROXY_MAX_USE_PER_DAY` 调小（如 2000），或把本池当**补充出口**而非主力。

---

## 7. 排障表

| 现象 | 原因 | 处理 |
|---|---|---|
| `Options error: --auth-user-pass fails` | ovpn 里凭证路径写成了 Windows 绝对路径 | 用 `harvest.py` 重新生成（现在写相对 `creds/<host>.txt`），并确保 openvpn 的 CWD 是 `output/` |
| 隧道起来了但 `ip netns exec vpn0 curl` 全是 DNS 失败 | netns 内 `/etc/resolv.conf` 指向宿主 DNS | 池层已用 `unshare -m` 绑隧道侧 DNS；手工测试请照第 4 节的写法 |
| 隧道起来但 SOCKS 全超时 | fail-closed 规则把「回宿主网关」也拦了 | 规则必须同时放行 `<宿主网关>/32`（池层已处理） |
| netns 完全出不了网（`Network is unreachable`） | 宿主 `FORWARD` 被 docker 改 DROP / 缺 MASQUERADE | 池层启动时会自动加，手工检查 `iptables -L FORWARD -n \| head` |
| 端口在宿主上 `ss` 能看到，容器连不上 | 见第 5 节 | 换 `--host` |
| `pool_layer.py up` 报 `Address already in use` | 上一个池进程没死 | `pkill -f 'pool_layer\.py up'`（注意转义，否则会杀掉自己的 shell） |

---

## 8. 交付时请在 PR/交接消息里带上这些证据

- `harvest.py` 输出的 `nodes with credentials: N (unique hosts)`
- `scan.txt` 的 UP 数量
- `pool_layer.py status` 的输出（含 `exit.ip`）
- 第 4 节三层验收的实际返回
- 使用的 `--host` 与 new-api 部署形态

## 9. 合规红线（写进交付说明）

节点是上游商业 VPN 自有服务器（GTHost 等 hosting IP），凭证由上游签发，上游 ToS 禁止非官方客户端接入。
**技术可行性 ≠ 使用权**。本仓库用于协议研究与自有链路验证；大规模入生产池属于盗用基础设施，
且上游可随时按 IP/账号封禁。生产长期稳定池请用自有 VPS（WireGuard/Hysteria2 → SOCKS5）
或正规住宅代理供应商。
