# new-api 对接指南 — Shuttle VPN 池

目标：把 `pool_layer.py` 起的每一条隧道，当成 new-api 代理池里的一个普通 SOCKS5 出口。

**new-api 侧不需要改任何业务代码。** `relay/channel/tryingopen/proxy_pool.go` 的
`LoadProxies()` 原生支持：

- `TRYINGOPEN_PROXY_FILE`：**逗号分隔的文件列表**，每行 `socks5://host:port`，`#` 开头跳过
- 从该文件读入的条目：`source="residential"`，`healthScore=1.0`（池内最高权重档）
- `TRYINGOPEN_PROXIES`：直接给逗号分隔的 URL（不走文件）
- `TRYINGOPEN_PROXY_MAX_USE_PER_DAY`：每出口每日用量上限（0 = 不限）
- `TRYINGOPEN_USE_COOLDOWN_MAP`：429 冷却曲线（0/30/90/300/900s 递增）

源码注释里就写着「住宅清单 + 本地协议转换层（如 hysteria2 → socks5 端口列表）」——
本项目的 `pool_layer.py` 就是那个转换层（OpenVPN → SOCKS5）。

---

## 1. 拓扑

```
new-api (容器/宿主)
   │  socks5://<reachable-host>:44000+i
   ▼
pool_layer.py 中继 (WSL 主命名空间, 0.0.0.0:44000+i)
   │  TCP relay
   ▼
netns vpnI (10.200.x.y:34000+i, microsocks)
   │  默认路由 = tun0
   ▼
OpenVPN 隧道 → 上游节点 → 互联网
```

`iptables -A OUTPUT -o vethXp ! -d <server>/32 ! -d <host-gw>/32 -j DROP` 保证：
隧道一断，该 netns 没有任何可用出口（**fail-closed**，不会回落宿主真实 IP）。

## 2. 端口约定

| 端口 | 用途 |
|---|---|
| `44000 + i` | 宿主侧 SOCKS5 入口（给 new-api 用） |
| `34000 + i` | netns 内 microsocks（内部） |
| `10.200.(i*4)/30` | 每条隧道的 veth 网段（内部） |

## 3. 三步接入

```bash
# 1) 起池（WSL 内，root）
cd tools
python3 pool_layer.py up output/nodes_alive.json --max 10
# -> /tmp/shuttle_pool_state.json

# 2) 生成 new-api 的代理清单
python3 gen_newapi_pool.py --host 172.17.0.1 \
        --out /opt/new-api/proxies/shuttle.txt
#    host 取值见下面第 4 节

# 3) 配 new-api 环境变量并重启
TRYINGOPEN_PROXY_FILE=/opt/new-api/proxies/shuttle.txt
```

清单长这样：

```
socks5://172.17.0.1:44000  # 142.202.48.20:8080/tcp US 142.202.48.20
socks5://172.17.0.1:44001  # 142.202.48.20:800/udp US 142.202.48.20
```

验证：

```bash
curl -s http://127.0.0.1:3000/api/twoapi/proxy_pool   # 能看到 residential 来源条目
curl -x socks5h://172.17.0.1:44000 https://api.ipify.org   # 出口 IP 必须是节点 IP
```

## 4. 「容器里的 127.0.0.1 不是宿主」——首次对接最常见失败点

`pool_layer.py` 跑在 WSL 宿主命名空间，端口绑在 WSL 的 `0.0.0.0`。new-api 在 Docker 里时：

| 方案 | 做法 | 适用 |
|---|---|---|
| A（推荐） | docker-compose 加 `extra_hosts: ["host.docker.internal:host-gateway"]`，清单里写 `socks5://host.docker.internal:44000` | 单机 docker compose |
| B | new-api 容器 `network_mode: host` | 简单粗暴，但与其他服务端口冲突风险 |
| C | 清单写 `socks5://<WSL 的局域网 IP>:44000`（`ip -4 addr` 里的 `192.168.x.x`） | WSL 桥接模式；Windows 防火墙需放行 |
| D | 转换层直接跑在 new-api 同一 compose 网络里（Linux 宿主） | 生产形态 |

> WSL2 会把 WSL 内 `0.0.0.0:端口` 转发到 Windows 的 `127.0.0.1`，所以 new-api 跑在
> **Windows 原生**时用 `127.0.0.1:44000` 即可。

## 5. 容量与调优

- 单机 netns 隧道经验值 **20–50 条**（每条 = 1 tun + 1 veth + 1 microsocks + 1 openvpn）。
- 本项目上游实测只有 2 个 host 数据面可用（每个 host 两条 tcp/udp），端口数少 →
  `TRYINGOPEN_USE_COOLDOWN_MAP` 的 429 冷却会很快把整池打进冷却，建议：
  - `TRYINGOPEN_PROXY_MAX_USE_PER_DAY` 设小（如 2000）
  - 或者只把这条隧道当**补充出口**，不要当主力池
- 上游节点存活率低且会轮换，需要**定期重跑 harvest + scan**，并用双阈值摘除
  （连续 2 轮失败才剔除，单轮抖动常见）。

## 6. 三层验证（缺一层就不算打通）

| 层 | 命令 | 期望 |
|---|---|---|
| 隧道层 | `ip netns exec vpn0 curl -s https://api.ipify.org` | 返回节点 IP |
| 池层 | `curl -x socks5h://127.0.0.1:44000 https://api.ipify.org` | 同上 |
| 业务层 | new-api 发真实请求，并核对上游侧看到的来源 IP | 与节点 IP 一致 |

只看 `/api/twoapi/proxy_pool` 里有条目 **不等于** 流量真的走了隧道。

## 7. 合规

节点是上游商业 VPN 的自有服务器，凭证由上游签发。生产大规模使用等于盗用基础设施，
且随时会被封。请把本池限制在**研究与自有链路验证**范围内；真正的长期稳定池请用
自有 VPS（WireGuard/Hysteria2 → SOCKS5）或正规住宅代理供应商。
