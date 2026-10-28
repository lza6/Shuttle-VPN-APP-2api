# 逆向报告 — Shuttle VPN 2.3.246 (com.shuttlevpn.free.proxy.gaming)

结论先行：这是一个 **PowerVPN SDK 白标**外壳，节点目录由自有 HTTP API 下发（DES 信封），
连接方式为 **OpenVPN（用户名 `superike` + 每节点独立密码 + tls-crypt）**。
目录 130 条节点 / 110 个唯一 host，全量测活后 6 个 host 真正可握手，其中 2 个 host
数据通道可用、2 个 host 握手成功但数据面不通。

---

## 1. 静态侦察

| 步骤 | 命令/工具 | 结果 |
|---|---|---|
| 解包 | `unzip` | 9 个 dex、`lib/arm64-v8a` 15 个 .so |
| dex 字符串表直读 | Python `struct` 解析 string_ids | 171 154 条字符串、131 个 URL |
| 架构判定 | 关键字扫描 | **无 Firebase RTDB**（`rtdb`/`firebaseio` 0 命中）→ 自有 HTTP API |
| 原生库指纹 | strings + PLT 符号表 | `libpowervpn.so`（PowerVPN SDK）、`libopenvpn.so`（ics-openvpn）、`libsslocal.so`（shadowsocks-rust，未启用）、`libstrongswan.so`（IKEv2，未启用） |
| 反编译 | jadx（`--no-res`，17 804 个 java） | 定位 `VPNSpeedAPI` / `VPNSpeedServer` / `OpenVpnManager` |

关键类：

```
com/android/shuttlevpn/free/proxy/gaming/vpnspeed/VPNSpeedAPI.java     # 网关池 + 端点 + 查询串
com/android/shuttlevpn/free/proxy/gaming/vpnspeed/VPNSpeedServer.java  # 节点对象 -> OpenVPN profile
com/free/vpn/openvpn/OpenVpnManager.java                               # 5 个 native 方法 b/c/d/e/f
defpackage/i6.java  (C0125i6)                                          # Context 伪装：包名 = com.supervpn.vpn.free.proxy
defpackage/j6.java  (C0133j6)                                          # PackageManager 伪装：signatures = 硬编码官方 DER
```

`C0133j6` 里那个 2 138 字符的 hex 常量就是官方签名证书 DER —— 说明 **APK 的签名不再参与
密钥派生**，只看这个字符串。

## 2. 加密链路还原

`.rodata` 里的字符串序列把调用链完整暴露出来：

```
getPackageManager → getPackageInfo(name, 0x40) → signatures → [0] → hashCode()  → I
java/lang/String.getBytes("UTF-8") → byte[]  (key 字节)
SecretKeyFactory.getInstance("DES")
DESKeySpec(<init>([B)V) + IvParameterSpec(<init>([B)V)
SecretKeyFactory.generateSecret(KeySpec) → SecretKey
Cipher.getInstance("DES/CBC/PKCS5Padding").init(int mode, Key, AlgorithmParameterSpec)
doFinal([B) → byte[]
android/util/Base64.encodeToString([B,int)
```

三个派生子函数（`sub_10010 / sub_ffa0 / sub_ff30`）签名均为 `(char* pkgName, int magic, std::string* out)`，
`magic = 0x3f051fcc = 1057427404`：

- 第一个输出 → 送进 `String.getBytes("UTF-8")` → **DES key**
- 第二个输出 → **IvParameterSpec**
- 第三个输出 → 另一用途（`b/c/d/e/f` 五个入口的模式/标记）

`magic` 同时是 **签名完整性闸门**：`signatures[0].hashCode()` 必须等于 1057427404，
否则 native 直接返回 null。这就是 mod 版必须带 `ApkSignatureKillerEx` + 包名/签名伪装的原因。

**尚未完成的部分**：三个派生函数的字符串变换算法（key 不是 `.rodata` 里的字面串，
是变换结果）。本仓库因此走「设备内 Java 层 oracle」路线（`tools/harvest.py`）。
纯静态 key 提取留作后续工作 —— 难点在于三个函数是 PLT 间接调用 +
`.rodata` 里是一堆错位 ASCII（如 `,4$8'9-6:.6$1#?*XhHpSeA~NrZlE`），需要单独做一次反混淆。

## 3. 动态验证（Frida）

环境：Android 11 (`sdk_gphone_x86_64_arm64`) + frida-server 16.5.9 + `frida==16.5.9`。

踩的坑按发生顺序：

1. **frida 17 内置 Java bridge 被移除** → `ReferenceError: 'Java' is not defined`。
   `pip install frida==16.5.9` + 用 16.x 的 frida-server 解决。
2. **`frida.spawn()` 在远程 device 上直接 `TransportError: connection closed`** →
   改成 `monkey` 拉起 + `dev.attach(pid)`。
3. **`adb kill-server` 后 root 丢失** → `frida.PermissionDeniedError`；必须重跑 `adb root`。
4. **ARM 翻译让 native hook 失效**：`Process.enumerateModulesSync()` 里没有
   `libpowervpn.so`（只有 `libndk_translation_proxy_libc.so`），`/proc/self/maps` 里
   却有映射。`Module.findBaseAddress/findExportByName` 全 null，`Interceptor` 挂不上。
   → 放弃 native hook，改走 Java 层 oracle。
5. 模拟器偶发 `device offline`（内存压力），`adb reconnect offline` 可恢复。

### 3.1 用 oracle 解出的东西

| 产物 | 大小 | 说明 |
|---|---|---|
| `usage_policy.txt` 明文 | 165 047 B | 内置目录（48 servers + 42 vip + 19 stream） |
| `cache/lic.txt` 明文 | 91 880 B | 线上目录（18 + 3 + 0） |
| `privacy_policy.txt` 明文 | 1 724 B | OpenVPN 模板（ca + tls-crypt，无客户端证书） |
| `enpass` 解密 | 32 字符 hex × 110 | 每节点 OpenVPN 密码 |

线上目录实测：`GET https://api.fastcloud.me/superwg.php?v=<加密串>` 返回 122 520 B
base64 密文，与缓存的 `lic.txt` 逐字节一致 → **服务端不按 uuid/地区下发不同目录**，
一次拿到的就是全量。

## 4. 测活

两轮，全部在 WSL（Ubuntu 22.04，openvpn 2.6.19），`--dev null --ifconfig-noexec --route-noexec`
（只验 TLS 控制信道 + 账号，不建 tun）：

| 轮次 | 并发 | 超时 | 结果 |
|---|---|---|---|
| 第一轮 | 10 | connect 5s / poll 12s | 220 配置 → **10 UP / 9 REFUSED / 1 TLSERR / 200 DEAD** |
| 第二轮 | 14 | connect 8s / poll 25s | 见 `pool/scan2_result.txt` |

第一轮 10 个 UP = 6 个唯一 host：

```
142.202.48.20  tcp+udp   US NewYork#1   GTHost
149.7.16.252   tcp       GB London#7
152.67.194.13  tcp+udp   KR Korea#1
162.251.62.100 tcp+udp   US Miami#1     GTHost
169.197.143.32 tcp       US Seattle#2
193.123.87.23  tcp+udp   AE Dubai#1
```

真实隧道（netns + tun + 出口 IP 校验）结果：**142.202.48.20 / 162.251.62.100 数据面正常**
（出口 IP = 节点 IP，GTHost），`152.67.194.13` / `193.123.87.23` 握手成功但 tun RX=0
（服务端不放行数据面，疑似按地区/账号风控）。

> 重要：**握手成功 ≠ 可用**。只看 `Initialization Sequence Completed` 会把 4 个死节点算成
> 活的，必须做出口 IP 校验（本项目用 `https://api.ipify.org`，直连 IP 与出口 IP 必须不同）。

## 5. 合规判定

| 项 | 结论 |
|---|---|
| 节点归属 | 商业 VPN 自有服务器（GTHost 等 hosting IP，非住宅），凭证是**上游签发给该 App 的账号** |
| 凭证性质 | 逆向可得 ≠ 有权使用；上游 ToS 禁止非官方客户端接入 |
| 入生产池建议 | **不建议**长期/大规模入生产代理池；做研究、自有链路验证、低并发测试可以 |
| 风险 | 上游随时可按 IP/账号封禁；节点存活率低（4.5%）且会轮换 |

真实跑量的长期稳定池应当用自有 VPS / 明确授权的住宅供应商。本仓库的价值在于
**协议知识 + 一套可复用的「APK → 节点 → SOCKS5 池」流水线**，不是在囤别人的免费节点。

## 6. 复现命令

```bash
# 0) 环境：root 模拟器 + app 已安装 + frida-server 16.x
adb root && adb shell "setsid /data/local/tmp/fs1659 -l 0.0.0.0:27050 &" && adb forward tcp:27050 tcp:27050

# 1) 抓目录 + 凭证 + 生成配置
python3 tools/harvest.py --assets <apk解包>/assets --out output

# 2) 全量测活（只验握手）
bash tools/scan.sh            # 见 pool/scan.sh

# 3) 起 SOCKS5 池（每节点一个 netns + microsocks + fail-closed）
python3 tools/pool_layer.py up output/nodes_alive.json --max 10

# 4) 压测
python3 tools/bench.py --ports 44000-44009 --conc 4 --rounds 3

# 5) 面板
python3 demo/server.py 8920
```
