# 协议手册 — Shuttle VPN (PowerVPN SDK) → OpenVPN 节点目录

给二次开发 / 对接方看的实现手册。所有结论来自实测（见 `REVERSE_REPORT.md` 的验证日志）。

---

## 1. 身份

| 项 | 值 |
|---|---|
| 包名 | `com.shuttlevpn.free.proxy.gaming` |
| 版本 | 2.3.246（Play 版标称 **Super VPN**，商店链接指向同包名） |
| SDK | PowerVPN（`libpowervpn.so`，日志 tag `PowerVPN`，Java 侧 `com.free.vpn.openvpn.OpenVpnManager`） |
| VPN 内核 | ics-openvpn fork（`libopenvpn.so`）+ shadowsocks-rust（`libsslocal.so`，本版本未走 SS 通道）+ strongswan（IKEv2，本版本未走） |
| 实际生效协议 | **OpenVPN**（用户名/密码 + tls-crypt，服务器不下发客户端证书） |

## 2. 网关发现

App 内置 6 个基址，随机挑一个；线上目录还会下发 `next_api_list`：

```
https://api.supershell.me
https://api.fastcloud.me
https://api.pm-img.com
https://api.itranslator.info
http://193.108.117.109
http://193.108.118.25
```

目录里的 `next_api_list`（2026-10 实测）：`api.fastcloud.me` / `api.pm-img.com` /
`api.itranslator.info` / `193.108.117.246` / `193.108.118.23` / `rufjskls.shop`。

## 3. 请求

```
GET {base}/superwg.php?v=<urlencode(cipher)>
User-Agent: Mozilla/5.0 (Linux; Android 10) ... Chrome/106.0.5249.126 Mobile Safari/537.36
Content-Type: application/x-www-form-urlencoded
```

`cipher` = `base64_no_pad( DES_CBC_PKCS5( "m=init" + query ) )`。

`query` 明文（照抄 `VPNSpeedAPI.getQueryString()`）：

| 字段 | 示例 | 说明 |
|---|---|---|
| `lang` | `en` | 固定 |
| `region` | `US` | 系统 locale 国家 |
| `ver` | `234` | 客户端版本号，服务端只做弱校验 |
| `pk` | `com.supervpn.vpn.free.proxy` | **不是**真实包名，是 SDK 冒充的包名 |
| `uuid` | 32 位 hex | 每次随机，无状态 |
| `country` | `US` | `Locale.getDefault()` |
| `sdk` | `30` | `Build.VERSION.SDK_INT` |
| `isp` | `vodafone` | 硬编码 |
| `operator` | SIM 运营商名，无则 `NULL` | |
| `network_type` | `2G/3G/4G/5G` 随机 | 硬编码列表随机 |
| `firstInstallTime` | 毫秒时间戳 | `PackageManager` 取，可伪造 |

字符串以 `&` 开头（`&lang=en&region=...`），服务端容忍。

## 4. 加密

全部在 `libpowervpn.so` 里通过 JNI 反向调用 JVM 实现（`.rodata` 里的字符串序列
`getPackageManager → signatures → hashCode → getBytes → SecretKeyFactory(DES) →
DESKeySpec → IvParameterSpec → Cipher(DES/CBC/PKCS5Padding) → doFinal →
Base64.encodeToString` 即完整调用链）：

1. **完整性闸门**：`packageManager.getPackageInfo(getPackageName(), 0x40).signatures[0].hashCode()`
   必须等于 `1057427404 (0x3f051fcc)`，否则 native 直接返回 null。
   → 所以 mod 版 APK 必须带签名伪装：`defpackage.i6`（jadx 名 `C0125i6`）把
   `getPackageName()` 改成 `com.supervpn.vpn.free.proxy`，`defpackage.j6`（`C0133j6`）
   把 `signatures` 换成硬编码 DER（`3082037f...26`，SuperVPN 官方签名证书）。
2. **密钥/IV**：由 `(包名字符串, 1057427404)` 经三个 native 派生函数生成 8 字节 key 与
   8 字节 IV（key/IV 随包名变化，与本机其他状态无关 → 换设备/换时间都不变）。
3. **算法**：`DES/CBC/PKCS5Padding`，密文 `android.util.Base64` 无换行、无 padding。
4. **明文前缀**：加密方向（`OpenVpnManager.d`）会在明文前加 `m=init`（模式标记），
   解密方向（`.f`/`.b`）原样返回，不做裁剪。

### 4.1 三条取值路径（按可用性排序）

| 路径 | 是否需要设备 | 说明 |
|---|---|---|
| **Java 层 oracle**（本仓库采用） | 需要 root 设备/模拟器 + frida-server 16.x | 直接调 `OpenVpnManager.b/f/d`，见 `tools/rpc_bridge.js`；实测稳定 |
| 纯静态还原 key/IV | 不需要 | 需要逆向 `0x10210 / 0xffa0 / 0xff30` 三个派生函数（key 不是 `.rodata` 里的字面串，是变换结果）；**未完成** |
| 抓包 | 需要中间人 | 只能拿到「已加密的 query」与「已加密的响应」，仍要 oracle 解 |

## 5. 响应

- 成功：`base64_no_pad(DES_CBC_PKCS5(JSON))` —— 122 520 字节密文 → 91 880 字节 JSON。
- 失败：明文 JSON（`{"code":..}` 之类），解析前先判首字符是否为 `{`。
- `?v=` 参数错误时返回 4xx；**基址根路径**返回一个 `VPN Free Super` 静态面板页（200），
  别把根页 200 当成「服务可用」。

## 6. 目录结构（解出的 JSON）

顶层字段：`ping_timeout, ads_config, tcp, udp, nut_port, auto, protocol, protocol2,
servers, vip_servers, stream_servers, min_version, set_location, ping, max_clicks,
connected_ads, dns, git, fake_host, track_rule, ads_rules, tg, fastest_location,
next_api, next_api_list, subs_sytle, tunnel_split, retry, check_network, check_url,
mux_enabled, mux_concurrency`。

关键：

| 字段 | 含义 | 实测值 |
|---|---|---|
| `tcp` / `udp` | OpenVPN 端口候选 | `[8080]` / `[800]` |
| `nut_port` / `nat_port` / `proxy_port` | 其他通道（NUT 协议 / NAT 端口 / 443 代理）用，OpenVPN 不用 | `80` / 随机 / `443` |
| `servers` / `vip_servers` / `stream_servers` | 免费 / VIP / 流媒体池 | 内嵌目录 48 / 42 / 19；线上目录 18 / 3 / 0 |

单个节点对象：

```json
{"server_id":3020,"country":"US","country_name":"US-NewYork3","alisa_name":"NewYork#234",
 "host":"5.161.55.124","load":29,"srate":0,"seeds":"5.161.55.124",
 "nat_port":"26995","nut_port":"80","proxy_port":"443",
 "enpass":"<base64 DES 密文>","ca":"-----BEGIN CERTIFICATE-----...","inip_pool":"","info":""}
```

**`enpass` 解密后就是 OpenVPN 密码**（32 位 hex 串），用户名固定 `superike`。

## 7. 连接

App 不拼 `remote` 行，而是拿 `assets/privacy_policy.txt`（DES 密文，2 304 B）解出的
**OpenVPN 模板**，再用 `VPNSpeedServer.m4969b()` 注入 remote：

```
client
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns
verb 3
auth-user-pass
<ca>...ECDSA ca cert, 10 年有效期...</ca>
<tls-crypt>...2048bit static key...</tls-crypt>
```

- 用户名：`superike`
- 密码：`OpenVpnManager.b(ctx, srv.enpass)`
- remote：`<host> 800 udp`（首选）与 `<host> 8080 tcp`（备选）
- 服务端会 push：`route-gateway / topology subnet / ping 20 / ping-restart 120 /
  cipher AES-128-GCM / redirect-gateway def1 bypass-dhcp`
- 目录里的 `ca` 字段与模板里的 `<ca>` 不同源，实测模板 ca 即可（服务端只校验 tls-crypt + 账号）

## 8. 最小实现（Python，走 Frida oracle）

```python
import frida, urllib.request, urllib.parse, json, ssl

pid = <adb shell pidof com.shuttlevpn.free.proxy.gaming>
dev = frida.get_device_manager().add_remote_device("127.0.0.1:27050")
s = dev.attach(pid)
sc = s.create_script(open("tools/rpc_bridge.js").read()); sc.load()
ex = sc.exports_sync; ex.init()

enc = ex.enc("&lang=en&region=US&ver=234&pk=com.supervpn.vpn.free.proxy&uuid=" + uuid +
            "&country=US&sdk=30&isp=vodafone&operator=vodafone&network_type=5G&firstInstallTime=1700000000000")
url = "https://api.fastcloud.me/superwg.php?v=" + urllib.parse.quote(enc, safe="")
body = <GET url>                                  # 122KB base64 密文
cfg  = json.loads(ex.dec(body))                   # 明文目录
for srv in cfg["servers"]:
    pw = ex.decb(srv["enpass"])                   # 每节点密码
```

完整脚本：`tools/harvest.py`。

## 9. 必避坑

1. **frida 17 起内置 Java bridge 被移除** → `Java is not defined`。必须用 frida-server **16.x**
   + `pip install frida==16.5.9`，两端版本要一致，否则 `ProtocolError: unable to communicate`。
2. **x86_64 模拟器 + arm64-only .so**：`sdk_gphone_x86_64_arm64` 走 ARM 翻译加载
   `libpowervpn.so`，`Module.findModuleByName/findExportByName` 全部返回 null，
   `Interceptor` 挂不上（执行的是翻译后的宿主代码）。**只能走 Java 层调用**。
3. **`adb kill-server` 会丢 root**：之后 `adb shell id` 变成 `uid=2000(shell)`，
   frida attach 报 `PermissionDenied`；重跑 `adb root` 再启 frida-server。
4. **`pkill -f pool_layer.py` 会杀掉自己的 shell**（命令行里含同样字符串）→ 用
   `pkill -f 'pool_layer\.py'` 或按 pid 文件杀。
5. **Linux 上 `block-outside-dns` 不识别**：Windows 专用选项，生成配置时删掉。
6. **`ip-api.com` 45 次/分钟限流**：批量探活会被判 `status:fail`，导出 IP 探测改用
   `https://api.ipify.org`。
7. **WSL 里 veth 转发默认被 DROP**（docker 把 FORWARD 策略改 DROP）：
   必须加 `iptables -I FORWARD -s/-d 10.200.0.0/16 -j ACCEPT` + `POSTROUTING MASQUERADE`。
8. **`--route-nopull` + 手工默认路由实测拿不到数据通道**（握手成功、tun RX=0）；
   让服务端 push 路由（`0.0.0.0/1` + `128.0.0.0/1`）反而正常，泄漏防护改为在 netns 内
   `iptables -A OUTPUT -o vethXp ! -d <server>/32 -j DROP`。
9. **`GET /` 200 不代表服务活着**：6 个基址里 4 个根路径返回同一个 10 111 字节的
   `VPN Free Super` 面板页（占位/停放页），真正有效的是 `/superwg.php`。
10. **节点很多但握不上手**：全量 220 个「host×transport」里只有 10 个能完成 TLS 握手
    （4.5%），且同一 host 的 udp/tcp 与不同地区的可用性完全独立。
