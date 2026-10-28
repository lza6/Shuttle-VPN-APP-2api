# tools

| 文件 | 作用 | 需要什么 |
|---|---|---|
| `powercrypto.py` | DES + AES 离线编解码（协议核心） | `pycryptodome` |
| `harvest.py` | 抓目录 + 解凭证 + 生成每节点 `.ovpn` | 网络；`--device` 才需要设备 |
| `scan.sh` | OpenVPN 握手测活（并行，不建 tun） | `openvpn` |
| `pool_layer.py` | 每节点一个 netns + microsocks + fail-closed 的 SOCKS5 池 | Linux/WSL root、`microsocks`、`iptables` |
| `bench.py` | SOCKS5 压测（延迟/成功率/吞吐/出口 IP） | 纯 Python |
| `gen_newapi_pool.py` | 生成 new-api 的 `TRYINGOPEN_PROXY_FILE` | 纯 Python |
| `emu.py` | Unicorn 模拟 `libpowervpn.so` 的混淆 builder，提取 key/IV 常量 | `capstone` `pyelftools` `unicorn` |
| `rpc_bridge.js` | Frida RPC 兜底（App 换加密层时用） | root 设备 + frida-server 16.x |

## 重推常量（上游改加密层时）

```bash
# 1) 重新找到 builder（.rodata 里那串 getPackageManager→signatures→hashCode→Cipher 的调用链附近）
#    以及 AES 侧：搜 `bl` 到 AES::MakeKey stub 的调用点（本案 0xd0e80）
# 2) 直接模拟执行
LIBPOWERVPN=libpowervpn.so python3 emu.py --sret 0x11b20c 0x11d874 0x11fec0 0x1224f0 0x118038 0x13f5c 0x17048
# 3) 结果填进 powercrypto.py 的 4 个常量，跑自校验
python3 powercrypto.py
```
