"""PowerVPN SDK crypto — fully static, no device required.

Every constant below was recovered by emulating the obfuscated builders inside
`libpowervpn.so` with Unicorn (see `tools/emu.py`). The builders do junk arithmetic
and then write the string byte-by-byte through a jump table, so they look
impenetrable in a disassembler but run fine:

    builder            returns              used for
    ----------------   ------------------   --------------------------------------
    0x11b20c           "20190826"           DES key   (query envelope + config + node ca)
    0x11d874           "00514321"           DES IV
    0x11fec0           "m=init"             plaintext prefix for /superwg.php requests
    0x1224f0           "m=ads"              plaintext prefix for ad/analytics configs
    0x118038           "vpntunnelsuper20"   secondary 16-byte secret (unused by OpenVPN path)
    0x13f5c            "2019082620190826"   AES-128 key  (per-node `enpass`)
    0x17048            "0051432100514321"   AES-CBC IV

Layouts
  * DES/CBC/PKCS5Padding  , base64 NO_WRAP + no padding   -> request `v=`, response body,
    `assets/usage_policy.txt`, `assets/privacy_policy.txt`
  * AES-128/CBC/PKCS7     , base64 NO_WRAP + no padding   -> `enpass` (per-node password)

The `m=init` marker is *added by the encrypt direction*; decrypt returns it verbatim,
so callers must strip it themselves.
"""
import base64

from Crypto.Cipher import AES, DES

DES_KEY = b"20190826"
DES_IV = b"00514321"
AES_KEY = b"2019082620190826"
AES_IV = b"0051432100514321"

PREFIX_INIT = "m=init"
PREFIX_ADS = "m=ads"


def _pad8(b: bytes) -> bytes:
    n = 8 - len(b) % 8
    return b + bytes([n]) * n


def _pad16(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def _unpad(b: bytes) -> bytes:
    if not b:
        return b
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    s = "".join(s.split())
    return base64.b64decode(s + "=" * (-len(s) % 4))


# ---- DES layer: requests, responses, bundled asset configs -------------------
def des_encrypt(plain: str, prefix: str = PREFIX_INIT) -> str:
    raw = _pad8((prefix + plain).encode("utf-8"))
    return _b64e(DES.new(DES_KEY, DES.MODE_CBC, DES_IV).encrypt(raw))


def des_decrypt(cipher: str, strip_prefix: bool = False) -> str:
    pt = _unpad(DES.new(DES_KEY, DES.MODE_CBC, DES_IV).decrypt(_b64d(cipher)))
    out = pt.decode("utf-8", "replace")
    if strip_prefix and out.startswith(PREFIX_INIT):
        out = out[len(PREFIX_INIT):]
    return out


# ---- AES layer: per-node `enpass` ------------------------------------------
def aes_decrypt(cipher: str) -> str:
    return _unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(_b64d(cipher))).decode("utf-8", "replace")


def aes_encrypt(plain: str) -> str:
    return _b64e(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(_pad16(plain.encode())))


if __name__ == "__main__":
    # self-check against pairs captured from the running app
    assert des_decrypt("LQooP6VdIUtqvwKrC6mgZQ==") == "m=initABCDEFGH"
    assert des_encrypt("ABCDEFGH") == "LQooP6VdIUtqvwKrC6mgZQ"
    assert aes_decrypt("BYo6Vw+PaJ54U77V3bRWwB5ZCa803Wwv5s+/POcNp0bdf6TH08tM3VSHywV7tLm2") == \
           "ee4f1f768776304ffe6b4632d3958789"
    assert aes_decrypt(aes_encrypt("deadbeefdeadbeefdeadbeefdeadbeef")) == "deadbeefdeadbeefdeadbeefdeadbeef"
    print("powercrypto self-check ok (DES + AES, both directions)")
