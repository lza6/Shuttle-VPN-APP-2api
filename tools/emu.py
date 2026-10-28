"""Unicorn emulation of libpowervpn.so's obfuscated constant builders.

The library is full of ~9.8KB functions that do junk arithmetic and then write a
hard-coded string byte-by-byte through a jump table (that's how "20190826" is built).
Instead of reading them by hand, run them: map the ELF, resolve the PLT stubs we
care about, stub the external ones, and read whatever string the function returns.

  python3 emu.py 0x13f5c 0x17048 0x11b20c ...
"""
import os
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X8, UC_ARM64_REG_LR, UC_ARM64_REG_PC)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

P = os.environ.get("LIBPOWERVPN", "libpowervpn.so")
DATA = open(P, "rb").read()

STACK = 0x70000000
STACK_SIZE = 2 * 1024 * 1024
HEAP = 0x71000000
HEAP_SIZE = 8 * 1024 * 1024
TLS = 0x7F000000
RET_MAGIC = 0x7FF00000


def load():
    f = open(P, 'rb')
    e = ELFFile(f)
    segs = []
    for s in e.iter_sections():
        if s['sh_flags'] & 0x2 and s['sh_size']:          # SHF_ALLOC
            segs.append((s['sh_addr'], s['sh_size'], s['sh_offset'], s['sh_type']))
    f.seek(0)
    dynsym = e.get_section_by_name('.dynsym')
    rel = e.get_section_by_name('.rela.plt')
    got2sym = {}
    for i in range(rel.num_relocations()):
        r = rel.get_relocation(i)
        got2sym[r['r_offset']] = dynsym.get_symbol(r['r_info_sym']).name
    defined = {}
    for sym in dynsym.iter_symbols():
        if sym.name and sym['st_value']:
            defined[sym.name] = sym['st_value']
    plt = e.get_section_by_name('.plt')
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(DATA[plt['sh_offset']:plt['sh_offset'] + plt['sh_size']], plt['sh_addr']))
    stub_map = {}
    i = 0
    while i + 3 < len(insns):
        a, b, c, d = insns[i:i + 4]
        if a.mnemonic == 'adrp' and b.mnemonic == 'ldr' and c.mnemonic == 'add' and d.mnemonic == 'br':
            try:
                page = int(a.op_str.split(', ')[1].lstrip('#'), 0)
                off = int(b.op_str.split('#')[1].rstrip(']'), 0)
                stub_map[a.address] = got2sym.get(page + off, '?')
            except Exception:
                pass
            i += 4
        else:
            i += 1
    return segs, stub_map, defined


SEGS, STUB, DEFINED = load()


PKG = b"com.supervpn.vpn.free.proxy" + bytes([0])
MAGIC = 0x3F051FCC
SRET = 0x72000000          # libc++ std::string out-param area


def emulate(func, x0=0, w1=0, want_len=32, max_insn=20_000_000, sret=False):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # map allocatable sections page-aligned
    pages = set()
    for addr, size, off, typ in SEGS:
        start = addr & ~0xFFF
        end = (addr + size + 0xFFF) & ~0xFFF
        for p in range(start, end, 0x1000):
            if p in pages:
                continue
            pages.add(p)
            try:
                uc.mem_map(p, 0x1000)
            except Exception:
                pass
    for addr, size, off, typ in SEGS:
        if typ == 'SHT_NOBITS':
            continue
        chunk = DATA[off:off + size]
        uc.mem_write(addr, chunk)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(TLS, 0x1000)
    uc.mem_map(RET_MAGIC, 0x1000)

    heap_ptr = [HEAP]

    def heap_alloc(n):
        n = max(n, 16)
        p = heap_ptr[0]
        heap_ptr[0] = (p + n + 15) & ~15
        return p

    if sret:
        uc.mem_map(SRET, 0x1000)
        uc.mem_write(SRET, bytes(64))
        uc.reg_write(UC_ARM64_REG_X8, SRET)
        uc.mem_write(HEAP, PKG)
        x0 = HEAP
        w1 = MAGIC
    uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x1000)
    try:
        uc.reg_write(UC_ARM64_REG_X8, 0)
    except Exception:
        pass
    uc.reg_write(UC_ARM64_REG_X0, x0)
    uc.reg_write(UC_ARM64_REG_X1, w1)
    uc.reg_write(UC_ARM64_REG_X2, 0)
    uc.reg_write(UC_ARM64_REG_LR, RET_MAGIC)
    uc.reg_write(UC_ARM64_REG_PC, func)
    uc.mem_write(TLS + 0x28, b'\x11' * 8)

    calls = []

    def on_code(uc_, address, size, _):
        if address == RET_MAGIC:
            uc_.emu_stop()
            return
        sym = STUB.get(address)
        if sym is None:
            return
        if sym in DEFINED and DEFINED[sym] and sym != '?':
            # internal implementation: jump straight there
            uc_.reg_write(UC_ARM64_REG_PC, DEFINED[sym])
            return
        # external: fake it
        a0 = uc_.reg_read(UC_ARM64_REG_X0)
        a1 = uc_.reg_read(UC_ARM64_REG_X1)
        a2 = uc_.reg_read(UC_ARM64_REG_X2)
        calls.append((sym, a0, a1))
        ret = 0
        if 'malloc' in sym or 'Znwm' in sym or 'calloc' in sym:
            ret = heap_alloc(a0 if a0 < 1 << 20 else 64)
        elif 'memcpy' in sym or 'memmove' in sym:
            try:
                uc_.mem_write(a0, bytes(uc_.mem_read(a1, max(a2, 0) or 0)))
            except Exception:
                pass
            ret = a0
        elif 'strlen' in sym:
            try:
                s = uc_.mem_read(a1, 256).split(b'\x00')[0]
                ret = len(s)
            except Exception:
                ret = 0
        uc_.reg_write(UC_ARM64_REG_X0, ret)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, on_code)
    err = None
    try:
        uc.emu_start(func, RET_MAGIC, count=max_insn)
    except Exception as e:
        err = e
    x0v = uc.reg_read(UC_ARM64_REG_X0)
    out = None
    try:
        raw = bytes(uc.mem_read(x0v, want_len))
        out = raw.split(b'\x00')[0]
    except Exception:
        pass
    return {"ret": x0v, "bytes": out, "err": str(err) if err else None,
            "calls": calls[:12], "heap_used": heap_ptr[0] - HEAP}


if __name__ == "__main__":
    sret = '--sret' in sys.argv
    for a in [x for x in sys.argv[1:] if not x.startswith('--')]:
        addr = int(a, 0)
        r = emulate(addr, sret=sret)
        print(hex(addr), '->', r['bytes'], '| ret', hex(r['ret']), '| err', r['err'])
        print('    calls:', [c[0] for c in r['calls']])
