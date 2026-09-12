#!/usr/bin/env python3
"""Patch the currency getters in libcocos2dcpp.so (armeabi-v7a + x86).

Gold / Cocoa Beans / Ticket are inventory items 1001 / 1002 / 1003, read through
Model::Dynamic::Player::getGold()/getCocoaBeans()/getTicket(). We replace each
getter with "return 99,999,999", size-preserving, so neighbouring functions and
all relocations stay intact.

Usage: python3 tools/patch_so.py <exploded-apk-dir>
"""
import os
import struct
import sys

VALUE = 99_999_999

# ---------------------------------------------------------------- ARM (Thumb)
def thumb_movw(rd, imm16):
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 1
    imm3 = (imm16 >> 8) & 7
    imm8 = imm16 & 0xFF
    return struct.pack('<HH', 0xF240 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)


def thumb_movt(rd, imm16):
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 1
    imm3 = (imm16 >> 8) & 7
    imm8 = imm16 & 0xFF
    return struct.pack('<HH', 0xF2C0 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)


def arm_patch(value):
    """movw r0,#lo ; [movt r0,#hi] ; bx lr ; nop..."""
    code = thumb_movw(0, value & 0xFFFF)
    if value >> 16:
        code += thumb_movt(0, (value >> 16) & 0xFFFF)
    return code + b'\x70\x47'


ARM_NOP = b'\x00\xbf'
ARM_TARGETS = [  # (symbol, file offset == vaddr, declared size)
    ("Model::Dynamic::Player::getGold()",       0x1e8a76, 20),
    ("Model::Dynamic::Player::getCocoaBeans()", 0x1e8aa2, 20),
    ("Model::Dynamic::Player::getTicket()",     0x1e8ad2, 20),
]

# ---------------------------------------------------------------------- x86
def x86_patch(value):
    """mov eax, imm32 ; ret ; nop..."""
    return b'\xb8' + struct.pack('<I', value) + b'\xc3'


X86_NOP = b'\x90'
X86_TARGETS = [
    ("Model::Dynamic::Player::getGold()",       0x2212c0, 58),
    ("Model::Dynamic::Player::getCocoaBeans()", 0x221350, 58),
    ("Model::Dynamic::Player::getTicket()",     0x2213f0, 58),
]


def apply(path, targets, code, nop):
    data = bytearray(open(path, 'rb').read())
    original = bytes(data)
    for name, off, size in targets:
        new = code + nop * ((size - len(code)) // len(nop))
        assert len(new) == size, (name, len(new), size)
        data[off:off + size] = new
        print("  patched %-38s @0x%08x (%dB)" % (name, off, size))
    open(path, 'wb').write(bytes(data))
    diffs = [i for i in range(len(original)) if original[i] != data[i]]
    allowed = set()
    for _, off, size in targets:
        allowed.update(range(off, off + size))
    assert set(diffs) <= allowed, "patch escaped its intended region!"
    print("  -> %d bytes changed, all inside intended regions" % len(diffs))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    for arch, targets, code, nop in [
        ("armeabi-v7a", ARM_TARGETS, arm_patch(VALUE), ARM_NOP),
        ("x86",         X86_TARGETS, x86_patch(VALUE), X86_NOP),
    ]:
        path = os.path.join(root, "lib", arch, "libcocos2dcpp.so")
        print("=== %s ===" % path)
        apply(path, targets, code, nop)
    print("\nDone. Currency getters now return %d." % VALUE)


if __name__ == "__main__":
    main()
