#!/usr/bin/env python3
"""Verify the signed, modded APK end to end.

Checks: ZIP CRCs, entry alignment, MANIFEST.MF / CERT.SF regeneration, PKCS#7
signature, and that the currency patches are present in both shipped .so files.

Usage: python3 tools/verify.py <signed.apk> <original-source-archive> [cert.pem]
"""
import base64
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_v1 import wrap, b64  # noqa: E402

ARM = [("getGold", 0x1e8a76), ("getCocoaBeans", 0x1e8aa2), ("getTicket", 0x1e8ad2)]
X86 = [("getGold", 0x2212c0), ("getCocoaBeans", 0x221350), ("getTicket", 0x2213f0)]
ARM_CODE = b'\x4e\xf2\xff\x00\xc0\xf2\xf5\x50\x70\x47'   # movw/movt r0,#99999999; bx lr
X86_CODE = b'\xb8\xff\xe0\xf5\x05\xc3'                    # mov eax,99999999; ret

ok, fail = [], []


def check(label, cond, extra=""):
    (ok if cond else fail).append(label)
    print("%s %-52s %s" % ("PASS" if cond else "FAIL", label, extra))


def main():
    apk, src = sys.argv[1], sys.argv[2]
    cert = sys.argv[3] if len(sys.argv) > 3 else None

    z = zipfile.ZipFile(apk)
    names = z.namelist()

    # --- zip integrity ---
    check("all entry CRCs", z.testzip() is None, "%d entries" % len(names))

    stale = [n for n in names if n.startswith('META-INF/') and n not in
             ('META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA')]
    check("no stale META-INF signature files", not stale, str(stale))

    # --- alignment of uncompressed entries ---
    bad = []
    f = open(apk, 'rb')
    for i in z.infolist():
        if i.compress_type == zipfile.ZIP_STORED:
            f.seek(i.header_offset)
            nl, el = struct.unpack('<HH', f.read(30)[26:30])
            if (i.header_offset + 30 + nl + el) % 4:
                bad.append(i.filename)
    check("stored entries 4-byte aligned", not bad, str(bad[:3]))
    arsc = [i for i in z.infolist() if i.filename == 'resources.arsc']
    check("resources.arsc uncompressed", arsc and arsc[0].compress_type == 0)

    # --- MANIFEST.MF regeneration ---
    MAN = z.read('META-INF/MANIFEST.MF')
    SF = z.read('META-INF/CERT.SF')
    RSA = z.read('META-INF/CERT.RSA')
    payload = [n for n in names if not n.startswith('META-INF/')]

    man = wrap("Manifest-Version", "1.0") + wrap("Created-By", "1.0 (Android)") + b"\r\n"
    secs = []
    for n in payload:
        s = (wrap("Name", n)
             + wrap("SHA-256-Digest", b64(hashlib.sha256(z.read(n)).digest())) + b"\r\n")
        secs.append((n, s))
        man += s
    check("MANIFEST.MF matches APK contents", man == MAN)

    sf = (wrap("Signature-Version", "1.0") + wrap("Created-By", "1.0 (Android)")
          + wrap("SHA-256-Digest-Manifest", b64(hashlib.sha256(MAN).digest())) + b"\r\n")
    for n, s in secs:
        sf += wrap("Name", n) + wrap("SHA-256-Digest", b64(hashlib.sha256(s).digest())) + b"\r\n"
    check("CERT.SF matches MANIFEST.MF", sf == SF)
    check("digest count == entry count",
          MAN.count(b"SHA-256-Digest:") == len(payload) == SF.count(b"SHA-256-Digest:"),
          "%d entries" % len(payload))
    check("manifest lines wrap at 70 bytes", max(len(l) for l in MAN.split(b"\r\n")) == 70)

    # JAR continuation lines (" " + up to 69 bytes) must be unfolded before comparing names
    def unfold(blob):
        out = []
        for raw in blob.split(b"\r\n"):
            if raw.startswith(b" ") and out:
                out[-1] += raw[1:]
            else:
                out.append(raw)
        return out

    for label, blob in [("MANIFEST.MF", MAN), ("CERT.SF", SF)]:
        lines = unfold(blob)
        nm = [l[6:].decode() for l in lines if l.startswith(b"Name: ")]
        check("%s covers exactly the payload" % label,
              set(nm) == set(payload) and len(nm) == len(set(nm)) == len(payload),
              "%d names" % len(nm))

    # --- PKCS#7 ---
    with tempfile.TemporaryDirectory() as td:
        sp, rp = os.path.join(td, 'sf'), os.path.join(td, 'rsa')
        open(sp, 'wb').write(SF)
        open(rp, 'wb').write(RSA)
        cmd = ["openssl", "cms", "-verify", "-inform", "DER", "-in", rp, "-content", sp]
        cmd += ["-CAfile", cert, "-partial_chain", "-purpose", "any"] if cert else ["-noverify"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().splitlines()
        check("PKCS#7 signature over CERT.SF", "successful" in (r.stdout + r.stderr),
              out[-1][:60] if out else "")

    # --- patches present ---
    so = z.read('lib/armeabi-v7a/libcocos2dcpp.so')
    for nm, off in ARM:
        check("armeabi-v7a %s patched" % nm, so[off:off + len(ARM_CODE)] == ARM_CODE,
              "@0x%x" % off)
    sox = z.read('lib/x86/libcocos2dcpp.so')
    for nm, off in X86:
        check("x86 %s patched" % nm, sox[off:off + len(X86_CODE)] == X86_CODE, "@0x%x" % off)

    # --- nothing else changed vs the original archive ---
    zo = zipfile.ZipFile(src)
    for arch, lib in [("armeabi-v7a", so), ("x86", sox)]:
        o = zo.read("lib/%s/libcocos2dcpp.so" % arch)
        diff = [i for i in range(len(o)) if o[i] != lib[i]]
        regions = ARM if arch == "armeabi-v7a" else X86
        span = 20 if arch == "armeabi-v7a" else 58
        allowed = set()
        for _, off in regions:
            allowed.update(range(off, off + span))
        # count contiguous regions properly
        nreg = sum(1 for k, i in enumerate(diff) if k == 0 or i != diff[k - 1] + 1)
        check("%s: only intended bytes differ" % arch, set(diff) <= allowed,
              "%d bytes in %d contiguous regions" % (len(diff), nreg))

    changed = []
    for n in payload:
        if 'libcocos2dcpp' in n:
            continue
        if zo.read(n) != z.read(n):
            changed.append(n)
    check("all other %d entries byte-identical to original" % (len(payload) - 2),
          not changed, str(changed[:3]))

    print("\n%d passed, %d failed" % (len(ok), len(fail)))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
