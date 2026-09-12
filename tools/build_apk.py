#!/usr/bin/env python3
"""Repack an exploded APK directory into an aligned, unsigned APK.

Java / Android build-tools are unavailable here, so the ZIP is written by hand:
that gives exact control over compression method and data alignment.

  * resources.arsc  -> STORED, 4-byte aligned
  * everything else -> DEFLATE (falls back to STORED+align if deflate is bigger)

Entry order and timestamps are taken from the source archive so the result stays
as close to the original as possible. META-INF/* is dropped (re-signed later).

Usage: python3 tools/build_apk.py <exploded-apk-dir> <source-archive> <out.apk>
"""
import os
import struct
import sys
import zipfile
import zlib

ALWAYS_STORED = {"resources.arsc"}


def dos_datetime(dt):
    y, mo, da, h, mi, s = dt
    y = max(y, 1980)
    return ((h << 11) | (mi << 5) | (s // 2)), (((y - 1980) << 9) | (mo << 5) | da)


def build_zip(entries, out_path):
    """entries: list of (name, data, stored, date_time). Returns entry count."""
    out = open(out_path, 'wb')
    central = []
    for name, data, stored, dt in entries:
        nb = name.encode('utf-8')
        crc = zlib.crc32(data) & 0xFFFFFFFF
        usize = len(data)
        if stored:
            method, blob = 0, data
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            blob = co.compress(data) + co.flush()
            if len(blob) >= usize:          # deflate did not help
                method, blob = 0, data
            else:
                method = 8
        mtime, mdate = dos_datetime(dt)
        offset = out.tell()
        extra = b''
        if method == 0:                     # uncompressed data must be 4-byte aligned
            need = (4 - ((offset + 30 + len(nb)) % 4)) % 4
            if need:
                extra = struct.pack('<HH', 0xd935, need) + b'\x00' * need
        flags = 0 if nb.isascii() else 0x0800
        out.write(struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, flags, method, mtime,
                              mdate, crc, len(blob), usize, len(nb), len(extra)))
        out.write(nb)
        out.write(extra)
        out.write(blob)
        central.append((nb, method, mtime, mdate, crc, len(blob), usize, offset, flags))

    cd_off = out.tell()
    for nb, method, mtime, mdate, crc, csize, usize, offset, flags in central:
        out.write(struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 0x031e, 20, flags,
                              method, mtime, mdate, crc, csize, usize, len(nb), 0, 0,
                              0, 0, 0o100644 << 16, offset))
        out.write(nb)
    cd_size = out.tell() - cd_off
    n = len(central)
    out.write(struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cd_size, cd_off, 0))
    out.close()
    return n


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    root, src_zip, out_apk = sys.argv[1:4]

    zf = zipfile.ZipFile(src_zip)
    infos = {i.filename: i for i in zf.infolist()}
    order = [i.filename for i in zf.infolist() if not i.filename.endswith('/')]
    zf.close()

    entries = []
    for name in order:
        if name.startswith('META-INF/'):
            continue
        path = os.path.join(root, name)
        if not os.path.exists(path):
            sys.exit("missing on disk: " + name)
        with open(path, 'rb') as f:
            data = f.read()
        entries.append((name, data, name in ALWAYS_STORED, infos[name].date_time))
    # AndroidManifest.xml first, by convention
    entries.sort(key=lambda e: e[0] != 'AndroidManifest.xml')

    n = build_zip(entries, out_apk)
    print("wrote %s (%d entries, %.1f MB)" % (out_apk, n, os.path.getsize(out_apk) / 1e6))


if __name__ == "__main__":
    main()
