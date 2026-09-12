#!/usr/bin/env python3
"""Sign an APK with the v1 (JAR) signature scheme, using only Python + openssl.

v1 alone is sufficient here because targetSdkVersion == 27; Android only mandates
v2+ for apps targeting API 30 and above.

Format was validated byte-for-byte against the signature files that shipped in the
original APK (SHA1-Digest there, SHA-256 here):

  MANIFEST.MF  per-entry:  Name / SHA-256-Digest of the *uncompressed* entry
  CERT.SF      main:       SHA-256-Digest-Manifest = digest of the whole MANIFEST.MF
               per-entry:  SHA-256-Digest of that entry's MANIFEST.MF section bytes
  CERT.RSA     detached PKCS#7 SignedData over CERT.SF, with signed attributes
               (contentType / signingTime / messageDigest) -- same shape as
               apksigner's output.

Attribute lines wrap at 70 bytes; continuation lines are " " + up to 69 bytes.

Usage: python3 tools/sign_v1.py <unsigned.apk> <signed.apk> <workdir>
"""
import base64
import hashlib
import os
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_apk  # reuse the ZIP writer


def wrap(name, value):
    line = ("%s: %s" % (name, value)).encode('utf-8')
    out = bytearray()
    i, limit = 0, 70
    while i < len(line):
        end = min(i + limit, len(line))
        while end < len(line) and (line[end] & 0xC0) == 0x80:
            end -= 1
        if i > 0:
            out += b" "
        out += line[i:end] + b"\r\n"
        i, limit = end, 69
    return bytes(out)


def b64(digest):
    return base64.b64encode(digest).decode()


def make_key(workdir):
    key, cert = os.path.join(workdir, 'key.pem'), os.path.join(workdir, 'cert.pem')
    if not os.path.exists(key):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                        "-days", "10950", "-nodes", "-keyout", key, "-out", cert,
                        "-subj", "/C=MY/O=Personal Use/"
                                  "CN=BoBoiBoy Power Spheres (modded)"],
                       check=True, capture_output=True)
    return key, cert


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    unsigned, signed, workdir = sys.argv[1:4]
    os.makedirs(workdir, exist_ok=True)
    key, cert = make_key(workdir)

    zf = zipfile.ZipFile(unsigned)
    payload = [(i.filename, zf.read(i.filename),
                i.compress_type == zipfile.ZIP_STORED, i.date_time)
               for i in zf.infolist() if not i.filename.startswith('META-INF/')]
    zf.close()

    # ---- MANIFEST.MF -------------------------------------------------------
    man = wrap("Manifest-Version", "1.0") + wrap("Created-By", "1.0 (Android)") + b"\r\n"
    sections = []
    for name, data, _, _ in payload:
        sec = (wrap("Name", name)
               + wrap("SHA-256-Digest", b64(hashlib.sha256(data).digest()))
               + b"\r\n")
        sections.append((name, sec))
        man += sec

    # ---- CERT.SF -----------------------------------------------------------
    sf = (wrap("Signature-Version", "1.0")
          + wrap("Created-By", "1.0 (Android)")
          + wrap("SHA-256-Digest-Manifest", b64(hashlib.sha256(man).digest()))
          + b"\r\n")
    for name, sec in sections:
        sf += (wrap("Name", name)
               + wrap("SHA-256-Digest", b64(hashlib.sha256(sec).digest()))
               + b"\r\n")

    # ---- CERT.RSA (detached PKCS#7, signed attributes) ---------------------
    sf_path, rsa_path = os.path.join(workdir, 'CERT.SF'), os.path.join(workdir, 'CERT.RSA')
    open(sf_path, 'wb').write(sf)
    subprocess.run(["openssl", "cms", "-sign", "-binary", "-in", sf_path,
                    "-outform", "DER", "-out", rsa_path, "-signer", cert,
                    "-inkey", key, "-md", "sha256"], check=True, capture_output=True)
    rsa = open(rsa_path, 'rb').read()
    print("MANIFEST.MF %dB  CERT.SF %dB  CERT.RSA %dB" % (len(man), len(sf), len(rsa)))

    now = (2026, 9, 12, 18, 3, 0)
    entries, meta = [], [
        ("META-INF/MANIFEST.MF", man, False, now),
        ("META-INF/CERT.SF",     sf,  False, now),
        ("META-INF/CERT.RSA",    rsa, False, now),
    ]
    for e in payload:
        if e[0] == 'AndroidManifest.xml':
            entries.append(e)
    entries += meta
    entries += [e for e in payload if e[0] != 'AndroidManifest.xml']

    n = build_apk.build_zip(entries, signed)
    print("wrote %s (%d entries, %.1f MB)" % (signed, n, os.path.getsize(signed) / 1e6))


if __name__ == "__main__":
    main()
