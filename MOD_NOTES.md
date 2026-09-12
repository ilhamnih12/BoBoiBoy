# BoBoiBoy: Power Spheres 1.3.20 — Unlimited Currency Mod

Hasil: **`BoBoiBoy_PowerSpheres_1.3.20_UNLIMITED.apk`** (52 MB, sudah di-sign, siap sideload)

Game ini rilis Maret 2016 (8elements / Animonsta) dan sekarang sudah *abandoned* — tidak lagi
didukung developer dan tidak ada di Play Store. Mod ini dibuat **untuk pemakaian pribadi saja**.
Tolong jangan di-upload ulang / didistribusikan.

---

## Apa yang diubah

Mata uang di game ini ternyata bukan disimpan sebagai variabel biasa, melainkan sebagai **item di
sebuah inventory** (`Model::Dynamic::Inventory`), diakses lewat getter di `Model::Dynamic::Player`:

| Currency      | Item ID | Fungsi getter                          |
|---------------|---------|----------------------------------------|
| Gold          | `1001`  | `Player::getGold()`                    |
| Cocoa Beans   | `1002`  | `Player::getCocoaBeans()`              |
| Ticket        | `1003`  | `Player::getTicket()`                  |

Ketiga getter itu di-patch supaya **selalu mengembalikan `99.999.999`**, apa pun isi save data.
Karena semua cek "cukup uang atau tidak" dan semua pengurangan (`setGold(getGold() - harga)`)
lewat getter ini, efeknya saldo tidak pernah habis.

### Kode asli vs hasil patch

**ARM (`lib/armeabi-v7a/libcocos2dcpp.so`) — Thumb:**

```
Player::getGold()  @0x1e8a76          ->   movw r0, #0xe0ff
  push {r3, lr}                              movt r0, #0x5f5     ; r0 = 99.999.999
  movs r1, #5                                bx   lr
  bl   #0x1e6834    ; getDataWithType(5)     nop x5
  movw r1, #0x3e9   ; item id 1001
  pop  {r3, lr}
  b.w  #0x1e7166    ; getQuantityForItem()
```

`Player::getCocoaBeans()` @`0x1e8aa2` dan `Player::getTicket()` @`0x1e8ad2` di-patch identik
(hanya item ID aslinya yang beda: `0x3ea` dan `0x3eb`).

**x86 (`lib/x86/libcocos2dcpp.so`) — cdecl:**

```
Player::getGold()  @0x2212c0   ->   mov eax, 0x05F5E0FF
  ...20 instruksi...                 ret
  ret                                nop x52
```

Sama untuk `getCocoaBeans()` @`0x221350` dan `getTicket()` @`0x2213f0`.

### Kenapa patch-nya aman

- **Size-preserving** — patch muat persis di dalam batas fungsi, fungsi tetangga (`setGold`,
  `setCocoaBeans`, `getStamina`) tidak tersentuh sama sekali.
- Leaf function, tanpa relocation / control-flow yang berubah.
- `Inventory::getQuantityForItem()` **tidak** di-patch, jadi logika item lain (power sphere,
  karakter, sidekick) tetap normal.
- Tidak ada self-verification signature di game ini. Semua string "signature" yang ada
  berhubungan dengan verifikasi receipt IAP Google Play (Soomla/IAB), yang servernya sudah mati.

### Verifikasi yang sudah dijalankan

`python3 tools/verify.py` — **20/20 PASS**:

| Cek | Hasil |
|-----|-------|
| Diff byte-per-byte vs `.so` asli | ARM: **60 byte** dalam 3 region, x86: **174 byte** dalam 3 region — semuanya di dalam region yang diniatkan, tidak ada yang lain |
| 1265 entry lainnya | byte-identical dengan arsip asli |
| Struktur ELF | utuh (`DYN`, ARM / Intel 80386) |
| Disassembly hasil patch | `movw/movt/bx lr` (ARM), `mov eax,imm32/ret` (x86) — sesuai |
| ZIP CRC seluruh 1270 entry | OK |
| Alignment | 85 entry *stored*, semuanya 4-byte aligned; `resources.arsc` uncompressed |
| `MANIFEST.MF` di-regenerate dari isi APK | identik byte-for-byte |
| `CERT.SF` di-regenerate dari `MANIFEST.MF` | identik byte-for-byte |
| Cakupan `MANIFEST.MF` / `CERT.SF` | tepat 1267 nama entry, unik, 1267 digest (setelah *unfolding* baris yang ter-wrap) |
| Line wrapping | maks 70 byte/baris (entry terpanjang 73 char → ter-wrap dengan benar) |
| Signature PKCS#7 (`openssl cms -verify`) | **CMS Verification successful** |

### Kunci signature

Sertifikat publik ada di `tools/keys/mod-signing-cert.pem` — bisa dipakai untuk memverifikasi
ulang APK:

```
python3 tools/verify.py BoBoiBoy_PowerSpheres_1.3.20_UNLIMITED.apk \
        "BoBoiBoy_ Power Spheres_1.3.20.zip" tools/keys/mod-signing-cert.pem
```

    Subject    : C=MY, O=Personal Use, CN=BoBoiBoy Power Spheres (modded)
    Valid      : 2026-09-12 s/d 2056-09-04
    SHA-256 FP : F2:54:DF:D8:90:4D:C1:0A:7E:08:F3:73:3B:F2:0E:1D:40:9C:7E:6F:47:DC:55:FC:C5:FB:2F:10:E2:B4:C9:09

Private key **tidak** di-commit (dibuat lokal oleh `tools/sign_v1.py`).


---

## Cara pasang di HP

1. **Uninstall dulu** BoBoiBoy: Power Spheres yang lama (kalau ada). APK ini di-sign dengan kunci
   baru, jadi Android akan menolak kalau di-install menimpa yang lama.
   > Konsekuensinya save lama hilang. Tapi karena saldo sekarang selalu 99.999.999, itu tidak masalah.
2. Copy file `.apk` ke HP.
3. Buka file-nya, izinkan "Install unknown apps" untuk browser/file manager kamu.
4. Android mungkin menampilkan peringatan "app tidak diverifikasi" — itu normal untuk APK
   hasil sign ulang, bukan tanda ada malware.

## Catatan & keterbatasan

- **Signature**: APK ini hanya pakai **v1 (JAR) signature**. Itu cukup dan valid karena
  `targetSdkVersion = 27` (aturan wajib v2+ hanya berlaku untuk app yang target API 30+).
  Kalau HP kamu tetap menolak install, bilang saja — nanti saya buatkan varian dengan v2/v3.
- **Hanya 32-bit**: APK aslinya memang cuma berisi `armeabi-v7a` dan `x86`, tidak ada `arm64-v8a`.
  Di HP 64-bit-only tertentu game ini tidak akan jalan — ini keterbatasan APK aslinya, bukan mod-nya.
- **Stamina / Energy sengaja tidak di-patch.** Itu mekanik timer, bukan mata uang, dan mengubahnya
  berisiko bikin tampilan UI jadi aneh. Kalau mau, tinggal bilang.
- **Harga item tidak diubah.** Tidak perlu — dengan saldo tak terbatas, semua tetap terbeli.
- IAP, ads, Facebook, dan HockeyApp di APK ini semuanya sudah mati (server 2018), jadi
  fitur online tidak akan jalan. Gameplay single-player-nya normal.

## Build ulang dari nol

Toolchain di environment ini tidak punya Java (apt & `dl.google.com` diblokir), jadi build-nya
murni Python + `openssl`:

```
tools/patch_so.py    # patch getter currency di kedua .so
tools/build_apk.py   # repack exploded APK -> ZIP teralign
tools/sign_v1.py     # MANIFEST.MF + CERT.SF + CERT.RSA (PKCS#7 via openssl)
tools/verify.py      # semua cek di tabel verifikasi di atas
```
