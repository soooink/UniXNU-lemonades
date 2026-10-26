#!/usr/bin/env python3
"""Build the userdata root image on Linux (no hdiutil).

Replicates the SHNGROOT layout that the native UFS root driver reads
(drivers/NativeUfs/RootLayout.h):

    0x000000  manifest block (4096 B), zero padding to 1 MiB
    0x100000  window "OS"        the whole OS disk image, 1 MiB aligned
    ....      window "SystemOS"  the whole SystemOS disk image, 1 MiB aligned

Manifest (little endian): "SHNGROOT", u32 version=1, u32 count, u64 image_bytes,
then count 128-byte entries {char name[32], u64 offset, u64 size,
u32 block_size=512, u32 flags=1, u8 sha256[32], 40 reserved}, and at byte 4064
the SHA-256 of bytes 0..4063.

The disk images are Apple DMGs; hdiutil is not available on Linux, so the
UDZO/ULFO/LZFSE chunk table is decoded directly (zlib/bz2/LZFSE via the
`lzfse` CLI) and the raw whole-disk bytes are written. Nothing touches a
device: the report prints the fastboot command for the user.
"""
import argparse
import bz2
import ctypes
import hashlib
import json
import lzma
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
while ROOT.is_dir() and not (ROOT / "source-lock.json").is_file() and ROOT.parent != ROOT:
    ROOT = ROOT.parent

MIB = 1 << 20
CHUNK = 8 * MIB


def koly(dmg):
    """Parse the koly trailer of a UDIF DMG; None when the file is not UDIF."""
    with open(dmg, "rb") as f:
        f.seek(-512, 2)
        trailer = f.read(512)
    if trailer[:4] != b"koly":
        return None
    fields = struct.unpack_from(">IIII", trailer, 4)
    version, header_size, flags = fields[0], fields[1], fields[2]
    data_off, data_len = struct.unpack_from(">QQ", trailer, 24)
    xml_off, xml_len = struct.unpack_from(">QQ", trailer, 216)
    sector_count = struct.unpack_from(">Q", trailer, 492)[0]
    return dict(version=version, header_size=header_size, flags=flags,
                data_off=data_off, data_len=data_len,
                xml_off=xml_off, xml_len=xml_len, sector_count=sector_count)


def blkx_runs(table):
    """Decode a mish BLKX table into (type, sector, sectors, offset, length) runs."""
    if table[:4] != b"mish":
        raise SystemExit("DMG block table is not mish")
    runs = []
    # BLKXTable: signature 0, version 4, sectorNumber 8, sectorCount 16,
    # dataOffset 24, buffersNeeded 32, blockDescriptors 36, reserved[6] 40,
    # checksumType 64, checksumSize 68, checksum[32] 72, blocksRunCount 200,
    # runs[] 204. BLKXRun: type 0, comment 4, sector 8, sectors 16,
    # compressedOffset 24, compressedLength 32 (40 bytes).
    count = struct.unpack_from(">I", table, 200)[0]
    for i in range(count):
        at = 204 + 40 * i
        typ, _comment, sector, sectors, coff, clen = struct.unpack_from(">IIQQQQ", table, at)
        runs.append((typ, sector, sectors, coff, clen))
    return runs


def adc_decompress(payload, want):
    """Apple Data Compression (ADC) chunk decoder (dmg2img/libdmg semantics)."""
    out = bytearray()
    i = 0
    while len(out) < want and i < len(payload):
        code = payload[i]; i += 1
        if code & 0x80:                      # literal run
            n = (code & 0x7F) + 1
            out += payload[i:i + n]
            i += n
        elif code & 0x40:                    # back-reference, 16-bit offset
            n = (code & 0x3F) + 4
            off = (payload[i] << 8) | payload[i + 1]
            i += 2
            for _ in range(n):
                out.append(out[-off])
        else:                                # back-reference, 10-bit offset
            n = ((code & 0x3C) >> 2) + 3
            off = ((code & 0x03) << 8) | payload[i]
            i += 1
            for _ in range(n):
                out.append(out[-off])
    return bytes(out)


LZFSE_LIB = None


def lzfse_decode(payload, want):
    """Decode one LZFSE block stream (bvxn/bvx2/bvx- ... bvx$) via liblzfse."""
    global LZFSE_LIB
    if LZFSE_LIB is None:
        for candidate in ("liblzfse.so.1", "liblzfse.so",
                          str(Path.home() / "toolchain/local/usr/lib/x86_64-linux-gnu/liblzfse.so.1")):
            try:
                LZFSE_LIB = ctypes.CDLL(candidate)
                break
            except OSError:
                continue
        if LZFSE_LIB is None:
            raise SystemExit("liblzfse not found (install the lzfse package)")
    fn = LZFSE_LIB.lzfse_decode_buffer
    fn.restype = ctypes.c_size_t
    fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    dst = ctypes.create_string_buffer(want)
    n = fn(dst, want, payload, len(payload), None)
    if n == 0:
        raise SystemExit("LZFSE decode failed (uncompressed block?)")
    return dst.raw[:n]


def decode_dmg(dmg, out):
    """Decompress a UDIF DMG to a raw whole-disk image; copy raw images unchanged."""
    info = koly(dmg)
    if info is None:
        # Cryptex1,SystemOS ships as a bare APFS container image, byte for byte.
        shutil.copyfile(dmg, out)
        return out.stat().st_size
    total = info["sector_count"] * 512
    with open(dmg, "rb") as f:
        f.seek(info["xml_off"])
        plist = plistlib.loads(f.read(info["xml_len"]))
        resources = plist.get("resource-fork", {})
        blkx = resources.get("blkx")
        if not blkx:
            raise SystemExit(f"{dmg}: no blkx resource fork")
        tables = [(struct.unpack_from(">Q", entry["Data"], 8)[0], blkx_runs(entry["Data"]))
                  for entry in blkx]
        for base, runs in tables:
            for _t, sector, sectors, _o, _l in runs:
                total = max(total, (base + sector + sectors) * 512)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as target:
            target.truncate(total)
            for base, runs in tables:
                for typ, sector, sectors, coff, clen in runs:
                    want = sectors * 512
                    absolute = base + sector
                    target.seek(absolute * 512)
                    if typ in (0x00000000, 0x00000002, 0xffffffff):
                        target.write(bytes(want))
                        continue
                    if clen == 0 and typ != 0x00000001:
                        continue
                    f.seek(info["data_off"] + coff)
                    payload = f.read(clen)
                    if typ == 0x00000001:              # raw
                        data = payload
                    elif typ == 0x80000005:            # zlib
                        data = zlib.decompress(payload)
                    elif typ == 0x80000006:            # bzip2
                        data = bz2.decompress(payload)
                    elif typ in (0x80000007, 0x80000008):   # LZFSE (bvxn/bvx2/bvx-)
                        data = lzfse_decode(payload, want)
                    elif typ == 0x80000009:            # LZMA
                        data = lzma.decompress(payload)
                    else:
                        raise SystemExit(f"{dmg}: unsupported chunk type {typ:#x} at sector {absolute}")
                    if len(data) != want:
                        raise SystemExit(f"{dmg}: chunk at sector {absolute} decoded {len(data)} != {want}")
                    target.write(data)
    return total


def build(image, windows, capacity, start=MIB):
    """Write the SHNGROOT manifest and the windows into the image.

    `start` leaves room between the manifest block and the first window for the
    signed verified-root policies (the driver reads them from disk, keeping the
    kernel small enough for the 96 MiB boot partition)."""
    layout, cursor = [], start
    for name, raw in windows:
        size = raw.stat().st_size
        layout.append((name, cursor, size, raw))
        cursor += (size + MIB - 1) // MIB * MIB
    total = cursor
    if total > capacity:
        raise SystemExit(f"image {total} bytes exceeds the userdata partition {capacity}")
    entries = []
    with open(image, "wb") as target:
        target.truncate(total)
        for name, offset, size, raw in layout:
            digest = hashlib.sha256()
            target.seek(offset)
            done = 0
            with open(raw, "rb", buffering=0) as handle:
                while done < size:
                    want = min(CHUNK, size - done)
                    data = handle.read(want)
                    if len(data) != want:
                        raise SystemExit(f"short read from {raw} at {done}")
                    digest.update(data)
                    target.write(data)
                    done += want
            entries.append((name, offset, size, digest.digest()))
            print(f"userdata: {name} {size} bytes at {offset:#x} sha256 {digest.hexdigest()}")
        header = bytearray(4096)
        header[0:8] = b"SHNGROOT"
        struct.pack_into("<IIQ", header, 8, 1, len(entries), total)
        for index, (name, offset, size, digest) in enumerate(entries):
            struct.pack_into("<32sQQII32s40s", header, 24 + 128 * index,
                             name.encode(), offset, size, 512, 1, digest, bytes(40))
        header[4064:4096] = hashlib.sha256(bytes(header[:4064])).digest()
        target.seek(0)
        target.write(header)
    return total, entries, hashlib.sha256(bytes(header)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board", type=Path, default=ROOT / "board.toml")
    parser.add_argument("--ipsw-dir", type=Path, required=True,
                        help="directory holding the extracted 044-*.dmg files")
    parser.add_argument("--out", type=Path, required=True, help="output userdata-root.img")
    parser.add_argument("--policy-reserve", type=lambda v: int(v, 0), default=MIB,
                        help="first window offset; leaves room for the signed root policies")
    args = parser.parse_args()
    import tomllib
    board = tomllib.loads(args.board.read_text())
    spec = board["userdata"]
    capacity = (spec["last_lba"] - spec["first_lba"] + 1) * spec.get("lba_bytes", 4096)
    # The IPSW component -> DMG member map (BuildManifest paths, pinned in board.toml).
    members = {"OS": "044-76040-038.dmg", "Cryptex1,SystemOS": "044-76034-038.dmg"}
    raws = []
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        for window in spec["windows"]:
            component = window["component"]
            dmg = args.ipsw_dir / members[component]
            if not dmg.is_file():
                raise SystemExit(f"missing {dmg}")
            raw = work / (window["name"] + ".raw")
            print(f"userdata: decoding {dmg.name} -> {raw.name}")
            size = decode_dmg(dmg, raw)
            print(f"userdata: {window['name']} raw {size} bytes")
            raws.append((window["name"], raw))
        total, entries, manifest = build(args.out, raws, capacity, args.policy_reserve)
    report = {
        "image": str(args.out),
        "image_bytes": total,
        "image_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
        "manifest_sha256": manifest,
        "windows": [{"name": n, "offset": o, "size": s, "sha256": d.hex()} for n, o, s, d in entries],
        "policy_reserve": args.policy_reserve,
        "userdata_bytes": capacity,
        "flash_command": f"fastboot flash userdata {args.out}",
        "source": "local (Linux DMG decoder)",
        "hardware_tested": False,
    }
    args.out.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"userdata: {args.out} ({total} bytes)")
    print(f"flash it yourself with: {report['flash_command']}")


if __name__ == "__main__":
    main()
