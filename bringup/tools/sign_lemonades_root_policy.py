#!/usr/bin/env python3
"""Sign the userdata windows with an owner RSA-3072 key (Linux, openssl only).

Produces the VerifiedRoot envelopes for the OS and SystemOS windows of the
built userdata image and a VRPOLICY region that the native UFS driver reads
from disk at boot. The trust anchor stays in the kernel: only the owner
public key is compiled in, and every envelope is verified against it.

The APFS volume UUID comes from the container's newest volume superblock
(APSB), found by scanning the window for the magic and keeping the highest
transaction id, so hdiutil is not required.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
while ROOT.is_dir() and not (ROOT / "source-lock.json").is_file() and ROOT.parent != ROOT:
    ROOT = ROOT.parent

MIB = 1 << 20
CHUNK = 64 << 20
POLICY_MAGIC = b"VRPOLICY"
POLICY_HEADER = 0x1000      # second block of the userdata partition
POLICY_BLOBS = 0x2000       # first manifest byte
POLICY_ENTRY = 96


def manifest_module(kits):
    spec = importlib.util.spec_from_file_location("vrmanifest", kits / "tools/manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fletcher_ok(block):
    words = struct.unpack_from("<1024I", block, 0)
    def fl(ws, init=0):
        s1 = init & 0xFFFFFFFF
        s2 = init >> 32
        for w in ws:
            s1 = (s1 + w) & 0xFFFFFFFFFFFFFFFF
            s2 = (s2 + s1) & 0xFFFFFFFFFFFFFFFF
        return ((s2 % 0xFFFFFFFF) << 32) | (s1 % 0xFFFFFFFF)
    return fl(words[:2], fl(words[2:], 0)) == 0


def volume_uuid(image, offset, size):
    """Newest APSB volume superblock's UUID inside a window."""
    best = None
    with open(image, "rb") as f:
        done = 0
        while done < size:
            f.seek(offset + done)
            chunk = f.read(min(CHUNK, size - done))
            at = 0
            while True:
                at = chunk.find(b"APSB", at)
                if at < 0:
                    break
                pos = done + at
                # APSB magic sits at block+0x20; the container base is only
                # 512-byte aligned relative to the window, so the Fletcher-64
                # checksum, not an alignment test, decides validity.
                block = pos - 0x20
                if block >= 0:
                    f.seek(offset + block)
                    data = f.read(4096)
                    if len(data) == 4096 and fletcher_ok(data):
                        xid = struct.unpack_from("<Q", data, 16)[0]
                        if best is None or xid > best[0]:
                            best = (xid, block, data)
                at += 4
            done += len(chunk)
            if not chunk:
                break
    if best is None:
        raise SystemExit("no valid APSB in window")
    xid, block, data = best
    return str(uuid.UUID(bytes=data[0xF0:0x100])), xid, block


class WindowStream:
    """A bounded view of one window inside the userdata image."""

    def __init__(self, image, offset, size):
        self.file = open(image, "rb")
        self.file.seek(offset)
        self.left = size

    def read(self, count):
        data = self.file.read(min(count, self.left))
        self.left -= len(data)
        return data

    def close(self):
        self.file.close()


def write_policy_region(image, policies):
    """Write the VRPOLICY header (block 1) and the signed manifests into the image.

    Header: magic[8], u32 version, u32 count, reserved[8].
    Entry (96 bytes): name[32], u64 offset, u64 size, u32 flags=1, u32 reserved,
    sha256[32], reserved2[8]. Offsets are relative to the userdata partition.
    """
    cursor = POLICY_BLOBS
    entries = []
    with open(image, "r+b") as f:
        for item in policies:
            data = Path(item["manifest"]).read_bytes()
            f.seek(cursor)
            f.write(data)
            entries.append((item["name"], cursor, len(data), hashlib.sha256(data).digest()))
            cursor = (cursor + len(data) + 4095) & ~4095
        header = bytearray(4096)
        header[0:8] = POLICY_MAGIC
        struct.pack_into("<II", header, 8, 1, len(entries))
        for index, (name, offset, size, digest) in enumerate(entries):
            at = 48 + POLICY_ENTRY * index
            struct.pack_into("<32sQQII", header, at, name.encode(), offset, size, 1, 0)
            header[at + 56:at + 88] = digest
        f.seek(POLICY_HEADER)
        f.write(header)
    # Read back and prove every manifest landed intact.
    with open(image, "rb") as f:
        f.seek(POLICY_HEADER)
        header = f.read(4096)
        assert header[0:8] == POLICY_MAGIC and struct.unpack_from("<I", header, 12)[0] == len(entries)
        for index, (name, offset, size, digest) in enumerate(entries):
            at = 48 + POLICY_ENTRY * index
            stored = struct.unpack_from("<32sQQI", header, at)
            assert stored[0].split(b"\0")[0].decode() == name and stored[1] == offset and stored[2] == size
            f.seek(offset)
            assert hashlib.sha256(f.read(size)).digest() == header[at + 56:at + 88] == digest
    print(f"policy region: {len(entries)} manifests, {cursor} bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--kits", type=Path, default=ROOT.parent / "UniXNU/kits/VerifiedRoot")
    parser.add_argument("--out", type=Path, required=True, help="policy directory")
    parser.add_argument("--generation", type=int, default=1)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    key = args.out / "owner.pem"
    public = args.out / "owner-public.pem"
    if not key.is_file():
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)], check=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True)
    module = manifest_module(args.kits)
    report = json.loads(args.report.read_text())
    policies = []
    for window in report["windows"]:
        uuid_text, xid, block = volume_uuid(args.image, window["offset"], window["size"])
        print(f"{window['name']}: volume uuid {uuid_text} (xid {xid}, block {block:#x})")
        out = args.out / window["name"]
        stream = WindowStream(args.image, window["offset"], window["size"])
        try:
            record = module.make(stream, window["size"], key, public, uuid.UUID(uuid_text),
                                 args.generation, out)
        finally:
            stream.close()
        assert record["image_sha256"] == window["sha256"], "window hash drifted"
        policies.append({"name": window["name"], "offset": window["offset"], "size": window["size"],
                         "volume_uuid": uuid_text, "manifest": str(out / "manifest.bin"),
                         "manifest_bytes": (out / "manifest.bin").stat().st_size,
                         "manifest_sha256": hashlib.sha256((out / "manifest.bin").read_bytes()).hexdigest()})
    summary = {"status": "owner_signed_manifests", "generation": args.generation,
               "trusted_key_sha256": hashlib.sha256((args.out / "OS/trusted-key.bin").read_bytes()).hexdigest(),
               "windows": policies, "hardware_tested": False}
    (args.out / "policies.json").write_text(json.dumps(summary, indent=2) + "\n")
    write_policy_region(args.image, policies)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
