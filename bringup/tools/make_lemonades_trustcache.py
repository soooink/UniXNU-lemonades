#!/usr/bin/env python3
"""Wrap an IM4P trust cache into the bundle format DarwinBoot validates.

The IPSW's StaticTrustCache is an IMG4 payload: a DER SEQUENCE holding
"IM4P"/"trst" strings and the raw version-2 trust cache in an OCTET STRING.
DarwinBoot (DarwinBootPkg/Driver/DarwinBoot.c, ValidTrustCaches) expects the
XNU trust cache bundle instead:

    u32 count, count x u32 module offsets,
    then per module: u32 version=2, uuid[16], u32 entries,
                     entries x 24 bytes {hash[20], hash_type, 3 pad}

sorted strictly ascending by hash. This tool extracts the payload, verifies it
against those rules, and writes the bundle.
"""
import argparse
import struct
import sys
from pathlib import Path


def extract(data):
    if data[:2] != b"\x30\x82":
        raise SystemExit("not a DER IM4P: missing 0x30 0x82")
    if data[4:6] != b"\x16\x04" or data[6:10] != b"IM4P":
        raise SystemExit("not an IM4P payload")
    if data[10:12] != b"\x16\x04" or data[12:16] != b"trst":
        raise SystemExit("not a trst payload")
    if data[0x13] != 0x04 or data[0x14] != 0x82:
        raise SystemExit("expected an OCTET STRING payload")
    length = struct.unpack_from(">H", data, 0x15)[0]
    start = 0x17
    if start + length > len(data):
        raise SystemExit("payload length exceeds the file")
    return data[start:start + length]


def validate_bundle(data):
    size = len(data)
    if size < 8:
        return False
    count = struct.unpack_from("<I", data, 0)[0]
    if count == 0 or count > 128 or count > (size - 4) // 4:
        return False
    for index in range(count):
        start = struct.unpack_from("<I", data, 4 + index * 4)[0]
        end = struct.unpack_from("<I", data, 8 + index * 4)[0] if index + 1 < count else size
        if (start < 4 + count * 4 or start & 3 or end > size or end < start or
                end - start < 24 or struct.unpack_from("<I", data, start)[0] != 2):
            return False
        entries = struct.unpack_from("<I", data, start + 20)[0]
        if entries > (end - start - 24) // 24 or end - start != 24 + entries * 24:
            return False
        for entry in range(entries):
            at = start + 24 + entry * 24
            if data[at + 20] < 1 or data[at + 20] > 4:
                return False
            if entry != 0 and data[at - 24:at - 4] >= data[at:at + 20]:
                return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="the IPSW *.dmg.trustcache (IM4P)")
    parser.add_argument("output", type=Path, help="bundle file for --trust-cache")
    args = parser.parse_args()
    payload = extract(args.input.read_bytes())
    bundle = struct.pack("<II", 1, 8) + payload
    if not validate_bundle(bundle):
        raise SystemExit("extracted trust cache does not satisfy the bundle rules")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    entries = struct.unpack_from("<I", payload, 20)[0]
    print(f"trust cache bundle: {args.output} ({len(bundle)} bytes, {entries} entries)")


if __name__ == "__main__":
    main()
