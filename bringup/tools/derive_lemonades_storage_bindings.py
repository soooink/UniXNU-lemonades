#!/usr/bin/env python3
"""Derive the pinned storage binding record from a prelinked kernel image.

The record is image-family specific: the addresses of the IOStorageFamily
donor kext's own methods move with the merged layout, which depends on the
root set that emit_prelink merges (the phone family carries
AMFI/Sandbox/ApplePMGR; the storage family adds APFS and the
filesystem-compression closure on top). Derive the record for the exact
family that will be flashed, and keep verify_lemonades_storage_bindings.py
in front of every flash so a stale record is caught before it leaves the
machine.

--check-against OLD_RECORD additionally proves family stability of the
dispatch identity: every slot whose target is kernel-exported must carry
the same export name in both records (only the addresses may move).
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
while ROOT.is_dir() and not (ROOT / "source-lock.json").is_file() and ROOT.parent != ROOT:
    ROOT = ROOT.parent
if not (ROOT / "source-lock.json").is_file():
    raise SystemExit("cannot locate the device repository root")


def prelink_dir():
    for base in (ROOT / "sources/UniXNU", ROOT.parent / "UniXNU"):
        if (base / "kits/NativePrelink/native_prelink.py").is_file():
            return base / "kits/NativePrelink"
    raise SystemExit("kits/NativePrelink not found (set the UniXNU checkout)")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kernel", type=Path, help="prelinked kernel Mach-O with its .json plan")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--check-against", type=Path,
                    help="an older record to prove the exported dispatch identity is stable")
    ap.add_argument("--roots", required=True,
                    help="comma list of the emit_prelink roots this image was built with")
    args = ap.parse_args()

    sys.path.insert(0, str(prelink_dir()))
    import native_prelink as np

    kernel = args.kernel.resolve()
    plan = json.loads(kernel.with_suffix(".json").read_text())
    blob = kernel.read_bytes()
    image = np.macho(blob)
    exports = np.exports(blob, image)
    by_name = {name: va for va, names in exports.items() for name in names}
    pure = by_name.get("___cxa_pure_virtual")
    if pure is None:
        raise SystemExit("no ___cxa_pure_virtual export: not the expected donor layout")

    extents = [e for e in plan["extents"] if e.get("module") == "com.apple.iokit.IOStorageFamily"]
    if len(extents) < 4:
        raise SystemExit("IOStorageFamily extents missing from the plan")

    def read(va, length):
        at = np.backed_offset(image["segments"], va, length, len(blob))
        return blob[at:at + length]

    def rb(addr, ins):
        imm = ins & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        return addr + imm * 4

    def thunk_names(address):
        a, load, branch = struct.unpack("<3I", read(address, 12))
        if not (a & 0x9f00001f == 0x90000010 and load & 0xffc003ff == 0xf9400210 and branch == 0xd61f0200):
            return []
        imm = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
        if imm & 0x100000:
            imm -= 0x200000
        slot = (address & ~4095) + imm * 4096 + (load >> 10 & 4095) * 8
        target = struct.unpack("<Q", read(slot, 8))[0]
        return exports.get(target, [])

    # Locate the unique 190-slot dispatch table.
    const = next(e for e in extents if e["segment"] == "__DATA_CONST")
    text = next(e for e in extents if e["segment"] == "__TEXT_EXEC")
    blobconst = read(const["va"], const["size"])
    export_addrs = set(exports.keys())
    in_text = lambda p: text["va"] <= p < text["va"] + text["size"]
    found = []
    for at in range(0, len(blobconst) - 192 * 8 + 1, 8):
        if blobconst[at:at + 16] != bytes(16):
            continue
        ptrs = struct.unpack_from("<190Q", blobconst, at + 16)
        if sum(p == pure for p in ptrs) != 14:
            continue
        if not all(p == pure or p in export_addrs or in_text(p) for p in ptrs):
            continue
        found.append((const["va"] + at, ptrs))
    if len(found) != 1:
        raise SystemExit(f"expected one dispatch table, found {len(found)}")
    table, ptrs = found[0]

    # Special symbols, derived exactly like the upstream interface audit.
    d1 = ptrs[0]
    if read(d1, 4) != struct.pack("<I", 0xd4200020):
        raise SystemExit("complete destructor lost its BRK trap")
    word = struct.unpack("<I", read(d1 - 4, 4))[0]
    if word & 0xfc000000 != 0x14000000:
        raise SystemExit("no forward branch before the complete destructor")
    d2 = rb(d1 - 4, word)
    if "IOService" not in " ".join(thunk_names(d2)):
        raise SystemExit("base destructor does not forward to the actual IOService destructor")
    constructors = []
    for address in range(text["va"], text["va"] + text["size"] - 32, 4):
        words = struct.unpack("<8I", read(address, 32))
        if (words[:2] != (0xa9bf7bfd, 0x910003fd) or words[2] & 0xfc000000 != 0x94000000 or
                words[3] & 0x9f00001f != 0x90000008 or words[4] & 0xffc003ff != 0x91000108 or
                words[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0)):
            continue
        imm = ((words[3] >> 5 & 0x7ffff) << 2) | (words[3] >> 29 & 3)
        if imm & 0x100000:
            imm -= 0x200000
        stored = ((address + 12) & ~4095) + imm * 4096 + (words[4] >> 10 & 4095)
        if stored == table + 16:
            constructors.append((address, rb(address + 8, words[2])))
    if len(constructors) != 1:
        raise SystemExit(f"expected one constructor storing the vtable, found {len(constructors)}")
    ctor, bl = constructors[0]
    if "IOService" not in " ".join(thunk_names(bl)):
        raise SystemExit("constructor does not forward to the actual IOService constructor")
    a, add, ret = struct.unpack("<3I", read(ptrs[7], 12))
    if not (a & 0x9f00001f == 0x90000000 and add & 0xffc003ff == 0x91000000 and ret == 0xd65f03c0):
        raise SystemExit("slot 7 is not the metaclass getter shape")
    imm = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
    if imm & 0x100000:
        imm -= 0x200000
    meta = (ptrs[7] & ~4095) + imm * 4096 + (add >> 10 & 4095)
    data = next(e for e in extents if e["segment"] == "__DATA")
    if not (data["va"] <= meta < data["va"] + data["size"]):
        raise SystemExit("metaclass object drifted out of the kext __DATA extent")

    slot_names = []
    moved = None
    for p in ptrs:
        if p in export_addrs:
            names = exports[p]
            slot_names.append(names[0] if len(names) == 1 else sorted(names))
        else:
            slot_names.append(None)

    # Family stability: the dispatch identity (names on exported slots) must
    # be invariant across image families; only the owned addresses move.
    if args.check_against:
        old = json.loads(args.check_against.read_text())
        old_names = old["slot_names_from_merged_kernel_exports"]
        moved = 0
        for i, (name, target) in enumerate(zip(slot_names, ptrs)):
            if old_names[i] is not None:
                expected = old_names[i]
                ok = name == expected or (isinstance(name, list) and expected in name) or \
                    (isinstance(expected, list) and name in expected)
                if not ok:
                    raise SystemExit(f"dispatch slot {i} identity changed between records: "
                                     f"{expected!r} vs {name!r}")
            if int(old["slot_targets"][i], 16) != target:
                moved += 1
        print(f"record stability vs {args.check_against.name}: {moved} slot addresses moved, "
              f"dispatch identity intact")

    record = {
        "class": "IOBlockStorageDevice",
        "source_revision": "e45fbe30a7879e0b16e26dddb78538f1b00e0bff",
        "donor_kernelcache_sha256": plan.get("original_sha256"),
        "slide": plan.get("slide"),
        "roots": [r.strip() for r in args.roots.split(",") if r.strip()],
        "prelink_input_kernel_sha256": plan.get("native_sha256"),
        "prelink_candidate_sha256": plan.get("candidate_sha256"),
        "iostoragefamily_extents": {e["segment"]: {"va": hex(e["va"]), "size": hex(e["size"])}
                                     for e in extents},
        "vtable": hex(table),
        "original_metaclass": hex(meta),
        "original_protected_constructor": hex(ctor),
        "original_base_destructor": hex(d2),
        "slot_targets": [hex(p) for p in ptrs],
        "slot_names_from_merged_kernel_exports": slot_names,
        "verification": {
            "method_slots": 190,
            "pure_virtual_slots": 14,
            "exported_slots": sum(n is not None for n in slot_names),
            "abstract_complete_destructors_brk_trap": True,
            "constructor_stores_vtable_plus_16": True,
            "constructor_forwards_to": "IOService C2",
            "base_destructor_forwards_to": "IOService D2",
            "metaclass_from_slot7_getter_adrp_add": True,
        },
        "hardware_tested": False,
        "disk_read_tested": False,
    }
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"PASS: record written to {args.out} (vtable {table:#x}, {moved if args.check_against else '-'} moved slots)")


if __name__ == "__main__":
    main()
