#!/usr/bin/env python3
"""Assert that a prelinked kernel still carries the pinned storage bindings.

The addresses in devices/lemonades/bringup/storage-bindings.json were recovered
statically from the hardware-proven phone/pmgr prelinked kernel. The donor
layout depends only on the donor kernelcache, the slide and the pinned
emit_prelink, so every profile's prelinked image must carry the identical
IOStorageFamily placement. Verifying before flashing catches a layout drift
(one changed kext root, a different donor, a new slide) that would otherwise
surface as an opaque crash inside the native UFS driver.
"""
import json
import struct
import sys
from pathlib import Path

def _root():
    # Locally this script lives in <repo>/bringup/tools; in the CI workspace
    # it is copied to work/tools where the device repository is symlinked at
    # work/devices. Walk up to the first directory carrying the markers.
    path = Path(__file__).resolve()
    for _ in range(8):
        if (path / "devices").is_dir() and (path / "source-lock.json").is_file() or \
                (path / "devices").is_dir() and (path / "tools").is_dir():
            return path
        path = path.parent
    raise SystemExit("cannot locate the device repository root")


ROOT = _root()


def record_path():
    for candidate in (ROOT / "devices/lemonades/bringup/storage-bindings.json",
                      ROOT / "bringup/storage-bindings.json"):
        if candidate.is_file():
            return candidate
    raise SystemExit("storage-bindings.json not found")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_lemonades_storage_bindings.py KERNEL_MACHO")
    sys.path.insert(0, str(ROOT / "sources/UniXNU/kits/NativePrelink"))
    prelink_dir = None
    for base in (ROOT / "sources/UniXNU", ROOT.parent / "UniXNU"):
        if (base / "kits/NativePrelink/native_prelink.py").is_file():
            prelink_dir = base / "kits/NativePrelink"
            break
    if prelink_dir is None:
        raise SystemExit("kits/NativePrelink not found (set the UniXNU checkout)")
    sys.path.insert(0, str(prelink_dir))
    import native_prelink as np

    kernel = Path(sys.argv[1]).resolve()
    plan = json.loads(kernel.with_suffix(".json").read_text())
    pinned = json.loads(record_path().read_text())
    blob = kernel.read_bytes()
    image = np.macho(blob)
    exports = np.exports(blob, image)
    by_name = {name: va for va, names in exports.items() for name in names}
    pure = by_name.get("___cxa_pure_virtual")
    if pure is None:
        raise SystemExit("kernel exports no ___cxa_pure_virtual; not the pinned donor layout")

    extents = [e for e in plan["extents"] if e.get("module") == "com.apple.iokit.IOStorageFamily"]
    const = next(e for e in extents if e["segment"] == "__DATA_CONST")
    text = next(e for e in extents if e["segment"] == "__TEXT_EXEC")

    def read(va, length):
        at = np.backed_offset(image["segments"], va, length, len(blob))
        return blob[at:at + length]

    blobconst = read(const["va"], const["size"])
    table = int(pinned["vtable"], 16)
    offset = table - const["va"]
    if offset < 0 or offset + 16 + 190 * 8 > len(blobconst):
        raise SystemExit("pinned vtable outside the IOStorageFamily __DATA_CONST extent")
    if blobconst[offset:offset + 16] != bytes(16):
        raise SystemExit("vtable header is not two zero words")
    pointers = struct.unpack_from("<190Q", blobconst, offset + 16)
    if pointers != tuple(int(v, 16) for v in pinned["slot_targets"]):
        raise SystemExit("dispatch slots drifted from the pinned storage record")
    # The exported slots still resolve to the kernel export trie.
    for i, name in enumerate(pinned["slot_names_from_merged_kernel_exports"]):
        if name is None:
            continue
        expected = name[0] if isinstance(name, list) else name
        if by_name.get(expected) != pointers[i]:
            raise SystemExit(f"exported dispatch slot {i} no longer resolves to {expected}")
    if struct.unpack("<2I", read(pointers[0], 8)) != (0xd4200020, 0xd4200020):
        raise SystemExit("abstract complete destructors lost their BRK traps")
    ctor = int(pinned["original_protected_constructor"], 16)
    words = struct.unpack("<8I", read(ctor, 32))
    if words[:2] != (0xa9bf7bfd, 0x910003fd) or words[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0):
        raise SystemExit("constructor shape drifted")
    imm = ((words[3] >> 5 & 0x7ffff) << 2) | (words[3] >> 29 & 3)
    if imm & 0x100000:
        imm -= 0x200000
    if ((ctor + 12) & ~4095) + imm * 4096 + (words[4] >> 10 & 4095) != table + 16:
        raise SystemExit("constructor no longer stores the vtable")
    meta = int(pinned["original_metaclass"], 16)
    data = next(e for e in extents if e["segment"] == "__DATA")
    if not (data["va"] <= meta < data["va"] + data["size"]):
        raise SystemExit("metaclass drifted out of the IOStorageFamily __DATA extent")
    print(f"PASS: pinned storage bindings verified at {table:#x} in {kernel.name}")


if __name__ == "__main__":
    main()
