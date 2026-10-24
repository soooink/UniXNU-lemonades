"""Audit the exact high-RAM window on the connected 12 GiB lemonades; no device writes."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "devices/lemonades/scripts"))
from lemonades_adt import load_hardware
from analyze_lemonades import fdt_nodes, reg_ranges

BASE, SIZE, OWNED = 0x100000000, 0x140000000, 0x130000000
MAP = ROOT / "devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Library/MemoryMapLib/MemoryMapLib.c"
IOMEM = ROOT / "out/lemonades/recovery-memory-before-47.txt"


def covered(base, size, ranges):
    end, cursor = base + size, base
    for start, length in sorted(ranges):
        if start > cursor:
            break
        cursor = max(cursor, start + length)
        if cursor >= end:
            return True
    return False


def audit_high_memory():
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    hardware = load_hardware()
    fdt = ROOT / "out/device/lemonades" / hardware["sources"]["evidence_snapshot"] / "running.dtb"
    assert sha(fdt) == hardware["sources"]["running_dtb_sha256"]
    raw = fdt.read_bytes()
    nodes = fdt_nodes(raw)
    assert covered(BASE, SIZE, [(b["base"], b["size"]) for b in hardware["memory_banks"]])
    reservations = []
    for path, props in nodes.items():
        if not path.startswith("/reserved-memory/"):
            continue
        if "reg" in props:
            reservations += [(int(r["address"], 16), r["size_bytes"]) for r in reg_ranges(nodes, path)]
        elif "size" in props:
            # Dynamic Linux pools must have a bounded allocator below our range.
            alloc = props.get("alloc-ranges", b"")
            assert alloc and len(alloc) % 16 == 0, path
            reservations += list(struct.iter_unpack(">QQ", alloc))
    offset = struct.unpack_from(">I", raw, 16)[0]
    while True:
        start, length = struct.unpack_from(">QQ", raw, offset)
        offset += 16
        if not start and not length:
            break
        reservations.append((start, length))
    assert all(not (start < BASE + SIZE and BASE < start + length) for start, length in reservations)
    ram = []
    for line in IOMEM.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]+)-([0-9a-f]+) : System RAM", line)
        if m:
            start, end = (int(v, 16) for v in m.groups())
            ram.append((start, end + 1 - start))
        child = re.match(r"\s+([0-9a-f]+)-([0-9a-f]+) : ", line)
        if child:
            start, end = (int(v, 16) for v in child.groups())
            assert not (start < BASE + SIZE and BASE <= end), line
    assert covered(BASE, SIZE, ram)
    descriptors = re.findall(r'\{"([^"\n]+)", (0x[0-9a-fA-F]+)(?:ULL)?, (0x[0-9a-fA-F]+)(?:ULL)?,', MAP.read_text())
    high = [(name, int(start, 16), int(size, 16)) for name, start, size in descriptors if name == "Darwin High RAM"]
    assert high == [("Darwin High RAM", BASE, SIZE)]
    assert all(name == "Darwin High RAM" or not (int(start, 16) < BASE + SIZE and BASE < int(start, 16) + int(size, 16))
               for name, start, size in descriptors)
    assert OWNED + 0x4000 < SIZE
    return {"base": BASE, "bytes": SIZE, "owned_bytes": OWNED,
            "fdt_sha256": sha(fdt), "iomem_sha256": sha(IOMEM), "map_source_sha256": sha(MAP),
            "fixed_and_dynamic_reservations_excluded": True,
            "status": "static_evidence_checked_first_hardware_use_pending"}


if __name__ == "__main__":
    print(json.dumps(audit_high_memory(), indent=2))
