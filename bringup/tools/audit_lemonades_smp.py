#!/usr/bin/env python3
"""Static and host checks for the lemonades SMP configuration; never boots a VM/device."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "devices/lemonades/scripts"))
from lemonades_adt import decode, load_hardware


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(adt=None):
    tree = ROOT / "out/lemonades-xnu/lemonades/tree"
    kernel = tree / ".cache/xnu-work"
    hardware = load_hardware()
    affinities = [cpu["affinity"] for cpu in hardware["cpus"]]
    assert affinities == [i << 8 for i in range(8)]
    evidence = ROOT / "out/device/lemonades" / hardware["sources"]["evidence_snapshot"] / "running.dtb"
    assert sha(evidence) == hardware["sources"]["running_dtb_sha256"]
    config = kernel / "pexpert/pexpert/arm64/board_config.h"
    text = config.read_text()
    section = text[text.index('#include <pexpert/arm64/BCM2837.h>'):]
    assert re.search(r"#define MAX_CPUS\s+8\b", section.split("#endif", 1)[0])
    reset = kernel / "osfmk/arm64/start.s"
    assert re.search(r"#if HAS_CLUSTER \|\| defined\(BCM2837\)\s+and\s+x0, x15, #0xFFFF", reset.read_text())
    armcpu = ROOT / "sources/UniXNU/drivers/ArmCpu/ArmCpu.cpp"
    original = armcpu.read_text()
    assert "psciCall (hvc, 0xc4000003ULL, affinity & 0xff00ffffffULL, entry, 0)" in original
    assert "ml_static_vtop" in original
    for region, size in (("LowResetVectorBase", "0x10000"), ("ResetHandlerData", "0x1000"), ("const_boot_args", "0x1000")):
        assert f"cleanToMemory ({region}, {size})" in original
    # Compile the actual signalCPU expression on the host. Privileged register
    # writes are checked separately in the actual ArmCpu object by its builder.
    function = original[original.index("void ArmCpu::signalCPU ("):]
    expression = re.search(r"uint64_t sgi = (.*?);", function, re.S).group(1)
    source = "#include <stdint.h>\n#include <assert.h>\nint main(void) {\n"
    source += "for(unsigned i=0;i<8;++i) { uint64_t aff=(uint64_t)i<<8;\n"
    source += "uint64_t sgi=" + expression + ";\n"
    source += "assert(sgi==(((uint64_t)i<<16)|1));\n} return 0; }\n"
    with tempfile.TemporaryDirectory(prefix="lemonades-sgi-host-") as tmp:
        c, exe = Path(tmp)/"sgi.c", Path(tmp)/"sgi"
        c.write_text(source)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                        str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    menu = ROOT / "devices/lemonades/package/unixnu-xnu-prelink.toml"
    entry, = [e for e in tomllib.loads(menu.read_text())["entry"] if e["type"] == "xnu"]
    args = entry["args"].split()
    assert all(a in args for a in ("sheng-smp=1", "armcpu-self-ipi=1", "armcpu-spi-ipi=0"))
    assert not any(a.startswith("cpus=") for a in args)
    build = json.loads((tree / "build/armcpu/build-report.json").read_text())
    baseline = json.loads((ROOT / "out/lemonades/gic-qemu-baseline.json").read_text())
    reference = ROOT / baseline["source_archive"] / "build-report.json"
    assert build["compiled_source_sha256"] == json.loads(reference.read_text())["compiled_source_sha256"]
    assert build["actual_instruction_sequences_checked"]
    report = {"status": "passed_host_and_static_checks_only", "affinities": affinities,
              "psci_cpu_on": "SMC64 0xc4000003", "ipi": "SGI 0 via ICC_SGI1R_EL1",
              "self_ipi_enabled": True, "spi_ipi_enabled": False,
              "actual_sgi_target_expression_host_checked": True,
              "unchanged_armcpu_compiled_source_sha256": build["compiled_source_sha256"],
              "actual_armcpu_instruction_sequences_checked": True,
              "max_cpus": 8, "reset_affinity_mask": "0xffff",
              "qemu_run": False, "hardware_tested": False,
              "sources": {str(p.relative_to(ROOT)): sha(p) for p in (evidence, armcpu, config, reset, menu)}}
    if adt:
        parsed = decode(adt.read_bytes())
        cpus = parsed.at("/cpus").children
        actual = [struct.unpack("<I", cpu.properties["reg"])[0] for cpu in cpus]
        assert actual == affinities
        assert [cpu.properties["state"] for cpu in cpus] == [b"running\0"]+[b"waiting\0"]*7
        assert parsed.at("/psci").properties["method"] == b"smc\0"
        gic = hardware["gic"]
        regions = struct.unpack("<QQQQ", parsed.at("/arm-io/intc").properties["reg"])
        bus = struct.unpack("<QQQ", parsed.at("/arm-io").properties["ranges"])
        assert (bus[1]+regions[0]-bus[0], regions[1]) == tuple(gic["distributor"][k] for k in ("base", "size"))
        assert (bus[1]+regions[2]-bus[0], regions[3]) == tuple(gic["redistributor"][k] for k in ("base", "size"))
        assert struct.unpack("<Q", parsed.at("/arm-io/intc").properties["redistributor-stride"])[0] == 0x20000
        report.update(adt_sha256=sha(adt), packed_adt_checked=True)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--adt", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = audit(a.adt)
    a.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result, indent=2))
