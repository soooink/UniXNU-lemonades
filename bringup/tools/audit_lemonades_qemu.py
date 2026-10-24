#!/usr/bin/env python3
"""Check the saved QEMU experiments and write a scoped runtime qualification."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "out/lemonades-qemu"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(name):
    folder = RUNS / name
    provenance = json.loads((folder / "provenance.json").read_text())
    report = json.loads((folder / "gdb-stop.json").read_text())
    for filename, digest in provenance["esp_sha256"].items():
        require(sha(folder / "esp" / filename) == digest, f"{name}: changed ESP {filename}")
    require(report["kernel_sha256"] == provenance["kernel_sha256"], f"{name}: kernel mismatch")
    require(report["boot_path"] == "uefi-unixnu-darwinboot", f"{name}: wrong boot path")
    return provenance, report


def returned(report):
    return (report.get("finished_function_entry") is not None
            and report.get("function_return_stack_matched") is True
            and report["pc"] == report.get("function_return_target")
            and not report["bounded_timeout_interrupted"])


def main():
    names = ["01-raw-assert", "02-raw-budget120", "03-prelink-bootstrap",
             "05-prelink-platform-policy", "06-prelink-tcg-platform",
             "07-prelink-root-boundary"]
    runs = {n: load(n) for n in names}
    original_p, original = runs[names[0]]
    fixed_p, fixed = runs[names[1]]
    require(original_p["kernel_sha256"] == fixed_p["kernel_sha256"],
            "budget comparison must use byte-identical kernels")
    require(original["pc"] == original_p["stop_address"]
            and original["argument_memory"].get("x0") == "kalloc.c"
            and int(original["x1"], 16) == 1779
            and original["argument_memory"].get("x2") ==
            "n_zones_sig + n_zones_type + 1 <= 32", "original assertion not reproduced")
    require(returned(fixed), "budget fix did not return from vm_mem_bootstrap")
    require(list(original["memory"].values()) == ["0401"]
            and list(fixed["memory"].values()) == ["7800"],
            "expected measured zone budgets 260 and 120")
    require(returned(runs[names[2]][1]), "prelink did not return from vm_mem_bootstrap")
    kernel = ROOT / "out/lemonades-xnu/lemonades/kernel/kernel.macho"
    prelink = json.loads(kernel.with_suffix(".json").read_text())
    digest = sha(kernel)
    require(digest == prelink["candidate_sha256"], "prelink candidate changed")
    require(prelink["source_inputs_modified"] is False
            and len(prelink["original_executable_sha256"]) == len(prelink["components"]),
            "missing original component code preservation audit")
    for name in names[2:]:
        require(runs[name][0]["kernel_sha256"] == digest, f"{name}: different prelink kernel")
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    _, runtime = runs["06-prelink-tcg-platform"]
    def read(name, size):
        address = f"0x{symbols[name]:x}:{size:x}"
        return int.from_bytes(bytes.fromhex(runtime["memory"][address]), "little")
    observed = {n: read(n, size) for n, size in [
        ("_armdt_platform_configured", 4), ("_armcpu_registered", 4),
        ("_armcpu_gic_ready", 4), ("_armcpu_timer_interrupts", 8),
        ("_g_crypto_funcs", 8), ("_crypto_init", 1), ("_prng_ready", 4),
        ("_page_shift", 4), ("_page_size", 8)]}
    for name in ("_armdt_platform_configured", "_armcpu_registered",
                 "_armcpu_gic_ready", "_crypto_init", "_prng_ready"):
        require(observed[name] == 1, f"{name} not initialized")
    require(observed["_armcpu_timer_interrupts"] > 0, "no real timer interrupt observed")
    pointer = observed["_g_crypto_funcs"]
    require(any(e["module"] == "com.apple.kec.corecrypto"
                and e["va"] <= pointer < e["va"] + e["size"]
                for e in prelink["extents"]), "crypto table not owned by original corecrypto")
    tcr = int(runtime["system_registers"]["TCR_EL1"], 16)
    require((tcr >> 14) & 3 == 0 and (tcr >> 30) & 3 == 2
            and observed["_page_shift"] == 12 and observed["_page_size"] == 4096,
            "actual 4 KiB translation not demonstrated")
    root_p, root = runs["07-prelink-root-boundary"]
    require(root["pc"] == root_p["stop_address"] and not root["bounded_timeout_interrupted"],
            "root-search boundary not reached")
    result = {
        "status": "passed_scoped_runtime_checks", "kernel_sha256": digest,
        "components": prelink["components"], "original_code_preserved": True,
        "assertion_reproduced": "kalloc.c:1779 n_zones_sig + n_zones_type + 1 <= 32",
        "fix": "kt_fixed_zones=120", "source_kernel_memory_bootstrap_returned": True,
        "prelinked_kernel_memory_bootstrap_returned": True,
        "qemu_platform_cpu_and_timer_observed": True,
        "original_corecrypto_initialized": True, "actual_translation_page_bytes": 4096,
        "root_search_function_reached": "_IOFindBSDRoot",
        "observed_tcg_globals": {k: hex(v) if k == "_g_crypto_funcs" else v
                                 for k, v in observed.items()},
        "run_evidence": {n: {f: sha(RUNS / n / f)
                             for f in ("provenance.json", "gdb-stop.json", "gdb-uart.log")}
                         for n in names},
        "limits": [
            "QEMU platform verification does not qualify Xiaomi GIC or timer MMIO.",
            "No root disk is attached; root mounting and userland were not tested.",
            "The prelinked candidate has not been booted on the phone.",
            "45-second bounded runs ending in idle are not long-term stability tests.",
        ],
    }
    target = ROOT / "out/lemonades/qemu-baseline.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: assertion comparison, prelink, crypto, 4 KiB MMU, timer and root boundary; {target}")


if __name__ == "__main__":
    main()
