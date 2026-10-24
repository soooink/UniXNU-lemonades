#!/usr/bin/env python3
"""Qualify real init-exec entry/ENOENT and an unchanged XNU panic branch."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.file_digest(p.open("rb"), "sha256").hexdigest()


def main():
    kernel = ROOT / "out/lemonades-xnu/lemonades/kernel/qemu-exec-retry-trace.macho"
    build = json.loads(kernel.with_suffix(".source-build.json").read_text())
    assert build["trust_cache_runtime"] and build["owner_root"] == "trust"
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        row = line.split()
        if len(row) == 3:
            symbols[row[2]] = int(row[0], 16)
    ordered = sorted((v, k) for k, v in symbols.items())
    def resolve(a):
        return max((row for row in ordered if row[0] <= a-4))[1]
    evidence, cases = {}, {}
    for case, folder in (("entry", "44-exec-record-control"),
                         ("panic", "45-exec-panic-control"),
                         ("enoent", "46-exec-retry-observation")):
        run = ROOT / "out/lemonades-qemu" / folder
        d = json.loads((run / "gdb-stop.json").read_text())
        p = json.loads((run / "provenance.json").read_text())
        assert d["kernel_sha256"] == p["kernel_sha256"] == sha(kernel)
        assert not d["bounded_timeout_interrupted"] and d["qemu_accelerator"] == "tcg"
        assert not p["guest_memory_patched"] and not p["vmm_property_declared"]
        assert p["root_input"]["read_only"] and p["trustcache_sha256"] == "7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7"
        def read(name, n):
            return struct.unpack("<"+"Q"*n, bytes.fromhex(d["memory"][f"{symbols[name]:#x}:{n*8:x}"]))
        v = read("_lemonades_exec_trace_observation", 20)
        root = read("_lemonades_owner_root_observation", 18)
        assert v[0] == 1 and root[:6] == (2, 1, 80, 1, 1, 1)
        assert root[6] == root[7] == root[8] != 0
        seen = read("_lemonades_exec_trace_seen", 1)[0]
        assert seen & (1 << 6)
        if case == "panic":
            assert v[1] == 5 and 4 <= v[8] <= 11 and "lemonades-lock-test=1" in p["boot_args"]
            assert int(d["pc"], 16) == symbols["_ml_panic_trap_to_debugger"]
            frames = [resolve(a) for a in v[9:9+v[8]]]
            assert "_panic_trap_to_debugger" in frames and "_lemonades_lock_failure_selftest" in frames
            assert read("_lemonades_lock_failure_observation", 64)[0] == 1
            cases[case] = {"observation": v, "frames": frames}
        else:
            assert d["function_return_stack_matched"] and "lemonades-lock-test" not in p["boot_args"]
            assert read("_lemonades_lock_failure_observation", 64) == (0,)*64
            if case == "entry":
                assert v[1] == 0x10 and v[5] == 1 and v[2] >= 0xffff000000000000
                assert d["function_entry_arguments"][0] == "0x10"
            else:
                assert v[1:3] == (0x20, 2)
            cases[case] = {"observation": v, "recorder_returned_to_original_code": True}
        for f in run.iterdir():
            if f.is_file():
                evidence[str(f.relative_to(ROOT))] = sha(f)
    for suffix in (".json", ".source-build.json", ".provenance.json"):
        f = kernel.with_suffix(suffix)
        evidence[str(f.relative_to(ROOT))] = sha(f)
    for n in ("tools/lemonades_exec_trace.py", "tools/check_lemonades_exec_trace_qemu.py", "tools/test_lemonades_exec_trace.py"):
        evidence[n] = sha(ROOT/n)
    result = {"status": "passed_real_exec_entry_error_and_panic_recording", "kernel": str(kernel),
              "kernel_sha256": sha(kernel), "device_sources": build["execution_trace"],
              "evidence_files": evidence, "cases": cases, "root_writer_config_include_fixed": True,
              "kernel_fault_retry_branch_runtime_qualified": False, "el0_execution_proved": False,
              "root_policy_changed": False, "lock_rule_changed": False}
    (ROOT / "out/lemonades/exec-trace-qemu-baseline.json").write_text(json.dumps(result, indent=2)+"\n")
    print("PASS: real PID 1 exec entry and ENOENT result; recorder returns to unchanged code")
    print("PASS: real XNU lock-guard panic captured with bounded backtrace; ordinary control has no lock failure")


if __name__ == "__main__":
    main()
