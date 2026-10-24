#!/usr/bin/env python3
"""Check the real lock failure recorder and an ordinary mounted-root control."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    kernel=ROOT/"out/lemonades-xnu/lemonades/kernel/qemu-lock-trace.macho"
    symbols={}
    for line in subprocess.check_output(["xcrun","nm","-n",kernel],text=True).splitlines():
        row=line.split()
        if len(row)==3:symbols[row[2]]=int(row[0],16)
    names=sorted((v,k) for k,v in symbols.items())
    def resolve(address):
        return max((row for row in names if row[0]<=address-4),default=(0,"unknown"))[1]
    evidence={}
    cases={}
    for case,folder in (("failure","36-lock-failure-trace"),("normal","37-lock-normal-root-control")):
        run=ROOT/"out/lemonades-qemu"/folder
        d=json.loads((run/"gdb-stop.json").read_text())
        p=json.loads((run/"provenance.json").read_text())
        assert d["kernel_sha256"]==p["kernel_sha256"]==sha(kernel)
        assert not d["bounded_timeout_interrupted"] and d["function_return_stack_matched"]
        assert d["qemu_accelerator"]=="tcg" and not p["vmm_property_declared"]
        assert not p["guest_memory_patched"] and p["root_input"]["read_only"]
        def read(symbol,count):
            return struct.unpack("<"+"Q"*count,bytes.fromhex(d["memory"][f"{symbols[symbol]:#x}:{count*8:x}"]))
        lock=read("_lemonades_lock_failure_observation",64)
        root=read("_lemonades_owner_root_observation",18)
        assert root[:6]==(2,1,80,1,1,1)
        assert root[6]==root[7]==root[8]!=0 and root[9:13]==(1,9,1,1)
        if case=="failure":
            assert "lemonades-lock-test=1" in p["boot_args"]
            assert lock[0]==1 and lock[1]>=0xffff000000000000
            assert lock[3:6]==(0,0,0) and lock[8]==16 and 4<=lock[9]<=48
            frames=[resolve(a) for a in lock[10:10+lock[9]]]
            assert "_lck_rw_lock_shared" in frames and "_lemonades_lock_failure_selftest" in frames
            assert "_native_owner_root_accepted_checkpoint" in frames and lock[58]>0
            cases[case]={"observation":list(lock),"frame_symbols":frames}
        else:
            assert "lemonades-lock-test" not in p["boot_args"] and lock==tuple([0]*64)
            assert [int(v,16) for v in d["function_entry_arguments"][:2]]==[80,1]
            cases[case]={"owner_root":list(root),"lock_failure_observation_zero":True}
        for f in run.iterdir():
            if f.is_file():evidence[str(f.relative_to(ROOT))]=sha(f)
    inputs=("devices/lemonades/scripts/lemonades-lock-trace.h",
            "devices/lemonades/patches/lemonades-xnu/zzzzzzzzz-lemonades-lock-trace.patch")
    for suffix in (".json",".source-build.json",".provenance.json"):
        p=kernel.with_suffix(suffix);evidence[str(p.relative_to(ROOT))]=sha(p)
    result={"status":"passed_original_lock_failure_backtrace_and_normal_root_control",
            "kernel":str(kernel),"kernel_sha256":sha(kernel),"cases":cases,
            "device_sources":{p:sha(ROOT/p) for p in inputs},
            "evidence_files":evidence,"phone_failure_reproduced":False,
            "lock_rule_modified":False,"root_owner_policy_modified":False}
    (ROOT/"out/lemonades/lock-trace-qemu-baseline.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS: original non-sleepable-lock guard captures actual state and bounded call stack")
    print("PASS: default control still mounts and accepts the original OS; no lock diagnostic event")


if __name__=="__main__":
    main()
