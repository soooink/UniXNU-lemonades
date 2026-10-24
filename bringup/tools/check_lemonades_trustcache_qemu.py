#!/usr/bin/env python3
"""Qualify initialized trust caches at the original launchd AMFI query."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    kernel=ROOT/"out/lemonades-xnu/lemonades/kernel/qemu-trustcache-runtime.macho"
    run=ROOT/"out/lemonades-qemu/38-trustcache-query"
    d=json.loads((run/"gdb-stop.json").read_text())
    p=json.loads((run/"provenance.json").read_text())
    build=json.loads(kernel.with_suffix(".source-build.json").read_text())
    assert d["kernel_sha256"]==p["kernel_sha256"]==sha(kernel)
    assert build["trust_cache_runtime"] and build["owner_root"]=="trust"
    assert not d["bounded_timeout_interrupted"] and d["function_return_stack_matched"]
    assert d["x0"]=="0x0" and d["qemu_accelerator"]=="tcg"
    assert not p["guest_memory_patched"] and not p["vmm_property_declared"]
    assert p["trustcache_sha256"]=="7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7"
    symbols={}
    for line in subprocess.check_output(["xcrun","nm","-n",kernel],text=True).splitlines():
        row=line.split()
        if len(row)==3:symbols[row[2]]=int(row[0],16)
    def read(name,n):
        return bytes.fromhex(d["memory"][f"{symbols[name]:#x}:{n:x}"])
    assert read("_trust_cache_static_init",1)==read("_trust_cache_static_loaded",1)==b"\1"
    lock=read("_trust_cache_rt_lock",16)
    assert struct.unpack_from("<I",lock)[0]!=0
    assert read("_lemonades_lock_failure_observation",512)==bytes(512)
    root=struct.unpack("<18Q",read("_lemonades_owner_root_observation",144))
    assert root[:6]==(2,1,80,1,1,1) and root[6]==root[7]==root[8]!=0
    traced={int(e["pc"],16) for e in d["trace_events"]}
    assert symbols["_trust_cache_runtime_init"] in traced and symbols["_load_init_program"] in traced
    plan=json.loads(kernel.with_suffix(".json").read_text())
    pc=int(d["pc"],16)
    assert any(e["module"]=="com.apple.driver.AppleMobileFileIntegrity" and
               e["segment"]=="__TEXT_EXEC" and e["va"]<=pc<e["va"]+e["size"] for e in plan["extents"])
    inputs=json.loads((ROOT/"out/lemonades/trustcache/inputs.json").read_text())
    assert sha(Path(inputs["bundle"]))==p["trustcache_sha256"]
    evidence={str(f.relative_to(ROOT)):sha(f) for f in run.iterdir() if f.is_file()}
    for suffix in (".json",".provenance.json",".source-build.json"):
        f=kernel.with_suffix(suffix);evidence[str(f.relative_to(ROOT))]=sha(f)
    for f in (ROOT/"out/lemonades/trustcache/inputs.json",Path(inputs["bundle"]),ROOT/"tools/prepare_lemonades_trustcache.py"):
        evidence[str(f.relative_to(ROOT))]=sha(f)
    result={"status":"passed_original_amfi_query_with_initialized_target_trust_caches",
            "kernel":str(kernel),"kernel_sha256":sha(kernel),"evidence_files":evidence,
            "trustcache_sha256":p["trustcache_sha256"],"lock_bytes":lock.hex(),
            "query_return":0,"returned_to_original_amfi":True,
            "root_owner_accepted":True,"user_program_load_reached":True,"el0_execution_proved":False}
    (ROOT/"out/lemonades/trustcache-qemu-baseline.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS: real trust-cache initialization/loading and launchd AMFI query returning success")
    print("PASS: initialized runtime lock, original AMFI continuation, no lock failure event")


if __name__=="__main__":main()
