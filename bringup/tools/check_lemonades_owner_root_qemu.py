#!/usr/bin/env python3
"""Qualify actual OS mounting, owner-root refusal/acceptance and AES self-tests."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from lemonades_root_trace import FIELDS

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    observations = {}
    evidence = {}
    for case, run_name, mode in (
        ("audit","33-owner-root-audit","audit"),
        ("trust","34-owner-root-trust","trust"),
    ):
        kernel=ROOT/f"out/lemonades-xnu/lemonades/kernel/qemu-owner-root-{case}.macho"
        run=ROOT/"out/lemonades-qemu"/run_name
        data=json.loads((run/"gdb-stop.json").read_text())
        prov=json.loads((run/"provenance.json").read_text())
        source=json.loads(kernel.with_suffix(".source-build.json").read_text())
        assert sha(kernel)==data["kernel_sha256"]==prov["kernel_sha256"]
        assert data["qemu_accelerator"]=="tcg" and not prov["vmm_property_declared"]
        assert not data["bounded_timeout_interrupted"] and not prov["guest_memory_patched"]
        assert source["owner_root"]==mode and source["native_ufs"]
        assert prov["owned_memory_bytes"]==320<<20
        assert prov["root_input"]["read_only"] and data["virtio_block_input"]["read_only"]
        assert prov["root_input"]["offset"]==1048576 and prov["root_input"]["bytes"]==6077580800
        assert prov["root_input"]["sha256"]=="e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2"
        symbols={}
        for line in subprocess.check_output(["xcrun","nm","-n",kernel],text=True).splitlines():
            f=line.split()
            if len(f)==3: symbols[f[2]]=int(f[0],16)
        def read(name,format):
            n=struct.calcsize(format)
            return struct.unpack(format,bytes.fromhex(data["memory"][f"{symbols[name]:#x}:{n:x}"]))
        state=dict(zip(FIELDS,read("_lemonades_owner_root_observation","<18Q")))
        assert state["phase"]==(1 if case=="audit" else 2)
        assert state["trust_enabled"]==state["accepted"]==int(case=="trust")
        assert state["apple_autherr"]==80 and state["owner_decision"]==state["readonly"]==1
        assert state["mount_device"]==state["selected_device"]==state["verified_device"]!=0
        assert state["media_matches"]==state["uuid_match"]==state["wrong_uuid_refused"]==1
        assert state["provider_depth"]==9
        assert state["ufs_published"]==state["ufs_verified_blocks"]==state["ufs_integrity_failures"]==0
        for field in ("_native_aes_kat_status","_native_aes_registered","_native_aes_interface_status"):
            assert read(field,"<I")== (1,)
        verified=read("_native_virtio_verified_blocks","<Q")[0]
        assert verified>=329 and read("_native_virtio_integrity_failures","<I")== (0,)
        uuid=read("_native_verified_block_root_uuid","37s")[0].rstrip(b"\0").decode()
        assert uuid=="04769D26-2CA0-4825-B443-E2E5F88300F2"
        if case=="audit":
            assert int(data["pc"],16)==symbols["_panic"]
            assert data["argument_memory"]["x0"].startswith("rootvp not authenticated after mounting")
        else:
            assert data["function_return_stack_matched"]
            assert [int(v,16) for v in data["function_entry_arguments"][:2]]==[80,1]
        registers={k:int(v,16) for k,v in data["system_registers"].items()}
        assert registers["TCR_EL1"]>>14&3==0 and registers["TCR_EL1"]>>30&3==2
        observations[case]={"kernel_sha256":sha(kernel),"state":state,"verified_blocks":verified,
                            "volume_uuid":uuid,"real_function_return":case=="trust"}
        for p in run.iterdir():
            if p.is_file(): evidence[str(p.relative_to(ROOT))]=sha(p)
        for suffix in (".json",".source-build.json",".provenance.json"):
            p=kernel.with_suffix(suffix); evidence[str(p.relative_to(ROOT))]=sha(p)
    kernel=ROOT/"out/lemonades-xnu/lemonades/kernel/qemu-owner-root-trust.macho"
    source=json.loads(kernel.with_suffix(".source-build.json").read_text())
    screen=json.loads((ROOT/"out/lemonades/screen-qemu-baseline.json").read_text())
    assert screen["kernel_sha256"]==sha(kernel)
    archive=ROOT/"out/lemonades-qemu/34-owner-root-trust-qualification"
    archive.mkdir()
    shutil.copytree(ROOT/"out/lemonades-xnu/lemonades/tree/build/lemonades-storage-providers",archive/"providers")
    inputs=[
        ROOT/"devices/lemonades/scripts/lemonades-root-trace.h",
        ROOT/"devices/lemonades/patches/lemonades-xnu/zzzzzzzz-lemonades-owner-root-trace.patch",
        ROOT/"sources/UniXNU/patches/xnu/offline-owner-root-binding-audit.patch",
        ROOT/"tools/build_lemonades_storage_providers.py",Path(__file__),
    ]
    inputs += [ROOT/n for n in source["storage_providers_build"]["sources"]]
    hashes={str(p.relative_to(ROOT)):sha(p) for p in inputs}
    for p in inputs:
        target=archive/"sources"/p.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(p,target)
    index={str(p.relative_to(archive)):sha(p) for p in archive.rglob("*") if p.is_file()}
    (archive/"sha256.json").write_text(json.dumps(index,indent=2)+"\n")
    result={"status":"passed_real_mounted_owner_root_binding_and_aes",
            "kernel":str(kernel),"kernel_sha256":sha(kernel),
            "observations":observations,"source_archive":str(archive.relative_to(ROOT)),
            "source_archive_index_sha256":sha(archive/"sha256.json"),
            "sources":hashes,"storage_providers_build":source["storage_providers_build"],
            "evidence_files":evidence,"original_apple_authentication_error_preserved":80,
            "qemu_root_mounted":True,"qemu_root_owner_accepted":True,
            "phone_root_mounted":False,"userspace_booted":False}
    (ROOT/"out/lemonades/owner-root-qemu-baseline.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS: real read-only original OS mount; audit refuses, owner binding accepts; AES KAT/interface pass")
    print("PASS: 329+ verified reads, matching mounted device/UUID, wrong UUID refused, no integrity failures")


if __name__=="__main__":
    main()
