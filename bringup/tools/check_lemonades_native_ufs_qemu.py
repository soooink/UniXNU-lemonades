#!/usr/bin/env python3
"""Qualify actual kernel crypto and hardware exclusion, not a root mount."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"out/lemonades"
TREE=ROOT/"out/lemonades-xnu/lemonades/tree"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    kernel=ROOT/"out/lemonades-xnu/lemonades/kernel/qemu-native-ufs-trace.macho"
    crypto=ROOT/"out/lemonades-qemu/25-native-ufs-policy"
    screen=ROOT/"out/lemonades-qemu/26-native-ufs-screen"
    names={}
    for line in subprocess.check_output(["xcrun","nm","-n",kernel],text=True).splitlines():
        row=line.split()
        if len(row)==3:names[row[2]]=int(row[0],16)
    def run(path):
        data=json.loads((path/"gdb-stop.json").read_text())
        prov=json.loads((path/"provenance.json").read_text())
        assert data["kernel_sha256"]==prov["kernel_sha256"]==sha(kernel)
        assert not data["bounded_timeout_interrupted"] and not prov["vmm_property_declared"]
        assert data["qemu_accelerator"]=="tcg"
        return data
    def read(data,name,format):
        count=struct.calcsize(format)
        return struct.unpack(format,bytes.fromhex(data["memory"][f"{names[name]:#x}:{count:x}"]))
    c=run(crypto);s=run(screen)
    assert int(c["pc"],16)==names["_native_verified_root_checkpoint"]
    assert read(c,"_native_verified_root_status","<I")== (1,)
    assert read(c,"_native_verified_root_results","<8I")== (0,4,3,3,4,5,2,1)
    assert read(c,"_native_verified_root_signature_calls","<I")== (4,)
    assert read(c,"_native_verified_root_block_count","<Q")== (1483785,)
    assert int(s["pc"],16)==names["_lemonades_boot_progress_checkpoint_eight"]
    state=read(s,"_lemonades_native_ufs_observation","<32Q")
    assert state[:9]==(4,0,0,1,1,0,0,0,0)
    assert state[13:16]==(0,0,0) and state[17:23]==(0,0,0,0,0,0)
    assert json.loads((screen/"provenance.json").read_text())["owned_memory_bytes"]==320<<20
    display=json.loads((OUT/"screen-qemu-baseline.json").read_text())
    assert display["kernel_sha256"]==sha(kernel)
    source=json.loads(kernel.with_suffix(".source-build.json").read_text())
    build=source["native_ufs_build"]; bundle=source["root_policy_build"]
    assert not build["disk_write_path"] and build["profile"]=="qemu"
    assert build["bindings"]["virtual_methods_checked"]==190
    for name,value in build["device_sources"].items(): assert sha(ROOT/name)==value
    for name,value in build["upstream_sources"].items(): assert sha(ROOT/"sources/UniXNU"/name)==value
    for name,value in bundle["source_sha256"].items(): assert sha(ROOT/name)==value
    archive=screen.with_name(screen.name+"-storage-sources")
    archive.mkdir()
    shutil.copytree(TREE/"build/native-ufs",archive/"native-ufs")
    shutil.copytree(TREE/"build/lemonades-root-policy",archive/"root-policy")
    assert sha(archive/"native-ufs/libNativeUfs.a")==build["archive_sha256"]
    assert sha(archive/"root-policy/libVerifiedRootProbe.a")==bundle["archive_sha256"]
    shutil.copyfile(OUT/"storage-abi/interface-audit.json",archive/"interface-audit.json")
    shutil.copyfile(Path(__file__),archive/Path(__file__).name)
    index={str(p.relative_to(archive)):sha(p) for p in sorted(archive.rglob("*")) if p.is_file()}
    (archive/"sha256.json").write_text(json.dumps(index,indent=2)+"\n")
    result={"status":"passed_native_ufs_abi_crypto_and_hardware_exclusion",
        "kernel":str(kernel),"kernel_sha256":sha(kernel),
        "source_archive":str(archive.relative_to(ROOT)),"source_archive_index_sha256":sha(archive/"sha256.json"),
        "native_ufs_build":build,"root_policy_build":bundle,
        "real_xnu_crypto_results":list(read(c,"_native_verified_root_results","<8I")),
        "qemu_ufs_observation":list(state),
        "evidence_files":{str(p.relative_to(ROOT)):sha(p) for folder in (crypto,screen)
                          for p in sorted(folder.iterdir()) if p.is_file()},
        "hardware_tested":False,"root_mounted":False,"userspace_booted":False}
    (OUT/"native-ufs-qemu-baseline.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS: actual XNU crypto/negative controls, NativeUfs ABI, QEMU hardware exclusion, 320 MiB boot and live screen")

if __name__=="__main__":main()
