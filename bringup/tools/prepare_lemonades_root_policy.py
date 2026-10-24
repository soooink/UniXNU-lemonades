#!/usr/bin/env python3
"""Build and independently verify the official owner-integrity policies for lemonades."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[1]
UP=ROOT/"sources/UniXNU/kits/VerifiedRoot"
OUT=ROOT/"out/lemonades/root-policy"
MEDIA=ROOT/"out/lemonades-xnu/lemonades/userdata"

class Window:
    def __init__(self,path,offset,length):
        self.stream=path.open("rb")
        self.stream.seek(offset)
        self.left=length
    def read(self,count):
        data=self.stream.read(min(count,self.left))
        self.left-=len(data)
        return data
    def close(self): self.stream.close()

class View(ctypes.Structure):
    _fields_=[("hashes",ctypes.c_void_p),("image_bytes",ctypes.c_uint64),
              ("block_count",ctypes.c_uint64),("generation",ctypes.c_uint64),
              ("volume_uuid",ctypes.c_uint8*16),("image_sha256",ctypes.c_uint8*32)]

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    host=OUT/"host"
    with (OUT/"host-tests.log").open("w") as log:
        subprocess.run(["python3",str(UP/"tests/check.py"),"--output",str(host),
                        "--openssl-prefix","/opt/homebrew/opt/openssl@3"],
                        check=True,stdout=log,stderr=subprocess.STDOUT)
    spec=importlib.util.spec_from_file_location("manifest",UP/"tools/manifest.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    native=ctypes.CDLL(str(host/"verified-root.dylib"))
    native.vr_host_open.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,
                                ctypes.c_uint64,ctypes.POINTER(View)]
    native.vr_host_block.argtypes=[ctypes.POINTER(View),ctypes.c_uint64,
                                 ctypes.c_void_p,ctypes.c_size_t]
    media=json.loads((MEDIA/"userdata-root.json").read_text())
    reports=[]
    for w in media["windows"]:
        infos=json.loads((MEDIA/(w["name"]+"-volume-info.json")).read_text())
        volumes=[d for d in infos if d.get("FilesystemType")=="apfs" and d.get("VolumeUUID")]
        assert len(volumes)==1 and volumes[0]["Writable"] is False
        identity=uuid.UUID(volumes[0]["VolumeUUID"])
        out=OUT/w["name"];out.mkdir(exist_ok=True)
        stream=Window(Path(media["image"]),w["offset"],w["size"])
        try:
            record=module.make(stream,w["size"],host/"keys/owner.pem",
                host/"keys/owner-public.pem",identity,1,out)
        finally:stream.close()
        assert record["image_sha256"]==w["sha256"]
        encoded=ctypes.create_string_buffer((out/"manifest.bin").read_bytes())
        key=ctypes.create_string_buffer((out/"trusted-key.bin").read_bytes())
        view=View()
        assert native.vr_host_open(encoded,len(encoded)-1,key,1,ctypes.byref(view))==0
        assert bytes(view.volume_uuid)==identity.bytes and view.image_bytes==w["size"]
        stream=Window(Path(media["image"]),w["offset"],w["size"])
        complete=hashlib.sha256()
        try:
            for index in range(view.block_count):
                block=stream.read(4096)
                assert native.vr_host_block(ctypes.byref(view),index,block,len(block))==0,index
                complete.update(block)
            assert not stream.read(1)
        finally:stream.close()
        assert complete.hexdigest()==w["sha256"] and complete.digest()==bytes(view.image_sha256)
        result={**record,"name":w["name"],"blocks_verified":view.block_count,
                "real_c_signature_and_block_verification":True,
                "root_image_offset":w["offset"],
                "manifest_sha256":hashlib.sha256((out/"manifest.bin").read_bytes()).hexdigest(),
                "hardware_tested":False,"root_mounted":False}
        (out/"verification.json").write_text(json.dumps(result,indent=2)+"\n")
        reports.append(result)
        print(f"{w['name']}: RSA envelope and {view.block_count} real 4 KiB blocks verified",flush=True)
    assert (OUT/"OS/trusted-key.bin").read_bytes()==(OUT/"SystemOS/trusted-key.bin").read_bytes()
    result={"status":"host_verified_owner_integrity_policies","windows":reports,
        "source_sha256":{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (UP/"tools/manifest.py",UP/"src/verified_root.c",UP/"tests/openssl_provider.c",Path(__file__))},
        "manifest_bytes":sum((OUT/w["name"]/"manifest.bin").stat().st_size for w in media["windows"]),
        "apple_signature_claim":False,"hardware_tested":False,"root_mounted":False}
    (OUT/"policies.json").write_text(json.dumps(result,indent=2)+"\n")

if __name__=="__main__": main()
