#!/usr/bin/env python3
"""Build the official SHNGROOT OS/SystemOS layout without flashing.

Uses upstream IPSW verification and read-only hdiutil attachment. Copies one
whole disk image at a time so the host need not retain both DMGs and both raw
images simultaneously. An interrupted image has no valid manifest and cannot
be mistaken for a completed root image.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"sources/UniXNU/scripts"))
from unixnu.cli import parser as upstream_parser
from unixnu.config import Context
from unixnu.ipsw import Ipsw
from unixnu.userdata import attach,image_size

MIB=1<<20
CHUNK=8*MIB

def hash_window(path,offset,size):
    digest=hashlib.sha256()
    with path.open("rb") as f:
        f.seek(offset)
        while size:
            data=f.read(min(size,CHUNK))
            if not data: raise ValueError("short root image")
            digest.update(data)
            size-=len(data)
    return digest.hexdigest()

def compact_raw_cache(path,expected):
    """Compact only a verified *raw* DMG; round-trip before removing its cache."""
    info=plistlib.loads(subprocess.check_output(["hdiutil","imageinfo","-plist",str(path)]))
    size=path.stat().st_size
    if info["Class Name"]!="CRawDiskImage" or info["Size Information"]["Total Bytes"]!=size:
        raise ValueError("Only byte-identical raw disk image caches may be compacted")
    if hash_window(path,0,size)!=expected: raise ValueError("Input pin mismatch")
    packed=path.with_suffix(path.suffix+".raw.gz")
    partial=packed.with_suffix(".partial")
    if packed.exists() or partial.exists(): raise ValueError("Compressed cache already exists")
    with path.open("rb") as src, partial.open("xb") as dst:
        with gzip.GzipFile(filename="",mode="wb",fileobj=dst,compresslevel=6,mtime=0) as output:
            shutil.copyfileobj(src,output,CHUNK)
        dst.flush()
        os.fsync(dst.fileno())
    digest=hashlib.sha256()
    count=0
    with gzip.open(partial,"rb") as src:
        while data:=src.read(CHUNK):
            digest.update(data); count+=len(data)
    if count!=size or digest.hexdigest()!=expected:
        raise ValueError("Compressed raw input failed round-trip verification")
    partial.rename(packed)
    metadata={"original_sha256":expected,"raw_bytes":size,
        "compressed_sha256":hash_window(packed,0,packed.stat().st_size),
        "imageinfo":info,"round_trip_verified":True}
    packed.with_suffix(".json").write_text(json.dumps(metadata,indent=2)+"\n")
    path.unlink()
    print(f"Compacted verified raw cache: {packed.name}",flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--release-input-cache",action="store_true",
                   help="remove each newly downloaded, hash-verified DMG after its raw window is verified")
    p.add_argument("--compact-systemos-cache",action="store_true",
                   help="gzip the verified raw SystemOS download to reduce temporary disk usage")
    a=p.parse_args()
    board=tomllib.loads((ROOT/"devices/lemonades/board.toml").read_text())
    if a.compact_systemos_cache:
        cache=ROOT/"out/lemonades-xnu/ipsw/21H461/044-76034-038.dmg"
        compact_raw_cache(cache,board["ipsw"]["sha256"][cache.name])
        return
    geometry=board["userdata"]
    assert (geometry["first_lba"],geometry["last_lba"],geometry["lba_bytes"])==(0x2c0000,0x3b51ffa,4096)
    capacity=(geometry["last_lba"]-geometry["first_lba"]+1)*4096
    ctx=Context(upstream_parser().parse_args([
        "build","userdata","-D",str(ROOT/"devices/lemonades"),"--out",str(ROOT/"out/lemonades-xnu")]))
    out=ctx.work/"userdata"
    out.mkdir(parents=True,exist_ok=True)
    image=out/"userdata-root.img"
    partial=out/"userdata-root.img.partial"
    state_path=out/"preparation.json"
    if image.exists(): raise SystemExit("Completed image exists; refusing to overwrite")
    state=json.loads(state_path.read_text()) if state_path.exists() else {
        "format":"SHNGROOT","version":1,"windows":[],"partition_capacity":capacity,
        "upstream_builder_sha256":hashlib.sha256((ROOT/"sources/UniXNU/scripts/unixnu/userdata.py").read_bytes()).hexdigest(),
        "hardware_tested":False,"flash_performed":False}
    if not partial.exists():
        if state["windows"]: raise ValueError("Saved windows without partial image")
        with partial.open("xb") as f: f.truncate(MIB)
    for window in state["windows"]:
        if hash_window(partial,window["offset"],window["size"])!=window["sha256"]:
            raise ValueError("Previously copied window changed")
    cursor=MIB
    if state["windows"]:
        last=state["windows"][-1]
        cursor=last["offset"]+((last["size"]+MIB-1)//MIB)*MIB
    source=Ipsw(ctx)
    with partial.open("r+b") as target:
        target.seek(0)
        if target.read(4096)!=bytes(4096): raise ValueError("Partial image must have an invalid zero manifest")
        target.truncate(cursor)
        for item in geometry["windows"][len(state["windows"]):]:
            member,size,_=source.info(item["component"])
            cache=source.cache/Path(member).name
            packed=cache.with_suffix(cache.suffix+".raw.gz")
            expected=board["ipsw"]["sha256"][cache.name]
            raw_input=False
            if packed.exists():
                metadata=json.loads(packed.with_suffix(".json").read_text())
                if (metadata["original_sha256"]!=expected or not metadata["round_trip_verified"] or
                    metadata["imageinfo"]["Class Name"]!="CRawDiskImage" or
                    metadata["raw_bytes"]!=size or
                    hash_window(packed,0,packed.stat().st_size)!=metadata["compressed_sha256"]):
                    raise ValueError("Compressed raw cache provenance mismatch")
                raw_bytes=size
                dmg=packed
                raw_input=True
            if not cache.exists() and cache.with_suffix(cache.suffix+".partial").exists():
                raise ValueError("Another download is in progress; resume after it completes")
            if not raw_input and not cache.exists() and shutil.disk_usage(out).free<size+2*1024**3:
                raise ValueError("Insufficient host space for the next verified input")
            if not raw_input:
                dmg=source.extract(item["component"])
                if hash_window(dmg,0,dmg.stat().st_size)!=expected:
                    raise ValueError("Cached DMG hash mismatch")
                raw_bytes=image_size(dmg)
            end=cursor+((raw_bytes+MIB-1)//MIB)*MIB
            if end>capacity or raw_bytes<=0 or raw_bytes%512:
                raise ValueError("Invalid root window capacity/alignment")
            if shutil.disk_usage(out).free<raw_bytes+1024**3:
                raise ValueError("Insufficient host space for complete raw window plus 1 GiB reserve")
            print(f"{item['name']}: attaching verified input; copying {raw_bytes} bytes at {cursor:#x}",flush=True)
            device=None if raw_input else attach(dmg)
            digest=hashlib.sha256()
            try:
                handle=gzip.open(dmg,"rb") if raw_input else open(device.replace("/dev/disk","/dev/rdisk"),"rb",buffering=0)
                with handle as raw:
                    target.seek(cursor)
                    done=0
                    while done<raw_bytes:
                        data=raw.read(min(CHUNK,raw_bytes-done))
                        if not data: raise ValueError("Short attached disk read")
                        digest.update(data)
                        if data.count(0)==len(data): target.seek(len(data),1)
                        else: target.write(data)
                        done+=len(data)
                    if raw_input and (raw.read(1) or digest.hexdigest()!=expected):
                        raise ValueError("Raw gzip payload differs from original pinned image")
                    target.truncate(end)
                    target.flush()
                    os.fsync(target.fileno())
            finally:
                if device: subprocess.run(["hdiutil","detach",device],check=True)
            if hash_window(partial,cursor,raw_bytes)!=digest.hexdigest():
                raise ValueError("Copied raw window hash mismatch")
            state["windows"].append({"name":item["name"],"component":item["component"],
                "offset":cursor,"size":raw_bytes,"sha256":digest.hexdigest(),
                "input_member":cache.name,"input_sha256":expected,
                "read_only_attachment":not raw_input,"raw_gzip_input":raw_input,
                "copied_window_rehashed":True})
            state_path.write_text(json.dumps(state,indent=2)+"\n")
            cursor=end
            if a.release_input_cache:
                dmg.unlink() # Only this exact verified download, after verified raw copy.
                print(f"{item['name']}: raw window verified; released downloaded DMG cache",flush=True)
        header=bytearray(4096)
        header[:8]=b"SHNGROOT"
        struct.pack_into("<IIQ",header,8,1,len(state["windows"]),cursor)
        for index,w in enumerate(state["windows"]):
            struct.pack_into("<32sQQII32s40s",header,24+128*index,
                w["name"].encode(),w["offset"],w["size"],512,1,bytes.fromhex(w["sha256"]),bytes(40))
        header[4064:]=hashlib.sha256(header[:4064]).digest()
        target.seek(0)
        target.write(header)
        target.flush()
        os.fsync(target.fileno())
    digest=hash_window(partial,0,cursor)
    partial.rename(image)
    state.update({"image":str(image),"image_bytes":cursor,"image_sha256":digest,
        "manifest_sha256":hashlib.sha256(header).hexdigest(),"status":"built_not_flashed",
        "userdata_bytes":capacity})
    (out/"userdata-root.json").write_text(json.dumps(state,indent=2)+"\n")
    print(json.dumps(state,indent=2))

if __name__=="__main__":
    main()
