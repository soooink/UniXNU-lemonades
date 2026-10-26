#!/usr/bin/env python3
"""Compile the VerifiedRoot XNU provider and its root policies.

Two modes:

  default     both full policies (header + signature + per-4K hash table) are
              embedded in __DATA_CONST. This is the host-qualified profile.

  --external  the kernel carries only the owner public key (395 bytes) and a
              writable policy table; the signed envelopes are read from the
              userdata image at boot. Needed on handsets whose boot partition
              cannot carry the ~70 MiB of hash tables (OnePlus 9R: 96 MiB
              total). The trust anchor is unchanged: every envelope must
              verify against the key compiled here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from build_lemonades_native_ufs import ROOT, TREE, UP, compile_from

KEY = ROOT / "root-policy/trusted-key.bin"


def emit_external(out):
    key = KEY.read_bytes()
    assert len(key) == 395 and key[:8] == b"VROOTKEY", f"unexpected key size {len(key)}"
    assembly = f'''
.section __DATA_CONST,__const
.balign 8
.globl _verified_root_key
_verified_root_key:
.incbin "{KEY}"
.balign 8
.section __DATA,__data
.balign 8
.globl _verified_root_policy_count
_verified_root_policy_count:
.quad 0
.balign 8
.globl _verified_root_policies
_verified_root_policies:
.space {16 * 16}
'''
    (out/"inputs.S").write_text(assembly)
    return {"mode": "external-manifests", "policies": 0,
            "trusted_key_sha256": hashlib.sha256(key).hexdigest()}


def emit_embedded(out):
    policy = ROOT / "out/lemonades/root-policy"
    reports = json.loads((policy/"policies.json").read_text())
    assert reports["status"] == "host_verified_owner_integrity_policies"
    keys = []
    for name in ("OS", "SystemOS"):
        p = policy/name
        report = json.loads((p/"verification.json").read_text())
        assert report["real_c_signature_and_block_verification"]
        assert hashlib.sha256((p/"manifest.bin").read_bytes()).hexdigest() == report["manifest_sha256"]
        key = (p/"trusted-key.bin").read_bytes()
        assert hashlib.sha256(key).hexdigest() == report["trusted_key_sha256"]
        keys.append(key)
    assert keys[0] == keys[1]
    media = ROOT / "out/lemonades-xnu/lemonades/userdata"
    disk = json.loads((media/"userdata-root.json").read_text())
    os = next(w for w in disk["windows"] if w["name"] == "OS")
    count = (os["size"] + 4095)//4096
    indices = [0, 1, count//2, count-1]
    lengths = []
    with Path(disk["image"]).open("rb") as stream, (out/"samples.bin").open("wb") as selected:
        for i in indices:
            n = min(4096, os["size"] - i*4096)
            stream.seek(os["offset"] + i*4096)
            data = stream.read(n)
            assert len(data) == n
            selected.write(data + bytes(4096 - n))
            lengths.append(n)
    assert lengths == [4096, 4096, 4096, 1536]
    manifest = policy/"OS/manifest.bin"
    extra = policy/"SystemOS/manifest.bin"
    assembly = f'''
.section __DATA_CONST,__const
.balign 8
.globl _verified_root_manifest, _verified_root_manifest_bytes
_verified_root_manifest:
.incbin "{manifest}"
_verified_root_manifest_bytes:
.quad . - _verified_root_manifest
.globl _verified_root_key
_verified_root_key:
.incbin "{policy/"OS/trusted-key.bin"}"
.balign 8
.globl _verified_root_sample_indices, _verified_root_sample_lengths, _verified_root_samples
_verified_root_sample_indices:
.quad {",".join(map(str, indices))}
_verified_root_sample_lengths:
.quad {",".join(map(str, lengths))}
_verified_root_samples:
.incbin "{out/"samples.bin"}"
.balign 8
.globl _verified_root_systemos_manifest, _verified_root_policies, _verified_root_policy_count
_verified_root_systemos_manifest:
.incbin "{extra}"
.balign 8
_verified_root_policies:
.quad _verified_root_manifest, {manifest.stat().st_size}
.quad _verified_root_systemos_manifest, {extra.stat().st_size}
_verified_root_policy_count:
.quad 2
'''
    (out/"inputs.S").write_text(assembly)
    return {"mode": "embedded-manifests", "policies": 2,
            "manifest_bytes": reports["manifest_bytes"],
            "policy_report_sha256": hashlib.sha256((policy/"policies.json").read_bytes()).hexdigest(),
            "sample_indices": indices, "sample_lengths": lengths}


def compile_bundle(out):
    rec = TREE/"build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o.json"
    record = json.loads(rec.read_text().strip().rstrip(","))
    sources = [UP/"kits/VerifiedRoot/src/verified_root.c",
               UP/"kits/VerifiedRoot/adapters/xnu_crypto.c",
               UP/"scripts/qemu-entry/verified-root-probe.c"]
    objects = []
    for source in sources:
        obj = out/(source.stem + ".o")
        compile_from(record, source, obj, ["-I", str(UP/"kits/VerifiedRoot/include")])
        objects.append(obj)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-ios17.0", "-isysroot", sdk,
                    "-c", str(out/"inputs.S"), "-o", str(out/"inputs.o")], check=True)
    objects.append(out/"inputs.o")
    archive = out/"libVerifiedRootProbe.a"
    archive.unlink(missing_ok=True)
    subprocess.run(["xcrun", "ar", "rcs", str(archive), *map(str, objects)], check=True)
    return archive, sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external", action="store_true",
                        help="only the owner key; the envelopes are read from the userdata image")
    args = parser.parse_args()
    out = TREE/"build/lemonades-root-policy"
    out.mkdir(parents=True, exist_ok=True)
    result = emit_external(out) if args.external else emit_embedded(out)
    archive, sources = compile_bundle(out)
    result.update({"archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                   "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in [*sources, Path(__file__)]},
                   "apple_signature_claim": False, "runtime_verified": False})
    (out/"build-report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Built VerifiedRoot bundle ({result['mode']}): {archive}")


if __name__ == "__main__":
    main()
