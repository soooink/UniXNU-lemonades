#!/usr/bin/env python3
"""Audit the compiled source kernel; does not execute it or claim a hardware boot."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sources/UniXNU/kits/NativePrelink"))
from native_prelink import macho


def audit(path):
    data = path.read_bytes()
    parsed = macho(data)
    if parsed["kind"] != 2:
        raise ValueError("Expected MH_EXECUTE")
    segments = parsed["segments"]
    for segment in segments:
        if segment["filesize"] and segment["fileoff"] + segment["filesize"] > len(data):
            raise ValueError("Segment extends outside the file")
    entries = []
    for command, at, length in parsed["commands"]:
        if command == 5:  # LC_UNIXTHREAD / ARM_THREAD_STATE64
            if length < 288 or struct.unpack_from("<II", data, at + 8) != (6, 68):
                raise ValueError("Unexpected kernel thread state")
            entries.append(struct.unpack_from("<Q", data, at + 272)[0])
    if len(entries) != 1 or not any(
            s["initprot"] & 4 and s["va"] <= entries[0] < s["va"] + s["filesize"]
            for s in segments):
        raise ValueError("Kernel entry is not backed by executable bytes")
    symbols = set(subprocess.check_output(["xcrun", "nm", "-j", path], text=True).splitlines())
    required = {"_source_corecrypto14_bootstrap", "_source_pthread_bootstrap",
                "_armcpu_registered", "_armcpu_gic_ready"}
    if not required <= symbols or not any("ArmDTPlatform" in s for s in symbols):
        raise ValueError("Missing real provider/CPU/platform symbols")
    undefined = subprocess.check_output(["xcrun", "nm", "-u", path], text=True).strip()
    if undefined:
        raise ValueError("Unresolved kernel symbols: " + undefined)
    sections = [section for segment in segments for section in segment["sections"]]
    code = next(s for segment in segments if segment["name"] in ("__TEXT", "__TEXT_EXEC")
                for s in segment["sections"] if s["name"] == "__text")
    fields = [s for s in sections if s["name"] == "__fips_hmacs"]
    if len(fields) != 1 or fields[0]["size"] != 32:
        raise ValueError("Expected one source-provider HMAC field")
    expected = hmac.digest(b"\0", data[code["fileoff"]:code["fileoff"] + code["size"]], "sha256")
    field = fields[0]
    if data[field["fileoff"]:field["fileoff"] + 32] != expected:
        raise ValueError("Source-provider build integrity HMAC mismatch")
    loaded = [s for s in segments if s["size"] and s["name"] != "__PAGEZERO"]
    base = min(s["va"] for s in loaded)
    end = max(s["va"] + s["size"] for s in loaded)
    if end - base > 256 << 20:
        raise ValueError("Kernel alone exceeds the currently planned 256 MiB window")
    return {
        "status": "host_verified", "kernel": str(path.resolve()),
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": "ARM64 (subtype 0)", "file_type": "MH_EXECUTE",
        "entry": hex(entries[0]), "virtual_base": hex(base),
        "virtual_span_bytes": end - base, "segment_count": len(segments),
        "required_provider_symbols": sorted(required), "undefined_symbols": [],
        "source_provider_hmac_verified": True,
        "version_strings": [s.decode() for s in re.findall(rb"Darwin Kernel Version[^\0]{0,300}", data)],
        "prelinked": False, "hardware_tested": False, "runtime_crypto_selftests": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.kernel)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
