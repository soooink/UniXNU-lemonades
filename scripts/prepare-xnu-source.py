#!/usr/bin/env python3
"""Restore the upstream recipe's omitted headers from pinned Git objects."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ("xnu-driverkit", "2c2f96dc2b9a4408a43d3150ae9c105355ca3daa",
     "xnu-10063.121.3", "iokit/DriverKit"),
    ("xnu-trustcache", "aca3beaa3dfbd42498b42c5e5ce20a938e6554e5",
     "xnu-8796.101.5", "EXTERNAL_HEADERS/TrustCache"),
)


def main():
    # This hook runs after the upstream patch series. Keep our optional-driver
    # fix separate, so the pinned upstream patch module is not replaced.
    work = ROOT / ".cache/xnu-work"
    for patch in sorted((ROOT / "patches/lemonades-xnu").glob("*.patch")):
        reverse = subprocess.run(["git", "-C", work, "apply", "--reverse", "--check", patch],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if reverse.returncode:
            subprocess.run(["git", "-C", work, "apply", "--check", patch], check=True)
            subprocess.run(["git", "-C", work, "apply", patch], check=True)
    trace = os.environ.get("LEMONADES_EARLY_TRACE", "0")
    if trace not in ("0", "1"):
        raise ValueError("LEMONADES_EARLY_TRACE must be 0 or 1")
    pmgr = os.environ.get("LEMONADES_PMGR", "0")
    if pmgr not in ("0", "1"):
        raise ValueError("LEMONADES_PMGR must be 0 or 1")
    ufs = os.environ.get("LEMONADES_UFS_PROBE", "0")
    if ufs not in ("0", "1"):
        raise ValueError("LEMONADES_UFS_PROBE must be 0 or 1")
    trace_files = {
        "lemonades_early_trace_config.h": f"#define LEMONADES_EARLY_TRACE {trace}\n".encode(),
        "lemonades_platform_power_config.h": f"#define LEMONADES_PMGR {pmgr}\n".encode(),
        "lemonades_ufs_config.h": f"#define LEMONADES_UFS_PROBE {ufs}\n".encode(),
        "lemonades-early-trace.inc": (ROOT / "scripts/lemonades-early-trace.inc").read_bytes(),
        "lemonades-root-trace.h": (ROOT / "scripts/lemonades-root-trace.h").read_bytes(),
        "lemonades-lock-trace.h": (ROOT / "scripts/lemonades-lock-trace.h").read_bytes(),
        "lemonades-exec-trace.h": (ROOT / "scripts/lemonades-exec-trace.h").read_bytes(),
        "lemonades-userspace-api.h": (ROOT / "scripts/lemonades-userspace-api.h").read_bytes(),
    }
    for name, data in trace_files.items():
        target = work / "osfmk/arm64" / name
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
    records = []
    for name, commit, tag, prefix in SOURCES:
        source = ROOT / "refer" / name
        head = subprocess.check_output(
            ["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()
        if head != commit:
            raise SystemExit(f"Unexpected header source revision: {name}: {head}")
        headers = sorted(source.rglob("*.h"))
        if not headers:
            raise SystemExit(f"Missing pinned headers: {source}")
        for header in headers:
            relative = header.relative_to(source)
            git_path = f"{prefix}/{relative.as_posix()}"
            data = subprocess.check_output(["git", "-C", source, "show", f"HEAD:{git_path}"])
            if header.read_bytes() != data:
                raise SystemExit(f"Modified reference header: {header}")
            target = ROOT / ".cache/xnu-work" / git_path
            existed = target.exists()
            if not existed:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            # Like upstream, retain any header already present in the XNU work tree.
            records.append({
                "name": git_path, "source_tag": tag, "source_commit": commit,
                "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "installed_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "already_present": existed,
            })
    out = ROOT / ".cache/sources/xnu-restored-headers.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, indent=2) + "\n")
    print(f"Prepared {len(records)} pinned public headers through Git; no GitHub API required")


if __name__ == "__main__":
    main()
