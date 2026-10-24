#!/usr/bin/env python3
"""Create a new host workspace for the published bring-up scripts; no device I/O."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--unixnu", type=Path, required=True)
    parser.add_argument("--uefi", type=Path, required=True)
    parser.add_argument("--sheng", type=Path, required=True)
    args = parser.parse_args()
    device = Path(__file__).resolve().parents[1]
    pins = json.loads((device / "source-lock.json").read_text())
    sources = {"UniXNU": args.unixnu, "uefi-lemonades": args.uefi, "UniXNU-sheng": args.sheng}
    resolved = {}
    for name, path in sources.items():
        path = path.resolve(strict=True)
        commit = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        if commit != pins[name]:
            parser.error(f"{name}: expected {pins[name]}, got {commit}")
        resolved[name] = path
    workspace = args.workspace.expanduser().resolve()
    if workspace.exists():
        parser.error("Use a new workspace directory; existing files are never replaced")
    if workspace == device or device in workspace.parents:
        parser.error("Keep the workspace outside the device repository")
    workspace.mkdir(parents=True)
    (workspace / "devices").mkdir()
    (workspace / "devices/lemonades").symlink_to(device, target_is_directory=True)
    (workspace / "sources").mkdir()
    for name, path in resolved.items():
        (workspace / "sources" / name).symlink_to(path, target_is_directory=True)
    for name in ("tools", "tests"):
        shutil.copytree(device / "bringup" / name, workspace / name)
    print(f"Workspace: {workspace}")
    print("Host tools copied; source checkouts linked. Firmware staging writes to the supplied UEFI checkout.")
    print("No images downloaded, partitions written, or hardware tests performed.")


if __name__ == "__main__":
    main()
