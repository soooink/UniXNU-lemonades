#!/usr/bin/env python3
"""Check runtime records together with explicit human panel observation."""
import argparse
import hashlib
import json
from pathlib import Path

from decode_lemonades_xnu_trace import decode

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("attempt", type=int)
    p.add_argument("--user-observed-live", action="store_true",
                   help="set only after the user confirms counters keep changing on the panel")
    a = p.parse_args()
    if not a.user_observed_live:
        p.error("Phone panel visibility requires explicit user observation")
    runtime = ROOT / f"out/lemonades/attempt-{a.attempt:02d}-runtime"
    archive = ROOT / f"out/lemonades/xnu-entry/attempt-{a.attempt:02d}"
    boot = ROOT / f"out/lemonades/boot/attempt-{a.attempt:02d}"
    session = json.loads((ROOT / f"out/lemonades/attempt-{a.attempt:02d}-boot-session.json").read_text())
    assert session["partition_flash"] is False
    assert sha(boot / "lemonades-uefi-menu.img") == session["image_sha256"]
    assert session["commands"][-1]["returncode"] == 0
    assert "Booting" in session["commands"][-1]["output"]
    assert "uid=2000(shell)" in (runtime / "adbd-shell-id.txt").read_text()
    for name, expected in json.loads((archive / "sha256.json").read_text()).items():
        assert sha(archive / name) == expected, name
    data = decode(a.attempt)
    panic = [m for m in data["markers"] if m["stage"] in ("a0","a1","a2","b0","b1","b2","b3")]
    assert not panic, "Panic/Assert records prevent a stable-monitor verdict"
    events = data["screen"]["events"]
    first = next(e for e in events if e["phase"] == 5)
    last = next(e for e in events if e["phase"] == 6)
    for event, count in ((first, 3), (last, 8)):
        assert event["version"] == 1 and event["monitor_passes"] == count
        assert event["bind_result"] == 0
        assert (event["width"],event["height"],event["stride"]) == (1080,2340,4320)
        assert event["framebuffer_va"] >= 0xffff000000000000
        assert event["pulse_worker_status"] == 2 and event["pulse_anchor_ready"] == 1
        assert event["storage_provider_bits"] == 0
        # One exception-vector entry can drain multiple GIC timer interrupts.
        # Only timer dispatches and completed EOIs must match at this thread snapshot.
        assert event["irq_entries"] > 0
        assert event["timer_entered"] == event["timer_completed"] > 0
    assert last["seconds"] > first["seconds"]
    assert last["irq_entries"] > first["irq_entries"]
    assert last["timer_entered"] > first["timer_entered"]
    assert last["timer_completed"] > first["timer_completed"]
    assert last["cntpct"] > first["cntpct"]
    gic = data["armcpu"]["events"]
    assert gic and any(e["gic_ready"] == 1 and e["cntfrq"] == 19200000 for e in gic)
    elapsed = (last["cntpct"]-first["cntpct"])/19200000
    assert elapsed >= 4
    result = {
        "status": "hardware_verified_full_diagnostic_display_and_live_monitor",
        "attempt": a.attempt, "kernel_sha256": data["kernel_sha256"],
        "runtime_log_sha256": data["runtime_log_sha256"],
        "boot_image_sha256": session["image_sha256"],
        "user_reported_visible_text_and_live_counters": True,
        "first_sample": first, "last_sample": last,
        "seconds_between_monitor_passes_3_and_8": elapsed,
        "coherent_screen_records": len(events),
        "incomplete_screen_groups": data["screen"]["incomplete_groups"],
        "discarded_screen_records": data["screen"]["discarded_records"],
        "panic_or_assert_markers": panic, "adb_restored_to_shell": True,
        "partition_flash": False, "root_mounted": False, "userspace_booted": False,
        "limits": "CPU framebuffer diagnostics with bounded logs and human panel observation; no OS display/GPU/storage qualification.",
    }
    (runtime / "screen-checked.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
