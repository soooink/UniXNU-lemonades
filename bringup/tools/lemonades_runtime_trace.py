"""Decode only complete, conflict-free CRC snapshots from the phone monitor."""
import re
import struct
import zlib

FIELDS = (
    "version", "sample", "seconds", "processes", "free_pages", "active_pages", "inactive_pages", "wired_pages",
    "launchd_main", "watchdog_policy_status", "data_stage", "data_status", "data_readonly", "ram_ready",
    "ram_bytes", "ram_reads", "ram_writes", "ram_failures", "ram_resident_bytes", "graphics_load_status",
    "display_stage", "display_init", "display_start", "surface_status", "surface_found", "registration_calls",
    "client_calls", "client_pid", "client_status", "transfer_calls", "transfer_status", "retirement_calls",
    "handoff_calls", "handoff_reason", "handoff_attempts", "display_owned", "guard_slot", "process_worker_status",
    "process_passes", "process_busy", "exit_total", "exit_failed", "exit_crashes", "framebuffer_bytes",
    "width", "height", "processes_seen", "exit_snapshot_available",
)
COUNT = 248
COUNTS = {1: 176, 2: COUNT}
SMP_FIELDS = (
    "requested", "running_secondary_summary", "psci_conduit", "boot_mpidr", "gicd_typer",
    "redistributor_stride", "registered", "ipi_sent_summary", "ipi_received_summary", "ipi_selftest_sent_summary",
    "xnu_logical_online", "xnu_logical_max", "xnu_physical_online", "xnu_physical_max",
)
CORE_FIELDS = ("step", "expected_mpidr", "seen_mpidr", "failure", "psci_rc", "timer_irqs", "ipi_irqs")
DEADLINES = (10, 30, 60, 90, 120, 180, 240, 300)


def decode_runtime_trace(data):
    phases = {}
    valid = rejected = 0
    for row in re.findall(rb"\nUMI LIVE ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n", data):
        phase, field, value, crc = (int(v, 16) for v in row)
        if zlib.crc32(struct.pack("<BBQ", phase, field, value)) != crc:
            rejected += 1
            continue
        if phase not in range(1, len(DEADLINES)+1) or field >= COUNT:
            rejected += 1
            continue
        valid += 1
        phases.setdefault(phase, {}).setdefault(field, set()).add(value)
    samples, incomplete, conflicts = [], [], []
    for phase, fields in sorted(phases.items()):
        if any(len(values) != 1 for values in fields.values()):
            conflicts.append(phase)
            continue
        version = next(iter(fields.get(0, {0})))
        count = COUNTS.get(version)
        if count is None or set(fields) != set(range(count)):
            incomplete.append(phase)
            continue
        values = [next(iter(fields[i])) for i in range(count)]
        if values[:2] != [version, phase] or values[2] < DEADLINES[phase-1]:
            incomplete.append(phase)
            continue
        result = dict(zip(FIELDS, values[:48]))
        packed = struct.pack(f"<{count}Q", *values)
        result["process_rows"] = [packed[384+i*64:384+(i+1)*64].split(b"\0", 1)[0].decode(errors="replace") for i in range(10)]
        result["failed_exits"] = [packed[1024+i*120:1024+(i+1)*120].split(b"\0", 1)[0].decode(errors="replace") for i in range(3)] if result["exit_snapshot_available"] else None
        if version == 2:
            smp = dict(zip(SMP_FIELDS, values[176:190]))
            smp["cores"] = []
            for i in range(8):
                core = dict(zip(CORE_FIELDS, values[192+i*7:199+i*7]))
                core["logical_id"] = i
                rc = core["psci_rc"] & 0xffffffff
                core["psci_rc"] = rc-(1 << 32) if rc & (1 << 31) else rc
                smp["cores"].append(core)
            smp["observation_is_asynchronous"] = True
            smp["aggregate_counters_are_advisory"] = True
            smp["boot_core_step_not_recorded_by_original_driver"] = True
            result["smp"] = smp
        samples.append(result)
    return {"samples": samples, "crc_valid_records": valid, "crc_rejected_records": rejected,
            "incomplete_samples": incomplete, "conflicting_samples": conflicts}
