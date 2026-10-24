"""Decode only complete, conflict-free, CRC-qualified execution records."""
import re
import struct
import zlib


def decode_exec_trace(data):
    phases = {}
    valid = rejected = 0
    for row in re.findall(rb"\nUMI EXEC ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n", data):
        phase, field, value, crc = (int(v, 16) for v in row)
        if zlib.crc32(struct.pack("<BBQ", phase, field, value)) != crc:
            rejected += 1
            continue
        if phase >= 64 or field >= 20:
            continue
        valid += 1
        phases.setdefault(phase, {}).setdefault(field, set()).add(value)
    events, incomplete, conflicts = [], [], []
    for phase, fields in phases.items():
        if any(len(v) != 1 for v in fields.values()):
            conflicts.append(phase)
            continue
        if set(fields) != set(range(20)):
            incomplete.append(phase)
            continue
        values = [next(iter(fields[i])) for i in range(20)]
        if values[:2] != [1, phase] or values[8] > 11:
            incomplete.append(phase)
            continue
        event = {"phase": phase, "data": values[2:8],
                 "return_addresses": values[9:9+values[8]]}
        if phase == 1:
            event.update(name="load_init_program", pid=values[3])
        elif phase == 3:
            event.update(name="first_user_svc", pc=values[2], cpsr=values[3],
                         sp=values[4], syscall=values[5], pid=values[6], lr=values[7])
            event["el0_svc_proved"] = values[3] & 15 == 0 and 0 < values[2] < 1 << 48
        elif phase == 4:
            event.update(name="first_user_exception", pc=values[2], cpsr=values[3],
                         esr=values[4], far=values[5], pid=values[6], lr=values[7])
        elif phase == 5:
            event.update(name="panic", format_address=values[2], caller=values[3], reason=values[4])
        elif phase == 6:
            event.update(name="static_trust_cache_load_returned")
        elif phase == 7:
            event.update(name="repeated_kernel_abort_64", pc=values[2], cpsr=values[3],
                         esr=values[4], far=values[5], pid=values[6], lr=values[7])
        elif phase == 8:
            event.update(name="critical_init_exit" if values[2] == 1 else "critical_process_exit", pid=values[2], status=values[3],
                         reason_namespace=values[4], reason_code=values[5], csflags=values[6],
                         description_bytes=values[7] & 0xffffffff,
                         description_limit_reached=bool(values[7] >> 32))
            event.update(signal=values[3] & 127, exit_status=(values[3] >> 8) & 255)
        elif phase == 9:
            name = struct.pack("<4Q", *values[4:8]).split(b"\0", 1)[0].decode("utf-8", errors="replace")
            event.update(name="critical_process_identity", initproc_spawned=values[2],
                         is_initproc=bool(values[3]), process_name=name)
        elif phase == 10:
            status = values[2] & 0xffffffff
            event.update(name="systemos_mount_result", status=status if status < 0x80000000 else status-(1 << 32),
                         authorized=values[3], stage=values[4], mount_flags=values[5],
                         selected_device=values[6], mounted_device=values[7])
        elif phase == 11:
            event.update(name="systemos_startup_result", readonly=values[2], native_union=values[3],
                         original_root_rechecked=values[4], dyld_flags=values[5],
                         boot_manifest_status=values[6], original_root=values[7])
        elif phase == 12:
            event.update(name="critical_exit_user_state", pc=values[2], lr=values[3],
                         sp=values[4], fp=values[5], cpsr=values[6], pid=values[7])
        elif phase == 14:
            event.update(name="critical_exit_user_arguments", pid=values[2],
                         x0=values[3], x1=values[4], x2=values[5], x3=values[6], x16=values[7])
        elif 0x30 <= phase <= 0x3f:
            event.update(name="critical_init_exit_text", chunk=phase-0x30)
        elif 0x10 <= phase <= 0x14:
            event.update(name="init_exec_begin", attempt=phase-0x10,
                         path_address=values[2], scratch_address=values[3], pid=values[5])
        elif 0x20 <= phase <= 0x24:
            event.update(name="init_exec_return", attempt=phase-0x20, error=values[2])
        events.append(event)
    critical_exit = None
    metadata = next((e for e in events if e["phase"] == 8), None)
    if metadata:
        critical_exit = dict(metadata)
        identity = next((e for e in events if e["phase"] == 9), None)
        if identity:
            critical_exit.update({k: identity[k] for k in ("initproc_spawned", "is_initproc", "process_name")})
        length = metadata["description_bytes"]
        chunks = {e["chunk"]: e for e in events if e.get("name") == "critical_init_exit_text"}
        valid_length = 0 <= length <= 768
        missing = [i for i in range((length+47)//48) if i not in chunks] if valid_length else []
        critical_exit["missing_text_chunks"] = missing
        critical_exit["valid_description_length"] = valid_length
        if valid_length and not missing:
            raw = b"".join(struct.pack("<6Q", *chunks[i]["data"]) for i in range((length+47)//48))[:length]
            critical_exit["description"] = raw.decode("utf-8", errors="replace")
    return {"events": events, "critical_exit": critical_exit,
            "crc_valid_records": valid, "crc_rejected_records": rejected,
            "incomplete_phases": incomplete, "conflicting_phases": conflicts}
