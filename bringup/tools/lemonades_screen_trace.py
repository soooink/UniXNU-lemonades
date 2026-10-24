"""Decode bounded full-diagnostic records without joining incomplete groups."""
FIELDS = (
    "version", "phase", "seconds", "monitor_passes", "bind_result", "framebuffer_va",
    "width", "height", "stride", "irq_entries", "timer_entered", "timer_completed",
    "pulse_worker_status", "pulse_anchor_ready", "storage_provider_bits", "cntpct",
)
PHASES = {1: "initialized", 2: "console bind returned", 3: "starting workers",
          4: "monitor pass 1", 5: "monitor pass 3", 6: "monitor pass 8",
          7: "before retained framebuffer mapping"}

def phone_events(records):
    events, pending, incomplete, discarded = [], None, 0, 0
    for record in records:
        code = int(record["stage"], 16)
        if code == 0xc0:
            if pending is not None:
                incomplete += 1
                discarded += len(pending)
            pending = []
        if 0xc0 <= code <= 0xcf:
            if pending is None:
                discarded += 1
                continue
            if code != 0xc0 + len(pending):
                incomplete += 1
                discarded += len(pending) + 1
                pending = None
                continue
            pending.append(int(record["value"], 16))
            if len(pending) == 16:
                state = dict(zip(FIELDS, pending))
                state["phase_name"] = PHASES.get(state["phase"], "unknown")
                events.append(state)
                pending = None
    if pending is not None:
        incomplete += 1
        discarded += len(pending)
    return {"events": events, "incomplete_groups": incomplete, "discarded_records": discarded,
            "panel_visibility_requires_user_observation": True}
