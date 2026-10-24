"""Schema shared by real phone RAM records and QEMU memory observations."""

FIELDS = (
    "version", "phase", "registered", "gic_ready", "timer_entered",
    "timer_completed", "irq_id", "irq_phase", "cntfrq", "cntvct",
    "cntv_cval", "cntv_ctl", "daif", "detail", "cpu_count", "boot_mpidr",
    "igroupr0", "isenabler0", "gicd_ctlr", "gicd_typer", "igrpmodr0",
    "icc_pmr", "icc_igrpen1", "icc_sre", "quiesce_calls", "halt_calls",
    "timer_returned", "first_irq_counter", "last_irq_counter", "phase_bitmap",
    "reserved30", "reserved31",
)
PHASES = {
    1: "before GIC preparation", 2: "GIC preparation and IOCPU::start returned",
    3: "processor registered", 4: "before interrupt controller allocation",
    5: "interrupt controller published", 6: "CPU interrupt handler installed",
    7: "interrupt action registration returned", 8: "initCPU returned",
    9: "GIC enabled and registers read back", 10: "virtual timer enabled",
    11: "ArmCpu::start complete", 12: "real PPI 27 before rtclock_intr",
    13: "rtclock_intr returned", 14: "real PPI 27 EOI executed",
    15: "before enableGic", 17: "GIC MMIO mapped",
    18: "distributor initialized", 19: "redistributor awake",
    20: "quiesceCPU entered", 21: "haltCPU entered",
}


def state(values):
    result = dict(zip(FIELDS, values))
    result["phase_name"] = PHASES.get(result["phase"], "unknown")
    return result


def phone_events(records):
    events, pending = [], None
    incomplete = 0
    discarded = 0
    for record in records:
        stage = int(record["stage"], 16)
        if stage == 0x80:
            if pending is not None:
                incomplete += 1
                discarded += len(pending)
            pending = []
        if 0x80 <= stage <= 0x9f:
            if pending is None:
                discarded += 1
                continue
            if stage != 0x80 + len(pending):
                incomplete += 1
                discarded += len(pending) + 1
                pending = None
                continue
            pending.append(int(record["value"], 16))
            if len(pending) == 32:
                events.append(state(pending))
                pending = None
    if pending is not None:
        incomplete += 1
        discarded += len(pending)
    return {"events": events, "incomplete_groups": incomplete,
            "discarded_records": discarded}
