"""Decode coherent UFS observations; transport success requires actual records."""
FIELDS = (
    "version", "phase", "status", "phone",
    "gdsc", "axi_clock", "ahb_clock", "aux_clock",
    "cap", "ufs_version", "hcs", "hce", "utrlba", "utrlbau",
    "doorbell", "run_stop", "task_doorbell", "task_run_stop", "ahit", "interrupt_status",
    "smmu_scr0", "smmu_idr0", "smmu_idr1", "smmu_idr2", "smmu_gfsr",
    "stream_count", "valid_streams", "sid_e0_index", "sid_e0_smr_s2cr",
    "sid_4e0_index", "sid_4e0_smr_s2cr", "cntpct",
)
SMMU_FIELDS=(
    "version","phase","status","phone","dma","contiguous","idr0","idr1","idr2","scr0",
    "bank","pages","slot_e0","smr_e0","s2cr_e0","slot_4e0","smr_4e0","s2cr_4e0",
    "cbar","cba2r","sctlr","fsr","gfsr","plan_error","run_stop","hce","doorbell",
    "task_doorbell","nonzero_upper_bits_seen","far","fsyn","gsyn",
)
READ_FIELDS=(
    "version","phase","status","commands","type","opcode","lun","ocs","scsi","response",
    "protocol_error","residual","sense","power","polls","doorbell_seen","interrupt_seen",
    "dma","run_stop","list_address","last_read_lba","userdata_first","userdata_last",
    "gpt_header_crc","gpt_entries_crc","manifest_status","magic0","magic1","windows",
    "lun0_last_lba","lun0_block_bytes","cntpct",
)
NATIVE_FIELDS=(
    "version","root_step","phone","requested","matched","host_ready","poisoned",
    "commands","status","ocs","scsi","protocol_error","residual","dma",
    "userdata_first","userdata_last","manifest_status","windows","prepared","published",
    "block_reads","block_failures","policy_count","verify_status","publication_phase",
    "publication_window","verified_blocks","integrity_failures","magic0","magic1",
    "nonzero_upper_bits_seen","cntpct",
)

def phone_events(records):
    events, pending, incomplete, discarded = [], None, 0, 0
    smmu_events,read_events,native_events,unknown=[],[],[],[]
    for record in records:
        code = int(record["stage"],16)
        if code == 0xe0:
            if pending is not None:
                incomplete += 1
                discarded += len(pending)
            pending = []
        if 0xe0 <= code <= 0xff:
            if pending is None:
                discarded += 1
                continue
            if code != 0xe0 + len(pending):
                incomplete += 1
                discarded += len(pending)+1
                pending = None
                continue
            pending.append(int(record["value"],16))
            if len(pending)==32:
                version=pending[0]
                if version==1: events.append(dict(zip(FIELDS,pending)))
                elif version==2: smmu_events.append(dict(zip(SMMU_FIELDS,pending)))
                elif version==3: read_events.append(dict(zip(READ_FIELDS,pending)))
                elif version==4: native_events.append(dict(zip(NATIVE_FIELDS,pending)))
                else: unknown.append(pending)
                pending = None
    if pending is not None:
        incomplete += 1
        discarded += len(pending)
    return {"events":events,"smmu_events":smmu_events,"read_events":read_events,
            "native_events":native_events,
            "unknown_versions":unknown,"incomplete_groups":incomplete,"discarded_records":discarded,
            "disk_read_tested":any(e["phase"]==15 and e["status"]==0 for e in read_events) or
                any(e["phone"]==1 and e["root_step"]==3 and e["host_ready"]==1 and
                    e["status"]==0 and e["commands"]>=7 for e in native_events),
            "controller_takeover_reached":any(e["phase"]>=8 for e in smmu_events),
            "root_mounted":False}
