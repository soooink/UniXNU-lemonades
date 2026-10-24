"""Decode CRC-qualified failing-lock state without repairing damaged values."""
import re
import struct
import zlib


def decode_lock_trace(data):
    fields = {}
    bad_crc = valid = 0
    for phase, index, value, checksum in re.findall(
            rb"\nUMI LOCK ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n", data):
        phase,index,value,checksum = (int(v,16) for v in (phase,index,value,checksum))
        if zlib.crc32(struct.pack("<BBQ",phase,index,value)) != checksum:
            bad_crc += 1
            continue
        if phase != 1 or index >= 64:
            continue
        valid += 1
        fields.setdefault(index,set()).add(value)
    conflicts = sorted(i for i,v in fields.items() if len(v) != 1)
    missing = sorted(set(range(10)) - fields.keys())
    event = None
    if not conflicts and not missing:
        read = lambda i: next(iter(fields[i]))
        count = read(9)
        if read(0) == 1 and 0 < count <= 48:
            missing = sorted((set(range(10,10+count)) | {58}) - fields.keys())
            if not missing:
                event = {"version":1,"lock":read(1),"lock_data":read(2),
                         "owner":read(3),"can_sleep":read(4),"preemption_level":read(5),
                         "daif":read(6),"thread":read(7),"lock_size":read(8),
                         "frame_count":count,"return_addresses":[read(i) for i in range(10,10+count)],
                         "source_line":read(58)}
    return {"event":event,"crc_valid_records":valid,"crc_rejected_records":bad_crc,
            "conflicting_fields":conflicts,"missing_required_fields":missing}
