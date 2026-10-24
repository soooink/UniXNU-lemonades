"""Accept only complete, unambiguous CRC-checked owner-root observations."""
import re
import struct
import zlib

FIELDS = ("phase", "trust_enabled", "apple_autherr", "owner_decision", "accepted",
          "readonly", "mount_device", "selected_device", "verified_device",
          "media_matches", "provider_depth", "uuid_match", "wrong_uuid_refused",
          "ufs_published", "ufs_verified_blocks", "ufs_integrity_failures",
          "aes_kat_status", "aes_registered")


def decode_root_trace(data):
    values = {}
    bad_crc = 0
    valid = 0
    for phase, index, value, checksum in re.findall(
            rb"\nUMI ROOT ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n", data):
        phase, index, value, checksum = (int(v, 16) for v in (phase,index,value,checksum))
        if zlib.crc32(struct.pack("<BBQ",phase,index,value)) != checksum:
            bad_crc += 1
            continue
        if phase not in (1,2) or index >= len(FIELDS):
            continue
        valid += 1
        values.setdefault(phase, {}).setdefault(index, set()).add(value)
    events, incomplete, conflicts = [], [], []
    for phase, fields in sorted(values.items()):
        if any(len(v) != 1 for v in fields.values()):
            conflicts.append(phase)
            continue
        if set(fields) != set(range(len(FIELDS))):
            incomplete.append(phase)
            continue
        event = dict(zip(FIELDS, (next(iter(fields[i])) for i in range(len(FIELDS)))))
        if event["phase"] != phase:
            conflicts.append(phase)
            continue
        events.append(event)
    return {"events":events,"crc_rejected_records":bad_crc,
            "crc_valid_records":valid,"incomplete_phases":incomplete,"conflicting_phases":conflicts}
