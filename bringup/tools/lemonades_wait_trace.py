"""Decode original tablet stack samples without inventing lost CRC fields."""
import re
import struct
import zlib

NAMES = ('version', 'record', 'snapshot_seconds', 'capture_start_seconds',
         'capture_end_seconds', 'generation', 'role', 'kind', 'pid',
         'main_captured')
MAIN = ('pc', 'lr', 'fp', 'trap', 'peer_pid', 'peer_code', 'stack_error',
        'image_error', 'image_base', 'cache_slide', 'options', 'remote_argument',
        'message_argument', 'receive_argument')
GROUP = ('thread_index', 'grouped_threads', 'stack_error', 'peer_pid', 'peer_code',
         'pc', 'lr', 'fp', 'trap', 'options', 'remote_argument',
         'message_argument', 'receive_argument', 'role_character')


def signed(value):
    return value - (1 << 32) if value is not None and value & (1 << 31) else value


def decode_wait_trace(data):
    groups = {}; valid = rejected = 0
    for row in re.findall(rb'\nUMI WAIT ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n', data):
        record, field, value, crc = (int(x, 16) for x in row)
        if not 1 <= record <= 24 or field >= 64 or zlib.crc32(struct.pack('<BBQ', record, field, value)) != crc:
            rejected += 1; continue
        valid += 1; groups.setdefault(record, {}).setdefault(field, set()).add(value)
    result = dict(records=[], crc_valid_records=valid, crc_rejected_records=rejected,
                  conflicts=[], invalid_records=[])
    for record, fields in sorted(groups.items()):
        if any(len(x) != 1 for x in fields.values()):
            result['conflicts'].append(record); continue
        v = {i: next(iter(x)) for i, x in fields.items()}
        if (v.get(0) != 1 or v.get(1) != record or v.get(6) != ((record-1) % 8)//2 or
                v.get(7) != (record-1) % 2+1):
            result['invalid_records'].append(record); continue
        o = dict(zip(NAMES, (v.get(i) for i in range(10))))
        o.update(complete=len(v) == 64, missing_fields=sorted(set(range(64))-set(v)),
                 snapshot_is_asynchronous=True, representative_groups_only=True)
        b = bytearray(); complete = False
        for i in range(10, 14):
            if i not in v: break
            part = struct.pack('<Q', v[i]); b.extend(part)
            if 0 in part: complete = True; break
        o['name_prefix'] = b.split(b'\0', 1)[0].decode(errors='replace')
        o['name_complete'] = complete or len(b) == 32
        for i, name in enumerate(('busy_thread_samples', 'omitted_thread_samples',
                                  'nonmain_group_count', 'total_sampled_threads'), 14):
            o[name] = v.get(i)
        a, z, t = v.get(3), v.get(4), v.get(2)
        o['capture_duration_seconds'] = z-a if a is not None and z is not None and z >= a else None
        o['capture_age_seconds'] = t-z if v.get(5, 0) > 0 and t is not None and z is not None and t >= z else None
        if v[7] == 1:
            o.update({name: v.get(18+i) for i, name in enumerate(MAIN)})
            o['peer_pid'] = signed(o['peer_pid'])
            o['frames'] = [v.get(i) for i in range(32, 64)]
        else:
            o.update(selected_group_count=v.get(18), unlogged_group_count=v.get(19), groups=[])
            if v.get(18) not in (None, 0, 1, 2):
                result['invalid_records'].append(record); continue
            # Without the CRC-valid count we cannot know which slots are populated.
            for i in range(v.get(18, 0)):
                base = 20+i*22
                g = {name: v.get(base+k) for k, name in enumerate(GROUP)}
                g['peer_pid'] = signed(g['peer_pid'])
                g['frames'] = [v.get(base+k) for k in range(14, 22)]
                o['groups'].append(g)
        result['records'].append(o)
    return result
