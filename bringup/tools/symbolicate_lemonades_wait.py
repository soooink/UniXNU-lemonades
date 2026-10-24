#!/usr/bin/env python3
"""Map CRC-qualified phone WAIT samples to the unchanged SystemOS cache.

The fixed header offsets are from Apple's dyld a571176e cache format, also
used by the tablet's symbolicate-original-user-exception.py. This reads only
local symbol tables; a nearest symbol is not proof of the callee's result.
"""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import uuid


class Cache:
    def __init__(self, directory):
        self.directory = Path(directory)
        main = (self.directory / 'dyld_shared_cache_arm64').read_bytes()
        if main[:16].rstrip(b'\0') != b'dyld_v1   arm64':
            raise ValueError('Expected original arm64 cache')
        self.uuid = str(uuid.UUID(bytes=main[88:104]))
        self.main_sha256 = hashlib.sha256(main).hexdigest()
        self.region, self.region_size, self.max_slide = struct.unpack_from('<3Q', main, 224)
        off, count = struct.unpack_from('<2Q', main, 136)
        self.images = []
        for i in range(count):
            ident, address, size, name = struct.unpack_from('<16sQ2I', main, off+i*32)
            end = main.index(b'\0', name)
            self.images.append(dict(address=address, size=size,
                                    path=main[name:end].decode(),
                                    uuid=str(uuid.UUID(bytes=ident))))
        self.images.sort(key=lambda x: x['address'])
        self.starts = [im['address'] for im in self.images]
        self.stream = (self.directory / 'dyld_shared_cache_arm64.symbols').open('rb')
        self.symbols = mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ)
        if self.symbols[88:104] != main[400:416]:
            raise ValueError('Symbols UUID differs from cache symbolFileUUID')
        self.symbols_uuid = str(uuid.UUID(bytes=self.symbols[88:104]))
        self.lo, size = struct.unpack_from('<2Q', self.symbols, 72)
        if self.lo+size > len(self.symbols):
            raise ValueError('Truncated symbols')
        self.no, self.nc, self.so, self.ss, eo, ec = struct.unpack_from('<6I', self.symbols, self.lo)
        if max(self.no+self.nc*16, self.so+self.ss, eo+ec*16) > size:
            raise ValueError('Invalid local-symbol bounds')
        self.entries = {}
        for i in range(ec):
            key, start, count = struct.unpack_from('<Q2I', self.symbols, self.lo+eo+i*16)
            if key in self.entries or start+count > self.nc:
                raise ValueError('Invalid local-symbol entry')
            self.entries[key] = start, count
        self.loaded = {}

    def close(self):
        self.symbols.close()
        self.stream.close()

    def resolve(self, runtime, slide, return_address=False):
        row = dict(runtime_address=hex(runtime), return_address=return_address)
        if not 0 <= slide <= self.max_slide or slide % 4096:
            raise ValueError('Observed shared-cache slide outside original bounds')
        va = runtime-slide-(4 if return_address else 0)
        row['lookup_address'] = hex(va)
        pos = bisect.bisect_right(self.starts, va)-1
        if pos < 0 or va >= self.images[pos]['address']+self.images[pos]['size']:
            row['unresolved_reason'] = 'Outside cache TEXT; executable slide not captured'
            return row
        im = self.images[pos]
        row.update(image=im['path'], image_uuid=im['uuid'])
        if pos not in self.loaded:
            start, count = self.entries.get(im['address']-self.region, (0, 0))
            syms = []
            for i in range(start, start+count):
                string, kind, section, _, value = struct.unpack_from('<IBBHQ', self.symbols, self.lo+self.no+i*16)
                if not kind & 0xe0 and kind & 0xe == 0xe and section and im['address'] <= value < im['address']+im['size']:
                    if string >= self.ss:
                        raise ValueError('String index outside original table')
                    begin = self.lo+self.so+string
                    end = self.symbols.find(b'\0', begin, self.lo+self.so+self.ss)
                    if end < 0:
                        raise ValueError('Unterminated local symbol')
                    syms.append((value, self.symbols[begin:end].decode(errors='replace')))
            syms.sort()
            self.loaded[pos] = syms, [sym[0] for sym in syms]
        syms, starts = self.loaded[pos]
        index = bisect.bisect_right(starts, va)-1
        if index >= 0:
            value, name = syms[index]
            row.update(nearest_local_symbol=name, symbol_address=hex(value), offset=va-value)
        else:
            row['unresolved_reason'] = 'No preceding local TEXT symbol'
        return row


def symbolicate(report, cache):
    records = report['userspace_waits']['records']
    result = []
    for record in records:
        # Groups lack their own dyld metadata: require the same pid, batch and
        # published generation's valid main record. Never borrow another run.
        main = next((r for r in records if r['kind'] == 1 and r['pid'] == record['pid']
                     and r['generation'] == record['generation']
                     and r['snapshot_seconds'] == record['snapshot_seconds']), None)
        if not main or main.get('image_error') != 0 or main.get('cache_slide') is None:
            result.append(dict(record=record['record'], unresolved_reason='Missing valid cache-slide sample'))
            continue
        rows = [record] if record['kind'] == 1 else record['groups']
        for group in rows:
            out = {k: record[k] for k in ('record', 'pid', 'name_prefix', 'snapshot_seconds', 'generation', 'capture_age_seconds')}
            out.update(kind=record['kind'], thread_index=group.get('thread_index', 'main'),
                       peer_pid=group.get('peer_pid'), peer_code=group.get('peer_code'),
                       stack_error=group.get('stack_error'), cache_slide=hex(main['cache_slide']))
            out['pc'] = cache.resolve(group['pc'], main['cache_slide']) if group.get('pc') else None
            # Keep missing/zero slots explicit; never join across lost frames.
            out['frames'] = [cache.resolve(pc, main['cache_slide'], True) if pc else pc for pc in group['frames']]
            result.append(out)
    return dict(cache_uuid=cache.uuid, main_cache_sha256=cache.main_sha256,
                symbols_uuid=cache.symbols_uuid, local_symbols_uuid_matches=True,
                source_cache=str(cache.directory), original_files_modified=False,
                provenance='CRC-qualified phone WAIT; runtime slide from original dyld image info',
                limitations=['Nearest local symbols, not full function-boundary validation',
                             'peer_code 5 is only a receive-argument candidate, not a confirmed outgoing RPC peer',
                             'Non-cache executable ASLR not captured; representative worker groups only'],
                samples=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    cache = Cache(args.cache)
    try:
        result = symbolicate(json.loads(args.report.read_text()), cache)
    finally:
        cache.close()
    result['input_report_sha256'] = hashlib.sha256(args.report.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output), samples=len(result['samples']), cache_uuid=result['cache_uuid'])))


if __name__ == '__main__':
    main()
