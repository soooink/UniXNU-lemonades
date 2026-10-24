#!/usr/bin/env python3
"""Read a legacy Android boot image header (Nexus 4 era); never write or flash."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def inspect(data):
    if len(data) < 608 or data[:8] != b'ANDROID!':
        raise ValueError('Not a complete legacy Android boot image header')
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
     second_addr, tags_addr, page_size, version, os_version) = struct.unpack_from('<10I', data, 8)
    if version != 0:
        raise ValueError('Only legacy/v0 headers are supported; header version is nonzero')
    if page_size < 2048 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError('Invalid legacy page size')
    if not kernel_size:
        raise ValueError('Kernel payload is empty')
    position = page_size
    segments = {}
    for name, size, address in (('kernel', kernel_size, kernel_addr),
                                ('ramdisk', ramdisk_size, ramdisk_addr),
                                ('second', second_size, second_addr)):
        if position + size > len(data):
            raise ValueError(f'Truncated {name} payload')
        if size and address + size > 0x100000000:
            raise ValueError(f'{name} load range exceeds 32-bit address space')
        segments[name] = {'file_offset': position, 'size': size, 'load_address': hex(address)}
        position += (size + page_size - 1) // page_size * page_size
    return {
        'format': 'legacy Android/v0 (608-byte common header)',
        'file_size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
        'page_size': page_size, 'tags_address': hex(tags_addr),
        'name': data[48:64].split(b'\0', 1)[0].decode('ascii', errors='replace'),
        'cmdline_first_512': data[64:576].split(b'\0', 1)[0].decode('ascii', errors='replace'),
        'reserved_or_os_version': hex(os_version), 'segments': segments,
        'note': 'Header addresses are metadata, not proof of usable RAM or XNU compatibility. '
                'Any modern extra command-line area, signatures, and payload contents are not validated.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    try:
        if args.image.stat().st_size > 512 * 1024 * 1024:
            raise ValueError('Image exceeds the 512 MiB inspection limit')
        print(json.dumps(inspect(args.image.read_bytes()), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, f'ERROR: {error}\n')


if __name__ == '__main__':
    main()
