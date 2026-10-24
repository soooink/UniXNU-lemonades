#!/usr/bin/env python3
"""Read Mi 10 (lemonades) bring-up evidence and boot backups using an already-root ADB.

No device writes, reboot, flashing, mounting or raw-memory reads. Binary reads
are limited to boot-related partitions, the boot FDT/config, and primary GPTs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
PROPERTIES = (
    'ro.product.device', 'ro.build.product', 'ro.product.vendor.device',
    'ro.product.model', 'ro.hardware', 'ro.board.platform', 'ro.soc.model',
    'ro.build.version.release', 'ro.build.version.sdk', 'ro.lineage.version',
    'ro.build.id', 'ro.build.type', 'ro.boot.slot_suffix',
    'ro.boot.flash.locked', 'ro.boot.vbmeta.device_state',
    'ro.boot.verifiedbootstate', 'ro.boot.bootloader',
)
READS = {
    'kernel.txt': 'uname -a',
    'cpuinfo.txt': 'cat /proc/cpuinfo',
    'cmdline.txt': 'cat /proc/cmdline',
    'bootconfig.txt': 'cat /proc/bootconfig',
    'iomem.txt': 'cat /proc/iomem',
    'meminfo.txt': 'cat /proc/meminfo',
    'partitions.txt': 'cat /proc/partitions',
    'partition-links.txt': 'ls -l /dev/block/by-name',
    'block-sysfs.txt': (
        'for p in /sys/class/block/sd*; do [ -e "$p" ] || continue; '
        'printf "NODE %s\\n" "$p"; cat "$p/uevent"; '
        'printf "START_512 "; cat "$p/start" 2>/dev/null; '
        'printf "SIZE_512 "; cat "$p/size"; '
        '[ ! -e "$p/queue/logical_block_size" ] || '
        '{ printf "LOGICAL_BLOCK_BYTES "; cat "$p/queue/logical_block_size"; }; done'),
    'input-devices.txt': 'cat /proc/bus/input/devices',
    'touch-driver.txt': 'readlink /sys/bus/i2c/devices/3-0049/driver; cat /sys/bus/i2c/devices/3-0049/name',
    'display-size.txt': 'wm size; wm density',
    'display-connector.txt': (
        'for n in status enabled modes dpms; do '
        'printf "%s\\n" "$n"; cat /sys/class/drm/card0-DSI-1/$n; done'),
    'drm-state.txt': 'cat /sys/kernel/debug/dri/0/state',
    'kgsl.txt': (
        'for n in gpu_model chipid gpu_available_frequencies devfreq/available_frequencies; do '
        'printf "%s\\n" "$n"; cat /sys/class/kgsl/kgsl-3d0/$n; done'),
    'soc.txt': (
        'for n in family machine soc_id revision; do '
        'printf "%s\\n" "$n"; cat /sys/devices/soc0/$n; done'),
    'dmesg.txt': 'dmesg',
    'pstore-list.txt': 'ls -l /sys/fs/pstore',
}


def validate_identity(properties):
    if (properties.get('ro.product.device') != 'lemonades'
            or properties.get('ro.board.platform') != 'kona'
            or properties.get('ro.soc.model') not in ('', 'SM8250')):
        raise ValueError('Device is not verified as lemonades / kona / SM8250')


def gpt_header(block, sector_bytes):
    if sector_bytes not in (512, 4096) or len(block) < sector_bytes:
        raise ValueError('Unsupported or truncated logical sector')
    if block[:8] != b'EFI PART':
        raise ValueError('GPT signature missing')
    revision, size, crc = struct.unpack_from('<III', block, 8)
    if revision != 0x10000 or not 92 <= size <= sector_bytes:
        raise ValueError('Invalid GPT revision/header size')
    header = bytearray(block[:size])
    header[16:20] = bytes(4)
    if zlib.crc32(header) != crc:
        raise ValueError('GPT header CRC mismatch')
    if struct.unpack_from('<Q', block, 24)[0] != 1:
        raise ValueError('Not a primary GPT')
    lba, count, entry_bytes, table_crc = struct.unpack_from('<QIII', block, 72)
    if lba < 2 or not 1 <= count <= 4096 or not 128 <= entry_bytes <= 4096 or entry_bytes % 128:
        raise ValueError('Invalid GPT table layout')
    end = lba * sector_bytes + count * entry_bytes
    if end > 1024 * 1024:
        raise ValueError('GPT metadata exceeds the 1 MiB read limit')
    return {'entry_lba': lba, 'count': count, 'entry_bytes': entry_bytes,
            'table_crc32': table_crc, 'read_blocks': (end + sector_bytes - 1) // sector_bytes}


def parse_gpt(data, sector_bytes):
    header = gpt_header(data[sector_bytes:sector_bytes * 2], sector_bytes)
    start = header['entry_lba'] * sector_bytes
    table = data[start:start + header['count'] * header['entry_bytes']]
    if len(table) != header['count'] * header['entry_bytes'] or zlib.crc32(table) != header['table_crc32']:
        raise ValueError('Truncated GPT entries or table CRC mismatch')
    first_usable, last_usable = struct.unpack_from('<QQ', data, sector_bytes + 40)
    result = []
    for index in range(header['count']):
        entry = table[index * header['entry_bytes']:(index + 1) * header['entry_bytes']]
        if entry[:16] == bytes(16):
            continue
        first, last, attributes = struct.unpack_from('<QQQ', entry, 32)
        if not first_usable <= first <= last <= last_usable:
            raise ValueError('GPT partition outside usable disk bounds')
        name = entry[56:128].decode('utf-16-le').split('\0', 1)[0]
        result.append({'index': index + 1, 'name': name, 'first_lba': first,
                       'last_lba': last, 'logical_block_bytes': sector_bytes,
                       'offset_bytes': first * sector_bytes,
                       'size_bytes': (last - first + 1) * sector_bytes,
                       'attributes': hex(attributes)})
    ordered = sorted(result, key=lambda partition: partition['first_lba'])
    for left, right in zip(ordered, ordered[1:]):
        if left['last_lba'] >= right['first_lba']:
            raise ValueError('GPT partitions overlap')
    return result


def read_gpt(adb, disk):
    if disk not in ('sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf'):
        raise ValueError('Disk is outside the GPT metadata allowlist')
    sector = int(adb.value(f'cat /sys/class/block/{disk}/queue/logical_block_size'))
    if sector not in (512, 4096):
        raise ValueError('Unsupported logical sector size')
    # Remote stderr is merged into exec-out stdout; exclude dd statistics.
    command = f'dd if=/dev/block/{disk} bs={sector}'
    head = adb.raw(command + ' count=2 2>/dev/null')
    if len(head) != sector * 2:
        raise ValueError('Short GPT header read')
    layout = gpt_header(head[sector:], sector)
    data = adb.raw(command + f' count={layout["read_blocks"]} 2>/dev/null')
    if len(data) != sector * layout['read_blocks']:
        raise ValueError('Short GPT metadata read')
    return sector, data, parse_gpt(data, sector)


class Adb:
    def __init__(self, serial):
        self.serial = serial

    def shell(self, command, timeout=30):
        return subprocess.run(['adb', '-s', self.serial, 'shell', command],
                              capture_output=True, text=True, errors='replace', timeout=timeout)

    def value(self, command):
        result = self.shell(command)
        if result.returncode:
            raise RuntimeError(f'{command}: {result.stderr.strip()}')
        return result.stdout.strip()

    def raw(self, command, timeout=30):
        result = subprocess.run(['adb', '-s', self.serial, 'exec-out', command],
                                capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace').strip())
        return result.stdout

    def copy_partition(self, device_path, destination):
        if not re.fullmatch(r'/dev/block/by-name/(boot|dtbo|recovery|vbmeta)(_[ab])?', device_path):
            raise ValueError('Partition is outside the boot backup allowlist')
        size = int(self.value('blockdev --getsize64 ' + shlex.quote(device_path)))
        if not 0 < size <= 256 * 1024 * 1024:
            raise ValueError('Boot backup exceeds the 256 MiB per-partition limit')
        partial = destination.with_suffix(destination.suffix + '.partial')
        with partial.open('wb') as stream:
            result = subprocess.run(['adb', '-s', self.serial, 'exec-out',
                                     'cat ' + shlex.quote(device_path)],
                                    stdout=stream, stderr=subprocess.PIPE, timeout=180)
        if result.returncode or partial.stat().st_size != size:
            raise RuntimeError('Partition read failed or backup size mismatch: ' + device_path)
        remote_hash = self.value('sha256sum ' + shlex.quote(device_path)).split()[0]
        with partial.open('rb') as stream:
            local_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        if not re.fullmatch('[0-9a-f]{64}', remote_hash) or remote_hash != local_hash:
            raise RuntimeError('Device/host SHA-256 mismatch: ' + device_path)
        partial.rename(destination)
        return {'source': device_path, 'bytes': size, 'sha256': local_hash,
                'device_sha256_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--skip-images', action='store_true')
    args = parser.parse_args()
    adb = Adb(args.serial)
    identity = {key: adb.value('getprop ' + key) for key in PROPERTIES}
    validate_identity(identity)
    root_identity = adb.value('id')
    if not re.search(r'\buid=0\b', root_identity):
        raise RuntimeError('An already-root ADB session is required (adb root); no settings were changed')
    suffix = identity['ro.boot.slot_suffix']
    if suffix not in ('', '_a', '_b'):
        raise ValueError('Unexpected active-slot suffix')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = ROOT / 'out/device/lemonades' / stamp
    output.mkdir(parents=True, mode=0o700)
    report = {'format_version': 1, 'collected_at_utc': stamp, 'identity': identity,
              'root_identity': root_identity, 'device_writes': False, 'reads': {},
              'artifacts': {}, 'gpt': {}}

    def save_report():
        (output / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')

    save_report()
    print('Collecting verified lemonades into ' + str(output), flush=True)
    for name, command in READS.items():
        try:
            result = adb.shell(command)
            (output / name).write_text(result.stdout)
            report['reads'][name] = {'command': command, 'exit_code': result.returncode,
                                     'stderr': result.stderr.strip()}
        except (OSError, subprocess.TimeoutExpired) as error:
            report['reads'][name] = {'command': command, 'error': str(error)}
        save_report()
    for name, path, magic in (
            ('running.dtb', '/sys/firmware/fdt', b'\xd0\x0d\xfe\xed'),
            ('kernel-config.gz', '/proc/config.gz', b'\x1f\x8b')):
        try:
            data = adb.raw('cat ' + shlex.quote(path))
            if not data.startswith(magic):
                raise ValueError('Unexpected file signature: ' + path)
            (output / name).write_bytes(data)
            report['artifacts'][name] = {'source': path, 'bytes': len(data),
                                         'sha256': hashlib.sha256(data).hexdigest()}
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            report['artifacts'][name] = {'error': str(error)}
        save_report()
    print('Text and boot FDT collected; reading primary GPT metadata.', flush=True)
    for disk in ('sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf'):
        try:
            sector, data, partitions = read_gpt(adb, disk)
            name = 'gpt-' + disk + '.bin'
            (output / name).write_bytes(data)
            report['artifacts'][name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            report['gpt'][disk] = {'header_crc_valid': True, 'table_crc_valid': True,
                                    'logical_block_bytes': sector, 'partitions': partitions}
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            report['gpt'][disk] = {'error': str(error)}
        save_report()
    if not args.skip_images:
        for partition in ('boot', 'dtbo', 'recovery', 'vbmeta'):
            name = partition + suffix
            print('Backing up ' + name + ' (read only).', flush=True)
            try:
                report['artifacts'][name + '.img'] = adb.copy_partition(
                    '/dev/block/by-name/' + name, output / (name + '.img'))
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                report['artifacts'][name + '.img'] = {'error': str(error)}
            save_report()
    print('Collection complete: ' + str(output), flush=True)
    for category in ('reads', 'artifacts', 'gpt'):
        failed = [name for name, value in report[category].items()
                  if 'error' in value or value.get('exit_code', 0) != 0]
        if failed:
            print(category + ' unavailable/partial: ' + ', '.join(failed))
    required = ['running.dtb'] + ([] if args.skip_images else ['boot' + suffix + '.img', 'dtbo' + suffix + '.img'])
    complete = (all('error' not in report['artifacts'].get(name, {'error': 'missing'}) for name in required)
                and all('error' not in report['gpt'].get(disk, {'error': 'missing'}) for disk in ('sda', 'sde')))
    report['required_collection_complete'] = complete
    save_report()
    return 0 if complete else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
