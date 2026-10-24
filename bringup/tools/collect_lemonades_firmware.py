#!/usr/bin/env python3
"""Read the Mi 10 boot firmware inputs needed for UEFI porting; never flash."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from collect_lemonades import Adb, ROOT, validate_identity

PARTITIONS = ('xbl_4', 'xbl_5', 'xbl_config_4', 'xbl_config_5', 'imagefv', 'abl')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    adb = Adb(args.serial)
    validate_identity({key: adb.value('getprop ' + key) for key in
                       ('ro.product.device', 'ro.board.platform', 'ro.soc.model')})
    if not re.search(r'\buid=0\b', adb.value('id')):
        raise RuntimeError('An already-root ADB session is required')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = ROOT / 'out/firmware/lemonades' / stamp
    output.mkdir(parents=True, mode=0o700)
    report = {'collected_at_utc': stamp, 'source': 'verified lemonades root ADB, read-only block reads',
              'device_writes': False, 'artifacts': {}}
    print('Firmware inputs: ' + str(output), flush=True)
    for name in PARTITIONS:
        source = '/dev/block/by-name/' + name
        length = int(adb.value('blockdev --getsize64 ' + source))
        if not 0 < length <= 32 * 1024 * 1024:
            raise ValueError('Unexpected firmware input size: ' + name)
        destination = output / (name + '.img')
        partial = destination.with_suffix('.img.partial')
        with partial.open('wb') as stream:
            result = subprocess.run(['adb', '-s', args.serial, 'exec-out', 'cat ' + source],
                                    stdout=stream, stderr=subprocess.PIPE, timeout=60)
        if result.returncode or partial.stat().st_size != length:
            raise RuntimeError('Incomplete firmware read: ' + name)
        expected = adb.value('sha256sum ' + source).split()[0]
        with partial.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != expected:
            raise RuntimeError('Device/host SHA-256 mismatch: ' + name)
        partial.rename(destination)
        report['artifacts'][name] = {'file': destination.name, 'source': source, 'bytes': length,
                                      'sha256': digest, 'device_sha256_verified': True}
        (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name + ': read and SHA-256 verified', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
