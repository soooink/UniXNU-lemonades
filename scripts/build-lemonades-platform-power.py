#!/usr/bin/env python3
"""Build the opt-in, guarded sheng original-PMGR integration instrument."""
import argparse
import os
import hashlib
import shutil
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/lemonades-platform-power'
OUT.mkdir(parents=True, exist_ok=True)
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--candidate', type=Path)  # optional: absent on a fresh workspace (audit skipped)
p.add_argument('--donor', type=Path, required=True)
a = p.parse_args()
sys.path.insert(0, str(ROOT / 'kits/NativePrelink'))
from native_prelink import macho, backed_offset, exports


def run(command, **kwargs):
    result = subprocess.run([str(v) for v in command], timeout=300,
                            capture_output=True, text=True)
    if result.returncode:
        # Surface the compiler diagnostics instead of swallowing them.
        print(result.stdout[-4000:], end='')
        print(result.stderr[-4000:], file=sys.stderr, end='')
        raise SystemExit(result.returncode)
    return result.stdout


def require(value, message):
    if not value:
        raise SystemExit(message)


if a.candidate and a.candidate.is_file():
    print(run(['python3', ROOT / 'scripts/audit-lemonades-pmgr-contract.py', '--candidate', a.candidate, '--donor', a.donor, '--output', OUT / 'contract.json'], text=True), end='')
else:
    print('audit skipped: no candidate kernel yet')
header = '''// Generated exact storage/slot ABI; private fields stay opaque.
#pragma once
#include <IOKit/IOPMGR.h>
class ApplePMGR : public IOPMGR {
 OSDeclareAbstractStructors(ApplePMGR)
 unsigned char originalPrivate[0x4b8a8-sizeof(IOPMGR)];
public:
'''
guards = ''
for i in range(177, 340):
    if i == 320:
        header += ' virtual uint32_t readAon();\n'
    elif i == 321:
        header += ' virtual void writeAon(uint64_t);\n'
    else:
        header += f' virtual void opaque{i}() = 0;\n'
        guards += f' void opaque{i}() override {{ unavailable({i}); }}\n'
header += '};\nstatic_assert(sizeof(ApplePMGR)==0x4b8a8,"Original provider storage");\n'
(OUT / 'OriginalPMGRABI.h').write_text(header)
(OUT / 'GuardedPMGRSlots.inc').write_text(guards)
source = ROOT / 'kits/lemonades/LemonadesPlatformPower.cpp'
obj = OUT / 'LemonadesPlatformPower.o'
record_dir = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT'
record = json.loads((record_dir / 'IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
command, i = [], 0
arguments = record['arguments']
while i < len(arguments):
    arg = arguments[i]
    if arg == record['file']:
        command.append(source)
    elif arg == '-o':
        command += ['-o', obj]
        i += 1
    elif arg == '-include':
        # The cpo record ran with cwd in the kernel object directory where
        # meta_features.h is generated; this compile runs elsewhere, so make
        # the forced include absolute.
        included = Path(arguments[i + 1])
        if not included.is_absolute():
            included = record_dir / included
        command += ['-include', included]
        i += 1
    elif arg == '-Xclang' and arguments[i + 1].startswith('-W'):
        i += 1
    elif not arg.startswith('-W'):
        command.append(arg)
    i += 1
command += ['-Wall', '-Wextra', '-Werror', '-Wno-format',
            '-Wno-unnecessary-virtual-specifier',
            # Xcode 26 makes the umi-era diagnostic format strings hard errors;
            # they print observation slots only.
            '-Wno-unused-parameter', '-Wno-c99-designator',
            '-Wno-reorder-init-list', '-Wno-deprecated-enum-enum-conversion',
            # meta_features.h lives in the kernel object dir with angled
            # includes of its own (config_dtrace.h, mach_assert.h, ...).
            '-I', record_dir,
            '-I', ROOT / '.cache/xnu-work/osfmk',
            '-I', ROOT / 'build/xnu/ios-obj/EXPORT_HDRS/osfmk',
            '-I', OUT]
(OUT / 'compile-command.json').write_text(json.dumps([str(v) for v in command], indent=2) + '\n')
run(command, cwd=record['directory'])
raw = obj.read_bytes()
info = macho(raw)
require(info['kind'] == 1, 'Require actual ARM64 subtype-0 Mach-O object')
build_version = [struct.unpack_from('<2I', raw, at + 8) for cmd, at, _ in info['commands'] if cmd == 0x32]
require(build_version == [(2, 0x110000)], 'Require iOS17 build target')
sym_at = next(at for cmd, at, _ in info['commands'] if cmd == 2)
at, count, strings, _ = struct.unpack_from('<4I', raw, sym_at + 8)
symbols = []
for i in range(count):
    ix, kind, _, _, address = struct.unpack_from('<IBBHQ', raw, at + i * 16)
    symbols.append((raw[strings + ix:raw.index(b'\0', strings + ix)].decode(), address, kind))
vtable = next(va for name, va, _ in symbols if name == '__ZTV16UmiPlatformPower')
relocations = {}
for segment in info['segments']:
    for section in segment['sections']:
        if section['va'] <= vtable < section['va'] + section['size']:
            at, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
            for i in range(count):
                offset, bits = struct.unpack_from('<2I', raw, at + i * 8)
                if bits >> 27 & 1 and bits >> 28 == 0 and bits >> 25 & 3 == 3:
                    relocations[section['va'] + offset] = symbols[bits & 0xffffff][0]
entries = [relocations.get(vtable + 16 + i * 8) for i in range(340)]
require(all(entries) and vtable + 16 + 340 * 8 not in relocations, 'Exact 340-entry provider table')
reference = a.candidate
if reference is None:
    # No prelink plan on a fresh workspace; the source kernel provides the
    # same vtable layout for the late-binding table.
    reference = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf'
candidate = reference.read_bytes()
meta = macho(candidate)
native_names = {n: va for va, names in exports(candidate, meta).items() for n in names}


def ptr(va):
    return struct.unpack_from('<Q', candidate, backed_offset(meta['segments'], va, 8, len(candidate)))[0]


bindings = {'__ZN9ApplePMGRC2EPK11OSMetaClass': 0xfffffff0049f003c,
            '__ZN9ApplePMGRD2Ev': 0xfffffff0049f019c,
            '__ZN9ApplePMGR10gMetaClassE': 0xfffffff006adf490}
for slot, name in enumerate(entries):
    if slot in (0, 1, 7) or 168 <= slot < 340 and slot not in (320, 321):
        require('16UmiPlatformPower' in name, f'Own guard/lifecycle required at slot {slot}')
    elif slot in (320, 321):
        require('9ApplePMGR' in name, 'Only actual original AON implementations inherited')
        if a.candidate is not None:
            bindings[name] = ptr(0xfffffff005ce26d8 + slot * 8)
        else:
            # Deterministic donor layout (same slide): the original AON
            # implementations read from our qualified prelinked kernel.
            bindings[name] = {320: 0xfffffff004a20fbc, 321: 0xfffffff004a20fc4}[slot]
    else:
        require(native_names.get(name) == ptr(native_names['__ZTV6IOPMGR'] + 16 + slot * 8),
                f'Native IOPMGR/IOService entry differs at {slot}')
undefined = {n for n, _, k in symbols if k == 1 and 'ApplePMGR' in n}
require(undefined == set(bindings), 'All and only audited original base imports')
bindings.update({'_umi_original_pmgr_nub_create': 0xfffffff004a22568,
                 '_umi_original_pmgr_nub_read': 0xfffffff004a24adc,
                 '_umi_original_pmgr_nub_write': 0xfffffff004a230ec})
nm = shutil.which('llvm-nm') or '/opt/homebrew/opt/llvm/bin/llvm-nm'
symtab = run([nm, obj], text=True)
ctor = sorted({line.split()[2].strip() for line in symtab.splitlines()
               if len(line.split()) >= 3 and line.split()[2].startswith('__GLOBAL__sub_I_')})
require(len(ctor) == 1, f'Expected exactly one static initializer, got {ctor}')
asm = OUT / 'original-bindings.S'
asm.write_text(''.join(f'.globl {name}\n.set {name}, {va:#x}\n' for name, va in bindings.items())
               # Xcode 26 objects reference the static initializer without a
               # definition surviving objcopy; kernel kext startup never runs
               # C++ static initializers anyway.
               + f'.globl {ctor[0]}\n{ctor[0]}:\n  ret\n')
sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-isysroot', sdk, '-c', asm, '-o', OUT / 'original-bindings.o'])
late = OUT / 'LemonadesPlatformPower.late.o'
objcopy = shutil.which('llvm-objcopy') or '/opt/homebrew/opt/llvm/bin/llvm-objcopy'
# Xcode 26 objects lose the initializer definition through objcopy and
# llvm-objcopy cannot globalize it anyway; the reference is satisfied by the
# no-op definition in the bindings assembly. Only drop the init section.
run([objcopy, '--remove-section=__DATA,__mod_init_func', obj, late])
(OUT / 'late-symbols.txt').write_text(run([nm, late], text=True))


def text_section(blob):
    section = next(s for seg in macho(blob)['segments'] for s in seg['sections'] if s['name'] == '__text')
    return blob[section['fileoff']:section['fileoff'] + section['size']]


require(text_section(raw) == text_section(late.read_bytes()), 'Late registration cannot change instructions')
archive = OUT / 'libLemonadesPlatformPower.a'
archive.unlink(missing_ok=True)
run(['xcrun', 'ar', 'rcs', archive, late, OUT / 'original-bindings.o'])
# Bring-up: show exactly what the archive exports into the kernel link.
archive_syms = run([nm, '--print-map' if False else '--defined-only', archive], text=True)
print('archive symbols:', archive_syms[-1500:])
report = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
          'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
          'bindings': {name: hex(va) for name, va in bindings.items()}, 'virtual_entries': 340,
          'mode': 'opt-in lifecycle/publication/refusal instrument; not a functional power backend',
          'reference_sha256': hashlib.sha256(candidate).hexdigest(),
          'early_trace': os.environ.get('LEMONADES_EARLY_TRACE', '0') == '1',
          'runtime_qualified': False, 'original_executable_modified': False}
(OUT / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: ordinary ARM64/iOS17 build; exact native and original bindings; unimplemented power slots stop')
