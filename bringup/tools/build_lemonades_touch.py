#!/usr/bin/env python3
"""Build Mi 10 FTS and the pinned tablet HID adapter against the actual XNU ABI."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
from build_lemonades_native_ufs import compile_from
ROOT=Path(__file__).resolve().parents[1]
TREE=ROOT/'out/lemonades-xnu/lemonades/tree';SOURCE=ROOT/'devices/lemonades/package/touch'
OUT=TREE/'build/lemonades-touch';HID=TREE/'build/native-hid-input'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    qualification=Path(os.environ['LEMONADES_FTS_QUALIFICATION'])
    host_tests=json.loads(qualification.read_text())
    assert host_tests['passed'] and not host_tests['qemu_test_performed'] and host_tests['irq_log_deferral_checked']
    for name,expected in host_tests['inputs'].items():assert sha(ROOT/name)==expected,name
    OUT.mkdir(parents=True,exist_ok=True);HID.mkdir(parents=True,exist_ok=True)
    reference=ROOT/'out/lemonades-xnu/lemonades/kernel/touch-hid-reference.macho'
    plan=json.loads(reference.with_suffix('.json').read_text())
    assert sha(reference)==plan['candidate_sha256']
    assert plan['original_sha256']=='f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7'
    assert plan['original_executable_sha256']['com.apple.iokit.IOHIDFamily']=='7e4c5104814f2e773d5be13d092dec53ee44ba5a61a81264b229780406e86b72'
    bounds={}
    for segment,label in (("__TEXT_EXEC","TEXT"),("__DATA_CONST","CONST")):
        e=next(e for e in plan['extents'] if e['module']=='com.apple.iokit.IOHIDFamily' and e['segment']==segment)
        bounds[label]=(e['va'],e['va']+e['size'])
    (HID/'LemonadesHidEdgeABI.h').write_text('// Exact IOHIDFamily image bounds; no guessed runtime pointer.\n'+''.join(
        f'#define LEMONADES_HID_{label}_{side} 0x{address:x}ULL\n' for label,pair in bounds.items() for side,address in zip(('BEGIN','END'),pair)))
    # Original script checks native IOService linkage, constructor instructions,
    # handleReport ABI, 207 slots and all compiled overrides before binding.
    original=ROOT/'sources/UniXNU/scripts/build-native-hid-input.py'
    text=original.read_text().replace("ROOT=Path(__file__).resolve().parents[1]",f"ROOT=Path({str(TREE)!r})")
    begin=text.index("p=ROOT/'build/native-prelink/native-owner-ufs-cpu-desktop-v9-hid-init-candidate.macho'")
    end=text.index("b=p.read_bytes();",begin)
    text=text[:begin]+f"p=Path({str(reference)!r})\n"+text[end:]
    call="print(run(['python3',ROOT/'scripts/build-arm-driver.py','NativeHidInput'],text=True),end='')"
    assert text.count(call)==1
    text=text.replace(call,f'''sys.path.insert(0,{str(ROOT/'tools')!r})
from build_lemonades_native_ufs import compile_from
record=json.loads((ROOT/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
compile_from(record,Path({str(SOURCE/'NativeHidInput.cpp')!r}),OUT/'NativeHidInput.o',['-I',str(OUT),'-I',{str(SOURCE)!r},'-I',str(ROOT/'.cache/xnu-work/osfmk')])''')
    text=text.replace("ROOT/'drivers/NativeHidInput/NativeHidInput.cpp'",f"Path({str(SOURCE/'NativeHidInput.cpp')!r})")
    audit=OUT/'build-hid-from-upstream.py';audit.write_text(text)
    subprocess.run([sys.executable,audit],check=True)
    rec=json.loads((TREE/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
    objects=[HID/'NativeHidInput.late.o',HID/'hid-original-bindings.o']
    for name in ('LemonadesFtsTouch','HidInputProbe'):
        obj=OUT/(name+'.o')
        compile_from(rec,SOURCE/(name+'.cpp'),obj,['-I',str(SOURCE),'-I',str(TREE/'.cache/xnu-work/osfmk'),'-Wno-unused-function'])
        objects.append(obj)
    archive=OUT/'libLemonadesTouch.a';archive.unlink(missing_ok=True)
    subprocess.run(['xcrun','ar','rcs',archive,*objects],check=True)
    report=dict(reference_candidate=str(reference),reference_candidate_sha256=sha(reference),
       original_component_hashes=plan['original_executable_sha256'],
       original_hid_abi=json.loads((HID/'abi-audit.json').read_text()),
       sources={str(p.relative_to(ROOT)):sha(p) for p in sorted(SOURCE.iterdir()) if p.is_file()},
       upstream_audit_sha256=sha(original),builder_sha256=sha(Path(__file__)),
       archive_sha256=sha(archive),objects={str(p):sha(p) for p in objects},
       host_test_report=str(qualification),host_test_report_sha256=sha(qualification),
       runtime_qualified=False,qemu_test_performed=False,coordinates=[1080,2340],max_contacts=10)
    (OUT/'build-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: Mi 10 FTS and original HID ABI compiled; real touch execution pending')
if __name__=='__main__':main()
