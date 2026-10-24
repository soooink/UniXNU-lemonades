#!/usr/bin/env python3
"""Host sanitizers for original persistence/large-seed code and actual UFS commands."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'out/lemonades/attempt-51-preparation';OUT.mkdir(parents=True,exist_ok=True)
base=ROOT/'devices/lemonades/package/data-store/NativeRamBlock'
results=[]
env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0') # original identity utility exits with seed pages live
with tempfile.TemporaryDirectory(prefix='lemonades-data-host-') as tmp:
    work=Path(tmp)
    for name in ('direct','persist','seeddisk','sparse','seed-identity'):
        src=base/'Test'/f'{name}.cpp';exe=work/name
        if name=='sparse':
            # Upstream retained the old 2 GiB negative fixture after raising the parser limit.
            adjusted=work/'sparse-current-limit.cpp'
            adjusted.write_text(src.read_text().replace('0x80001000','0x10000001000ULL').replace('../SparseDisk.h',str(base/'SparseDisk.h')))
            src=adjusted
        subprocess.run(['clang++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-Wno-unused-function','-fsanitize=address,undefined',str(src),'-o',str(exe)],check=True)
        args=[str(exe)]+([str(ROOT/'out/lemonades/data-persist/data.dbr')] if name=='seed-identity' else [])
        r=subprocess.run(args,check=True,capture_output=True,text=True,env=env)
        if name=='seed-identity':
            expected=json.loads((ROOT/'out/lemonades/data-persist/data.json').read_text())['sha256']
            assert r.stdout.strip()==expected,'C++ seed identity differs from actual packed APFS metadata'
        results.append({'case':name,'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'output':r.stdout.strip(),'passed':True,'fixture_adjustment':'old rejection case now uses 1 TiB + 4 KiB' if name=='sparse' else None})
    # Reuse the original DMA/MMIO fault fixture against the actual generated header.
    fixture=work/'ufs';fixture.mkdir();(fixture/'Test').mkdir()
    old=ROOT/'sources/UniXNU/drivers/NativeUfs'
    for p in old.glob('*.h'):shutil.copyfile(p,fixture/p.name)
    shutil.copyfile(ROOT/'out/lemonades-xnu/lemonades/tree/build/native-ufs/RootCommands.h',fixture/'RootCommands.h')
    bridge=(old/'tests/RootCommandsBridge.cpp').read_text().replace('hostWrite4k(lun,lba,blocks,src);','hostWrite4k(lun,lba,blocks,src,true);')
    (fixture/'Test/RootCommandsBridge.cpp').write_text(bridge)
    source=(old/'tests/RootCommands.cpp').read_text()
    # Validate the exact CDB emitted on the device, before fault fixture DMA completion.
    needle='uint8_t *cmd=device.data()+kUcdOffset, *rsp=cmd+kRspOffset;'
    source=source.replace(needle,needle+'\n      if(cmd[0]==1 && cmd[16]==0x2a)assert(cmd[17]==8 && cmd[1]==0x20);')
    insertion='''
  reset();out.fill(0x42);
  auto before=writes;
  assert(ufs_test_write(0,100,1,out.data())==kIOReturnBadArgument && writes==before);
  assert(ufs_test_store_open(100,32));
  for(auto range: {std::pair<uint64_t,uint32_t>{99,1},{132,1},{131,2}}) {
    before=writes;assert(ufs_test_write(0,range.first,range.second,out.data())==kIOReturnBadArgument && writes==before);
  }
  before=writes;assert(ufs_test_write(1,100,1,out.data())==kIOReturnBadArgument && writes==before);
  assert(ufs_test_write(0,100,32,out.data())==0);
  assert(ufs_test_write(0,131,1,out.data())==0);
  assert(ufs_test_sync()==0);
  fault=Fault::Timeout;assert(ufs_test_write(0,100,1,out.data())!=0);assertQuarantined();
'''
    source=source.replace('  puts("PASS: actual command/queue path;',insertion+'  puts("PASS: actual command/queue path;')
    (fixture/'Test/RootCommands.cpp').write_text(source)
    exe=work/'ufs-commands'
    subprocess.run(['clang++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined',str(fixture/'Test/RootCommands.cpp'),'-o',str(exe)],check=True)
    r=subprocess.run([str(exe)],check=True,capture_output=True,text=True,env=env)
    results.append({'case':'actual-UFS-command-FUA-bounds-and-quarantine','passed':True,'output':r.stdout.strip()})
report={'qemu_run':False,'device_written':False,'cases':results,'status':'passed_all_host_checks'}
(OUT/'data-store-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
