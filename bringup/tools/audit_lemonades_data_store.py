"""Audit only the intentional Data-store delta against the archived phone root."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def audit(current,ram):
    pin=json.loads((ROOT/'devices/lemonades/package/data-store/sources.json').read_text())
    for name,digest in pin['files'].items():
        if sha(ROOT/name)!=digest:raise ValueError('Pinned original Data source changed: '+name)
    previous=ROOT/'out/lemonades/xnu-entry/attempt-50'
    old=json.loads((previous/'source-build-status.json').read_text())['native_ufs_build']
    if current['profile']!='phone' or not current['disk_write_path'] or current['upstream_sources']!=old['upstream_sources']:
        raise ValueError('Data store must retain the phone root implementation and upstream inputs')
    for name,digest in old['device_sources'].items():
        if name!='tools/build_lemonades_native_ufs.py' and current['device_sources'].get(name)!=digest:
            raise ValueError('Unrelated phone transport change: '+name)
    folder=ROOT/'out/lemonades-xnu/lemonades/tree/build/native-ufs'
    if sha(folder/'NativeUfs.cpp')!=current['generated_source_sha256']:raise ValueError('Compiled UFS source changed')
    text=(folder/'NativeUfs.cpp').read_text()
    addition='#include "LemonadesUfsStore.inc"\n'
    geometry='  gStoreGeometry = { true, layout->userdataFirst, layout->userdataLast, layout->imageBytes, layout->gptEntriesLba,\n                     layout->gptHeaderCrc, layout->gptEntriesCrc, layout->gptEntryCount };\n'
    for part in (addition,geometry):
        if text.count(part)!=1:raise ValueError('Unexpected Data integration boundary')
        text=text.replace(part,'')
    if text!=(previous/'native-ufs-build/NativeUfs.cpp').read_text():
        raise ValueError('Root/transport changed beyond original store integration')
    command=(ROOT/'sources/UniXNU/drivers/NativeUfs/RootCommands.h').read_text()
    command=command.replace('uint32_t blocks, const void *src)\n','uint32_t blocks, const void *src, bool fua = false)\n')
    command=command.replace('uint8_t cdb[10] = { 0x2a, 0,','uint8_t cdb[10] = { 0x2a, uint8_t (fua ? 8 : 0),')
    if (folder/'RootCommands.h').read_text()!=command or sha(folder/'RootCommands.h')!=current['commands_sha256']:
        raise ValueError('Command path must preserve originals plus the exact FUA bit')
    store=(ROOT/'devices/lemonades/package/data-store/UfsStore.inc').read_text()
    for line in ('constexpr uint64_t kLogReserveBlocks = 8192;\n','constexpr uint64_t kExportBlocks = 65536;\n','uint64_t gLogRegionFirst, gLogRegionBlocks;\n'):
        if store.count(line)!=1:raise ValueError('Unexpected original log declarations')
        store=store.replace(line,'')
    if store!=(folder/'LemonadesUfsStore.inc').read_text() or sha(folder/'LemonadesUfsStore.inc')!=current['data_store_generated_sha256']:
        raise ValueError('Store differs from pinned original implementation')
    source=ROOT/'devices/lemonades/package/data-store/NativeRamBlock/NativeRamBlock.cpp'
    generated=ROOT/'out/lemonades-xnu/lemonades/tree/build/native-ram-block/NativeRamBlock.cpp'
    if not ram['persistent_ufs_store'] or ram['absent_optional_store_imports'] or source.read_bytes()!=generated.read_bytes():
        raise ValueError('All six real store providers must remain connected')
    for name,digest in ram['source_files'].items():
        if sha(ROOT/name)!=digest:raise ValueError('RAM driver input changed after compilation: '+name)
    if sha(generated)!=ram['generated_source_sha256']:raise ValueError('RAM driver changed after compile')
    for label,report,where in [('UFS',current,folder),('RAM',ram,generated.parent)]:
        obj=where/('NativeUfs.o' if label=='UFS' else 'NativeRamBlock.o')
        archive=where/('libNativeUfs.a' if label=='UFS' else 'libNativeRamBlock.a')
        if sha(obj)!=report['object_sha256'] or sha(archive)!=report['archive_sha256']:raise ValueError(label+' object/archive changed')
    return {'status':'passed_exact_source_delta_checks','original_root_transport_preserved':True,'original_data_driver_preserved':True,'qemu_run':False,'hardware_write_tested':False}
