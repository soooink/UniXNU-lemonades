#!/usr/bin/env python3
"""Reuse the unchanged, hash-verified storage objects from an installed phone build.

This supports pruning historical ABI-carrier Mach-O files without weakening an
ABI check or recompiling unrelated storage against an unaudited donor.
"""
import hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ARCHIVE_INDEX_SHA256='50cd5b93fcc81db043c4ec6dac454362e05d09f274521ffc01c8547576f669da'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def restore(attempt,tree):
    if attempt!=55:raise ValueError('Only the complete installed Hello build is supported')
    archive=ROOT/f'out/lemonades/xnu-entry/attempt-{attempt}'
    if sha(archive/'sha256.json')!=ARCHIVE_INDEX_SHA256:
        raise ValueError('Storage reuse requires the retained complete verified archive')
    index=json.loads((archive/'sha256.json').read_text())
    if sha(archive/'kernel.macho')!=index['kernel.macho']:
        raise ValueError('Archived installed kernel changed')
    folders={'native-ufs-build':'native-ufs','lemonades-root-policy-build':'lemonades-root-policy',
             'storage-providers':'lemonades-storage-providers','data-display/ram-build':'native-ram-block'}
    reports={}
    for folder,destination in folders.items():
        source=archive/folder
        if not source.is_dir():raise ValueError('Missing archived provider '+folder)
        files=list(source.iterdir())
        for p in files:
            if not p.is_file() or sha(p)!=index[str(p.relative_to(archive))]:raise ValueError('Archived provider changed '+str(p))
        report=json.loads((source/'build-report.json').read_text());reports[destination]=report
        inputs={}
        if destination=='native-ufs':
            inputs.update(report['device_sources'])
            inputs.update({'sources/UniXNU/'+n:h for n,h in report['upstream_sources'].items()})
        elif destination=='lemonades-storage-providers':inputs.update(report['sources'])
        elif destination=='native-ram-block':inputs.update(report['source_files'])
        for name,digest in inputs.items():
            if sha(ROOT/name)!=digest:raise ValueError('Cannot reuse changed storage source '+name)
        target=tree/'build'/destination;target.mkdir(parents=True,exist_ok=True)
        for p in files:shutil.copyfile(p,target/p.name)
    record=dict(source_attempt=attempt,source_archive=str(archive),archive_index_sha256=sha(archive/'sha256.json'),
                archived_phone_kernel_sha256=sha(archive/'kernel.macho'),unchanged_source_inputs_checked=True,
                copied_folders=folders,qemu_test_performed=False)
    (tree/'build/storage-reuse.json').write_text(json.dumps(record,indent=2)+'\n')
    return record
