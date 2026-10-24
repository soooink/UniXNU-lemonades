"""Explicit receipts for historical binaries intentionally removed by user cleanup.

New kernels, source files and Apple executable bytes are always checked directly.
Only named deleted historical artifacts can use a hash from the complete attempt
55 audit archive. These are prior-evidence receipts, never a fresh runtime test.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class HistoricalReceipts:
 def __init__(self):
  self.used={};self.expected={}
  self.archive=ROOT/'out/lemonades/xnu-entry/attempt-55'
  self.index=json.loads((self.archive/'sha256.json').read_text())
  from reuse_lemonades_storage import ARCHIVE_INDEX_SHA256
  if self.digest(self.archive/'sha256.json')!=ARCHIVE_INDEX_SHA256:raise ValueError('Retained audit index changed')
  record=self.read('verification.json')
  if record['status']!='host_verified_prelink' or self.digest(self.archive/'kernel.macho')!=record['sha256']:
   raise ValueError('Retained verified phone kernel changed')
  cleanup=json.loads((ROOT/'out/lemonades/generated-artifact-cleanup-20261021.json').read_text())
  self.deleted=set(cleanup['deleted_files'])
  for name in ('pmgr','gic','screen','native-ufs','owner-root','lock-trace','exec-trace','trustcache'):
   filename=name+'-qemu-baseline.json';archived='trustcache/qemu-baseline.json' if name=='trustcache' else filename;b=self.read(archived)
   p=ROOT/'out/lemonades'/filename
   if self.digest(p)!=self.index[archived]:raise ValueError('Historical baseline changed: '+name)
   if b.get('kernel') and b.get('kernel_sha256'):self.expected[b['kernel']]=b['kernel_sha256']
   source=b.get('source_archive');expected=b.get('source_archive_index_sha256')
   if source and expected:
    directory=ROOT/source;indexfile=directory/'sha256.json'
    if self.digest(indexfile)!=expected:raise ValueError('Historical source index changed')
    for relative,digest in json.loads(indexfile.read_text()).items():self.expected[str(directory/relative)]=digest
   for relative,digest in b.get('evidence_files',{}).items():self.expected[str(ROOT/relative)]=digest
 def read(self,name):
  p=self.archive/name
  if self.digest(p)!=self.index[name]:raise ValueError('Retained receipt changed: '+name)
  return json.loads(p.read_text())
 @staticmethod
 def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
 def sha(self,p):
  p=Path(p)
  if p.exists():return self.digest(p)
  key=str(p.resolve())
  if key not in self.deleted or key not in self.expected or p.suffix not in ('.macho','.o','.a','.img','.fd'):
   raise FileNotFoundError('No qualified cleanup receipt for '+key)
  self.used[key]=self.expected[key]
  return self.expected[key]
