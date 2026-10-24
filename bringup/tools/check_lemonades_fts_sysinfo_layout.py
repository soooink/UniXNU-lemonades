#!/usr/bin/env python3
"""Derive byte offsets from the pinned original C parser, not an audit note."""
import argparse,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'out/lemonades/rea-touch-20261021/source-audit/official-lemonades-q-oss/drivers/input/touchscreen/fts_521/fts_lib/ftsCore.c'
SHA='871855986aadfdaa0941e67770b8c138de8dea70ee363a7e1c51c87cae4f7234'
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==SHA
 header=SOURCE.with_name('ftsCore.h').read_text()
 die=int(re.search(r'#define\s+DIE_INFO_SIZE\s+(\d+)',header)[1]);external=int(re.search(r'#define\s+EXTERNAL_RELEASE_INFO_SIZE\s+(\d+)',header)[1])
 release=external+int(re.search(r'#define\s+RELEASE_INFO_SIZE\s+\(EXTERNAL_RELEASE_INFO_SIZE \+ (\d+)\)',header)[1])
 assert die==release==16
 text=raw.decode();start=text.index('index += 4;',text.index('int readSysInfo('));end=text.index('Parsed %d bytes!',start)
 pattern=r'index\s*\+=\s*(?P<inc>\d+)|u8ToU(?:16|32)\(\s*&data\[index\],\s*&systemInfo\.(?P<num>\w+)\s*\)|systemInfo\.(?P<byte>\w+)\s*=\s*data\[index\+\+\]|for\s*\(i = 0; i < (?P<array>DIE_INFO_SIZE|RELEASE_INFO_SIZE); i\+\+\)'
 index=0;fields={}
 for m in re.finditer(pattern,text[start:end]):
  if m['inc']:index+=int(m['inc'])
  elif m['array']:index+=die if m['array']=='DIE_INFO_SIZE' else release
  elif m['num']:fields[m['num']]=index
  else:fields[m['byte']]=index;index+=1
 assert index==208,index
 expected={'u16_chip0Id':10,'u16_chip1Id':14,'u16_fwVer':16,'u16_svnRev':18,'u16_cfgVer':20,'u16_cxVer':24,
 'u8_cfgAfeVer':28,'u8_cxAfeVer':29,'u8_panelCfgAfeVer':30,'u8_protocol':31,'u16_scrResX':80,'u16_scrResY':82,
 'u8_scrTxLen':84,'u8_scrRxLen':85,'u16_msTchRawAddr':136,'u16_ssTchTxRawAddr':144,'u16_ssTchRxRawAddr':152,
 'u16_msTchFilterAddr':138,'u16_msTchBaselineAddr':142,'u16_ssTchTxFilterAddr':146,'u16_ssTchTxBaselineAddr':150,'u16_ssTchRxFilterAddr':154,'u16_ssTchRxBaselineAddr':158}
 for name,offset in expected.items():assert fields[name]==offset,(name,fields[name],offset)
 args.output.write_text(json.dumps({'passed':True,'source':str(SOURCE),'source_sha256':SHA,'source_header_sha256':hashlib.sha256(SOURCE.with_name('ftsCore.h').read_bytes()).hexdigest(),'parser_size':index,'fields':fields,'checked_port_offsets':expected},indent=2)+'\n')
 print('PASS: original C parser-derived offsets; AFE28/29/30, resolution80/82, frames136/144/152')
if __name__=='__main__':main()
