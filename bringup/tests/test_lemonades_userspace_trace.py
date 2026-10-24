"""Actual C wire encoder, ring bounds and honest handling of damaged records."""
from pathlib import Path
import re,struct,subprocess,sys,tempfile,unittest,zlib
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from lemonades_userspace_trace import decode_userspace
class UserTraceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.t=tempfile.TemporaryDirectory(prefix='lemonades-user-wire-');w=Path(cls.t.name)
  source=r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "LemonadesUserWire.h"
int main(int argc,char **argv){assert(argc==2);FILE*f=fopen(argv[1],"wb");assert(f);const unsigned total=0x200000,cap=total-12;
 unsigned char*arena=malloc(total+64);assert(arena);uint32_t*h=(void*)(arena+32);
 for(unsigned k=0;k<2;++k){memset(arena,0xa5,total+64);h[0]=0x43474244;h[1]=k?cap-3:0;h[2]=k?cap:0;uint64_t v[64]={1,k+1,120};
 if(!k){v[3]=0;v[4]=4096;v[5]=56360960;v[6]=55000000;v[7]=54000000;v[10]=(1<<4)|(1<<6)|(1<<7)|(1<<8);v[12]=3;assert(lemonades_user_wire(h,"DATA",1,v,64));}
 else{v[3]=2;v[4]=240;v[5]=28;memcpy(v+8,"pkd",4);memcpy(v+12,"/private/var/containers/Test",29);assert(lemonades_user_wire(h,"USER",2,v,48));}
 unsigned char*data=(void*)(h+3);unsigned start=h[2]==cap?h[1]:0;for(unsigned i=0;i<h[2];++i)fputc(data[(start+i)%cap],f);
 for(unsigned i=0;i<32;++i)assert(arena[i]==0xa5&&arena[total+32+i]==0xa5);
 unsigned before=h[1];assert(!lemonades_user_wire(h,"USER",0,v,48));assert(!lemonades_user_wire(h,"DATA",1,v,65));assert(h[1]==before);
 }free(arena);fclose(f);}
'''
  p=w/'a.c';p.write_text(source);exe=w/'a';subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(ROOT/'devices/lemonades/package/boot-progress'),str(p),'-o',str(exe)],check=True)
  output=w/'raw';subprocess.run([str(exe),str(output)],check=True);cls.raw=output.read_bytes()
 @classmethod
 def tearDownClass(cls):cls.t.cleanup()
 def test_wire_and_wrapped_bounds(self):
  d=decode_userspace(self.raw);self.assertEqual(len(d['data_observations']),1);self.assertEqual(len(d['user_events']),1);self.assertTrue(d['user_events'][0]['complete']);self.assertEqual(d['user_events'][0]['name_prefix'],'pkd');self.assertEqual(d['data_observations'][0]['available_bytes'],54000000*4096)
 def test_missing_free_space_not_invented(self):
  raw=re.sub(rb'\nUMI DATA 01 07 [0-9a-f]{16} [0-9a-f]{8}\n',b'',self.raw);o=decode_userspace(raw)['data_observations'][0];self.assertFalse(o['complete']);self.assertIsNone(o['available_bytes']);self.assertEqual(o['missing_fields'],[7])
 def test_conflict_rejected_without_majority_vote(self):
  crc=zlib.crc32(struct.pack('<BBQ',1,7,1));extra=f'\nUMI DATA 01 07 {1:016x} {crc:08x}\n'.encode();d=decode_userspace(self.raw+extra);self.assertEqual(d['conflicts'],[['DATA',1]]);self.assertFalse(d['data_observations'])
 def test_corrupted_copy_needs_another_valid_copy(self):
  raw=self.raw.replace(f'{54000000:016x}'.encode(),f'{54000001:016x}'.encode(),1);d=decode_userspace(raw);self.assertEqual(len(d['user_events']),1);self.assertEqual(d['crc_rejected_records'],1)
if __name__=='__main__':unittest.main()
