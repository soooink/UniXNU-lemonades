#include <cassert>
#include <cstdio>
#include <cstring>
#include "../devices/lemonades/package/touch/LemonadesFtsSysInfo.h"
int main(){
 uint8_t data[208]={};data[0]=0xa5;data[1]=1;
 auto set=[&](unsigned i,unsigned n){data[i]=n&255;data[i+1]=n>>8;};
 set(10,0x3936);set(14,0x1234);set(16,0x128);set(18,0x4053);set(20,0x4b);set(24,0xffff);
 data[28]=5;data[29]=6;data[30]=7;data[31]=9;data[32]=0xaa;data[33]=0xbb;data[34]=0xcc;
 set(80,1080);set(82,2340);data[84]=32;data[85]=18;set(136,0x1000);set(144,0x2000);set(152,0x3000);
 for(unsigned i=0;i<3;++i){set(138+8*i,0x4100+i*0x100);set(142+8*i,0x5100+i*0x100);}
 auto s=lemonades_fts_sysinfo(data,208);assert(s.valid&&s.fw==0x128&&s.svn==0x4053&&s.config==0x4b&&s.cx==0xffff);
 for(unsigned i=0;i<3;++i){assert(s.filtered[i]==0x4100+i*0x100);assert(s.baseline[i]==0x5100+i*0x100);}
 assert(s.cfgAfe==5&&s.cxAfe==6&&s.panelAfe==7&&s.protocol==9);assert(s.resX==1080&&s.resY==2340&&s.tx==32&&s.rx==18);
 assert(s.msRaw==0x1000&&s.ssTxRaw==0x2000&&s.ssRxRaw==0x3000);
 for(unsigned n=0;n<208;++n)assert(!lemonades_fts_sysinfo(data,n).valid);
 data[0]=0;assert(!lemonades_fts_sysinfo(data,208).valid);data[0]=0xa5;data[1]=0;assert(!lemonades_fts_sysinfo(data,208).valid);data[1]=1;
 // Every read failure is isolated; no failed chunk bytes may be published.
 for(unsigned fail=0;fail<=14;++fail){unsigned calls=0;
  auto r=lemonades_fts_read_controller([&](const uint8_t *cmd,unsigned wn,uint8_t *dst,unsigned rn){
   ++calls;if(cmd[0]==0xa6){assert(wn==3&&rn==16);unsigned offset=(unsigned)cmd[1]*256+cmd[2];assert(offset==(calls-1)*16&&offset+rn<=208);}
   else{const uint8_t crc[]={0xfa,0x20,0,0,0x78};assert(wn==5&&rn==1&&!memcmp(cmd,crc,5));}
   if(calls==fail){memset(dst,0xee,rn);return 1;}
   if(cmd[0]==0xa6)memcpy(dst,data+cmd[2],rn);else dst[0]=3;return 0;
  });
  unsigned chunks=fail&&fail<=13?fail-1:13;
  assert(r.bytesRead==chunks*16&&r.chunkMask==((1U<<chunks)-1));
  assert(!memcmp(r.bytes,data,r.bytesRead));for(unsigned i=r.bytesRead;i<208;++i)assert(r.bytes[i]==0);
  if(fail&&fail<=13)assert(r.sysResult==1&&r.crcResult==0);
  else assert(r.sysResult==0&&r.crcResult==(fail==14?1U:0U));
  assert(r.crc==(fail==14?0:3));assert(calls==chunks+1+(chunks<13?1U:0U));
 }
 puts("PASS: complete/header/bounds/AFE offsets and chunk/CRC fault isolation using production read helper");
}
