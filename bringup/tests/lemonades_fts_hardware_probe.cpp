#include <assert.h>
#include "../devices/lemonades/package/touch/LemonadesFtsHardwareProbe.h"
int main(){
 const uint8_t expected[]={0,1,0x29,0x2d,0x30,0x32,0x25,0x78};
 for(unsigned fail=0;fail<=8;++fail){
  unsigned calls=0;
  auto r=lemonades_fts_hardware_probe([&](const uint8_t *w,unsigned wn,uint8_t *out,unsigned rn){
   assert(wn==5 && rn==1 && w[0]==0xfa && w[1]==0x20 && !w[2] && !w[3]);
   assert(w[4]==expected[calls]);unsigned n=calls++;
   *out=uint8_t(n+0x30);return n==fail?7U:0U;
  });
  assert(calls==(fail<8?fail+1:8));assert(r.validMask==(1U<<fail)-1);
  assert(r.result==(fail<8?7U:0U));
  for(unsigned n=0;n<8;++n)assert(r.values[n]==(n<fail?n+0x30:0));
 }
}
