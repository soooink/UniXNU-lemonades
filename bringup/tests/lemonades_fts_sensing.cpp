#include <cassert>
#include <cstdio>
#include <vector>
#include "../devices/lemonades/package/touch/LemonadesFtsSensing.h"
int main(){
 // A transport failure may overwrite part of its destination; never expose it.
 for(unsigned fail=0;fail<=2;++fail){
  unsigned calls=0;
  auto m=lemonades_fts_read_modes([&](const uint8_t *w,unsigned wn,uint8_t *r,unsigned rn){
   assert(wn==2 && rn==7 && w[0]==0xc1 && w[1]==(calls?8:5));++calls;
   for(unsigned i=0;i<rn;++i)r[i]=uint8_t(i+10*calls);
   return calls==fail?77U:0U;
  });
  assert(calls==(fail==1?1U:2U));
  assert(m.validMask==(fail==1?0U:fail==2?1U:3U));
  assert(m.modeResult==(fail==1?77U:0U));
  assert(m.gripResult==(fail==1?0x100U:fail==2?77U:0U));
  for(unsigned i=0;i<7;++i){
   assert(m.mode[i]==(fail==1?0U:i+10));
   assert(m.grip[i]==(fail?0U:i+20));
  }
  assert(m.mode[7]==0 && m.grip[7]==0);
 }
 for(unsigned failure:{0U,19U}){
  unsigned calls=0;
  assert(lemonades_fts_default_charge_mode([&](const uint8_t *w,unsigned n){
   ++calls;assert(n==3 && w[0]==0xa2 && w[1]==2 && w[2]==0);return failure;
  })==failure);assert(calls==1);
 }
 const std::vector<std::vector<uint8_t>> initial={{0xa0,0,1},{0xa2,3,0,0,0,3},{0xa0,0,0},{0xa0,0,1}};
 const unsigned errors[]={9,10,13,14};
 for(bool first:{false,true})for(unsigned fail=0;fail<=4;++fail){
  unsigned completed=99,attempts=0,sleeps=0;
  auto write=[&](const uint8_t *w,unsigned n){
   assert(attempts<(first?4U:2U));assert(std::vector<uint8_t>(w,w+n)==initial[attempts]);
   if(attempts==3)assert(sleeps==1);
   ++attempts;return attempts==fail?12:0;
  };
  auto sleep=[&](unsigned ms){assert(ms==50);assert(first&&attempts==3&&completed==3);++sleeps;};
  unsigned result=lemonades_fts_start_sensing(first,write,sleep,&completed),total=first?4:2;
  if(fail && fail<=total){assert(result==errors[fail-1]);assert(completed==fail-1);assert(attempts==fail);}
  else{assert(result==0);assert(completed==total);assert(attempts==total);}
  assert(sleeps==(first&&(!fail||fail==4)?1U:0U));
 }
 puts("PASS: native sensing order, failures, seven-byte mode read isolation, bounded default charger command");
}
