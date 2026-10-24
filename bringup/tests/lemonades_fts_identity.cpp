#include <cassert>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "../devices/lemonades/package/touch/LemonadesFtsIdentity.h"
struct Bus {
 unsigned calls=0,fail=0,alter=0,echo=0;bool stuck=false;uint64_t time=0;
 uint16_t counter=1;
 unsigned transfer(const uint8_t *w,unsigned wn,uint8_t *r,unsigned rn){
  ++calls;if(calls==fail){if(rn)memset(r,0xcc,rn);return 77;}
  if(!rn){assert(wn==3 && w[0]==0xa4 && w[1]==6 && w[2]==0x70);return 0;}
  memset(r,0,rn);
  if(w[0]==0x86){assert(wn==1 && rn==8);
   if(echo==1)return 0;
   const uint8_t event[]={0x43,1,0xa4,6,0x70,0,0,0};memcpy(r,event,8);
   if(echo==2)r[4]=0x30;if(echo==3)r[0]=3;if(echo==4)r[0]=0xf3;return 0;
  }
  assert(wn==3 && w[0]==0xa6 && w[1]==0 && w[2]==0);
  assert(rn==4 || rn==28);uint16_t count=rn==4?counter:uint16_t(counter+1);
  r[0]=0xa5;r[1]=rn==4?1:0x70;r[2]=count&255;r[3]=count>>8;
  if(rn==4){if(alter==1)r[0]=0;return 0;}
  const uint8_t identity[]={0x53,0x42,0x32,1,0x74,2,0x32,1};memcpy(r+20,identity,8);
  if(alter==2)r[0]=0;if(alter==3)r[1]=1;if(alter==4)r[4]=0x30;
  if(alter==5)r[2]^=1;if(alter>=6 && alter<=13)r[20+alter-6]^=1;
  return 0;
 }
 LemonadesFtsIdentity run(){return lemonades_fts_read_identity(
  [&](const uint8_t *w,unsigned wn,uint8_t *r,unsigned rn){return transfer(w,wn,r,rn);},
  [&](unsigned ms){assert(ms==10 || ms==2);if(!stuck)time+=uint64_t(ms)*1000000;},
  [&](){return time;});}
};
int main(){
 for(uint16_t count:{uint16_t(1),uint16_t(65535)}){
  Bus b;b.counter=count;auto r=b.run();assert(r.result==0 && r.flags==63 && r.polls==1 && b.calls==4);
 }
 const unsigned errors[]={0,1,3,4,7};
 for(unsigned fail=1;fail<=4;++fail){Bus b;b.fail=fail;auto r=b.run();assert(r.result==errors[fail] && b.calls==fail);for(auto x:r.identity)assert(x==0);}
 for(unsigned alter=1;alter<=13;++alter){Bus b;b.alter=alter;auto r=b.run();assert(r.result==(alter==1?2U:alter<6?8U:9U));assert(r.flags!=63);if(alter==1)assert(b.calls==1);}
 for(unsigned echo=1;echo<=4;++echo)for(bool stuck:{false,true}){
  Bus b;b.echo=echo;b.stuck=stuck;auto r=b.run();assert(r.result==(echo<=2?6U:5U));assert(r.polls<51 && b.calls<53);for(auto x:r.identity)assert(x==0);
 }
 puts("PASS: factory identity load bounded; all IO/echo/header/counter/profile failures rejected; no NVM writes");
}
