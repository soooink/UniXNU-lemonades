// Run the production queue driver against a fault-injectable MMIO/DMA device.
// This is a host boundary test, not a hardware/emulator boot qualification.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include "../devices/lemonades/package/touch/LemonadesFtsGpiCore.h"
using IOOptionBits=unsigned;using IOByteCount=uint64_t;
constexpr unsigned kernel_task=0,kIODirectionInOut=1,kIOMemoryPhysicallyContiguous=2,kIOMemoryMapperNone=4;
constexpr uint64_t gPhysBase=0x80000000,gPhysSize=0x130000000;
constexpr int EFI_SUCCESS=0,EFI_DEVICE_ERROR=2,EFI_INVALID_PARAMETER=3,EFI_ACCESS_DENIED=6,EFI_NOT_READY=8;
alignas(16384) static uint8_t buffer[0x4000];
constexpr uint64_t dmaPa=0x1a0000000ULL;
struct IOBufferMemoryDescriptor {
 static IOBufferMemoryDescriptor *inTaskWithOptions(unsigned,unsigned,unsigned n,unsigned align){
  assert(n==sizeof buffer && align==sizeof buffer);static IOBufferMemoryDescriptor d;return &d;}
 void *getBytesNoCopy(){return buffer;}
 uint64_t getPhysicalSegment(unsigned,IOByteCount *n,unsigned){*n=sizeof buffer;return dmaPa;}
};
static uint64_t now;static std::map<uintptr_t,uint32_t> regs;
static unsigned head[2],evProducer,doorbells;
static uint64_t rxTre;static unsigned rxBytes;static bool stretch;
static unsigned fault;
static uint64_t GetPerformanceCounter(){return now+=100;}
static uint64_t GetTimeInNanoSecond(uint64_t ticks){return ticks;}
static void MicroSecondDelay(unsigned us){now+=uint64_t(us)*1000;}
static void lemonadesGpiDmaSync(void *p,unsigned n){assert((uint8_t *)p>=buffer && (uint8_t *)p+n<=buffer+sizeof buffer);}
static uint32_t MmioRead32(uintptr_t address){return regs[address];}
static void emit(unsigned c,uint64_t tre,unsigned bytes,unsigned code){
 if(fault==1)return; // no completion / command timeout
 LemonadesGpiTre ev={{uint32_t(tre),uint32_t(tre>>32),(code<<24)|bytes,(c<<24)|0x220000U}};
 if(fault==2 && c==1)--ev.d[2];
 if(fault==3 && c==1)ev.d[0]+=16;
 if(fault==4)ev.d[3]|=0x40;
 memcpy(buffer+evProducer*16,&ev,16);evProducer=(evProducer+1)%256;
 regs[0xa1b010]=uint32_t(dmaPa+evProducer*16);regs[0xa1b014]=uint32_t(dmaPa>>32);
}
static void MmioWrite32(uintptr_t a,uint32_t v){
 if(a==0x118600){regs[a]=v&~1U;return;}
 if(a==0xa1d0a0 || a==0xa1d0a4){regs[a-0x10]&=~v;return;}
 if(a==0xa1d008 || a==0xa1d010){
  bool ev=a==0xa1d010;unsigned c=v&255,opcode=v>>24;unsigned s=opcode==0?1:opcode==1?2:3;
  if(opcode==2 && fault==5)return;
  uintptr_t ctx=ev?0xa1b000:0xa1a000+0x80*c;
  regs[ctx]=(regs[ctx]&~0xf00000U)|(s<<20);regs[ev?0xa1d094:0xa1d090]|=1U<<c;return;
 }
 if(a==0xa1a000 || a==0xa1a080 || a==0xa1b000){regs[a]=(v&~0xf00000U)|(regs[a]&0xf00000);return;}
 regs[a]=v;
 if(a==0xa1b008){regs[0xa1b010]=v;regs[0xa1b014]=uint32_t(dmaPa>>32);}
 if(a!=0xa1c000 && a!=0xa1c008)return;
 ++doorbells;unsigned c=(a==0xa1c008),off=0x1000+c*0x400;
 unsigned end=(v-uint32_t(dmaPa+off))/16;assert(end<64);
 while(head[c]!=end){uint64_t at=dmaPa+off+head[c]*16;LemonadesGpiTre t;
  memcpy(&t,buffer+off+head[c]*16,16);head[c]=(head[c]+1)%64;
  unsigned type=(t.d[3]>>16)&255;
  if(c){assert(type==0x10);rxTre=at;rxBytes=t.d[2];continue;}
  if(type==0x22){assert(t.d[0]==0x0318070a);continue;}
  if(type==0x20){
   if((t.d[0]&255)==1){stretch=t.d[0]&0x04000000;continue;}
   assert(stretch && rxTre && rxBytes==t.d[2]);stretch=false;
   memset(buffer+0x3000,0x5a,rxBytes);emit(1,rxTre,rxBytes,2);emit(0,at,0,4);rxTre=0;
  }else{assert(type==0x10);emit(0,at,t.d[2],2);}
 }
}
namespace gpi {
#include "../devices/lemonades/package/touch/LemonadesFtsGpi.inc"
}
static void reset(){
 now=0;regs.clear();head[0]=head[1]=evProducer=doorbells=0;rxTre=0;fault=0;
 regs[0xa94068]=0x303;regs[0xa94064]=1;regs[0x118614]=1;regs[0x11861c]=0x100000;regs[0x118008]=0x80000002;
 regs[0x15000020]=(1U<<30)|(1U<<27)|16;regs[0x15000024]=8;regs[0x15000028]=0x1222;
 regs[0x15000800]=0x800000e0;regs[0x15000c00]=7;
 for(unsigned b=0;b<8;++b)regs[0x15000000+(2+b)*4096]=0xe0;
 gpi::memory=nullptr;gpi::data=nullptr;gpi::physical=gpi::base=0;gpi::instance=~0U;
 gpi::phase=gpi::result=gpi::clockLevel=gpi::smmuResult=gpi::completed=gpi::transactions=0;
 gpi::wp[0]=gpi::wp[1]=gpi::eventRp=gpi::allocatedMask=0;
 gpi::ready=gpi::poisoned=gpi::configSent=gpi::eventAllocated=false;
 gpi::smmuPlan=LemonadesTouchSmmuPlan{};
}
int main(){
 reset();assert(gpi::initialize());uint8_t w=0x86,r[208];
 assert(gpi::smmuPlan.bank==6 && gpi::smmuPlan.oldSctlr==0xe0);
 assert(regs[0x15008000]==0 && regs[0x15009000]==0xe0 && regs[0x15000c00]==7);
 for(unsigned i=0;i<600;++i){memset(r,0,sizeof r);assert(gpi::transfer(&w,1,r,sizeof r)==0);for(auto v:r)assert(v==0x5a);}
 assert(gpi::transactions==600);assert(gpi::shutdown());assert(gpi::poisoned && gpi::memory);
 for(unsigned f=1;f<=4;++f){reset();assert(gpi::initialize());fault=f;memset(r,0x77,sizeof r);
  assert(gpi::transfer(&w,1,r,sizeof r));for(auto v:r)assert(v==0x77);
  unsigned before=doorbells;assert(gpi::poisoned && gpi::memory);
  assert(gpi::transfer(&w,1,r,sizeof r));assert(doorbells==before);}
 reset();regs[0x118004]=0x80000002;assert(!gpi::initialize());assert(gpi::clockStep==1 && gpi::result==101 && !gpi::memory);
 reset();for(unsigned i=0;i<8;++i)regs[0x11861c+i*4]=0x101;assert(!gpi::initialize());assert(gpi::result==105 && !gpi::memory);
 reset();regs[0xa1e000]=2<<20;assert(!gpi::initialize());assert(gpi::phase==2 && !gpi::memory); // another active GPII
 reset();for(unsigned b=1;b<7;++b)regs[0x15000000+(2+b)*4096]=0xe1;
 assert(!gpi::initialize());assert(gpi::phase==4 && gpi::smmuResult==4 && doorbells==0 && regs[0x15000c00]==7);
 reset();assert(gpi::initialize());fault=5;assert(!gpi::shutdown());assert(gpi::memory && gpi::poisoned);
 puts("PASS: production GPI 600 combined reads/ring wraps, timeout/short/stale/NACK no-copy, quarantine, foreign-channel guard");
}
