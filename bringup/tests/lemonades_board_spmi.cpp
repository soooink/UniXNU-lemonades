#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>
#define STATIC static
#define VOID void
#define TRUE true
#define FALSE false
#define BIT0 1U
#define BIT1 2U
#define BIT2 4U
#define BIT3 8U
using UINT8=uint8_t;using UINT16=uint16_t;using UINT32=uint32_t;
using UINTN=uintptr_t;using BOOLEAN=bool;using EFI_STATUS=int;
enum {EFI_SUCCESS,EFI_TIMEOUT,EFI_DEVICE_ERROR,EFI_INVALID_PARAMETER,EFI_UNSUPPORTED,EFI_NOT_FOUND,EFI_ACCESS_DENIED};
static unsigned owner,status,delays,maps;static bool found,allowMap,irqs;
static uint32_t version;
static std::vector<std::pair<uintptr_t,uint32_t>> writes;
static bool prepare(unsigned sid,unsigned address,unsigned value,uintptr_t channel){
 assert(sid==2 && address==0xc444 && value==0x80 && channel==0x0c650000);++maps;return allowMap;
}
#define LEMONADES_SPMI_PREPARE_WRITE(s,a,v,c) prepare(s,a,v,c)
static uint32_t MmioRead32(uintptr_t a){
 if(a==0xc440000)return version;
 if(a>=0xc440900 && a<0xc441100)return found && a==0xc440914?0x2c400:0;
 if(a==0xc40a714)return owner;
 assert(a==0xc650008);return status;
}
static void MmioWrite32(uintptr_t a,uint32_t v){
 assert(!irqs && maps==1);assert((a==0xc650010 && v==0x80) || (a==0xc650000 && v==0x440));writes.push_back({a,v});
}
static bool SaveAndDisableInterrupts(){bool old=irqs;irqs=false;return old;}
static void SetInterruptState(bool enabled){irqs=enabled;}
static void MicroSecondDelay(unsigned us){assert(us==1);++delays;}
#include "../devices/lemonades/package/touch/LemonadesSpmi.inc"
static void reset(){owner=0;status=1;delays=maps=0;found=allowMap=irqs=true;version=0x50010000;writes.clear();}
int main(){
 reset();assert(!LemonadesSpmiBoardBoostHigh() && writes.size()==2 && maps==1 && irqs && delays==0);
 for(unsigned n=1;n<=7;++n){reset();owner=n;assert(LemonadesSpmiBoardBoostHigh()==EFI_ACCESS_DENIED && writes.empty() && !maps && irqs);}
 reset();found=false;assert(LemonadesSpmiBoardBoostHigh()==EFI_NOT_FOUND && writes.empty() && !maps);
 reset();version=0x50020000;assert(LemonadesSpmiBoardBoostHigh()==EFI_UNSUPPORTED && writes.empty() && !maps);
 reset();allowMap=false;assert(LemonadesSpmiBoardBoostHigh()==EFI_ACCESS_DENIED && writes.empty() && maps==1 && irqs);
 for(unsigned s:{3U,5U,9U}){reset();status=s;assert(LemonadesSpmiBoardBoostHigh()==EFI_DEVICE_ERROR && writes.size()==2 && irqs);}
 reset();status=0;assert(LemonadesSpmiBoardBoostHigh()==EFI_TIMEOUT && delays==1000 && writes.size()==2 && irqs);
 reset();assert(LemonadesSpmiWrite8(2,0xc444,0)==EFI_ACCESS_DENIED && writes.empty() && !maps);
 puts("PASS: actual SPMI command/byte/address, EE ownership, map failure, transfer errors, bounded timeout, IRQ restoration; generic API cannot write boost");
}
