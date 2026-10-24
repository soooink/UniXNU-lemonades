// Exercise the actual transport/recovery implementation against GPIO faults.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>
#define STATIC static
#define CONST const
#define VOID void
#define TRUE true
#define FALSE false
#define BIT0 (1U<<0)
#define BIT1 (1U<<1)
#define BIT2 (1U<<2)
#define BIT3 (1U<<3)
#define BIT7 (1U<<7)
#define BIT8 (1U<<8)
#define BIT9 (1U<<9)
#define BIT11 (1U<<11)
#define BIT12 (1U<<12)
#define MAX_UINT32 UINT32_MAX
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define DEBUG(x) ((void)0)
using UINT8=uint8_t;using UINT16=uint16_t;using UINT32=uint32_t;using UINT64=uint64_t;
using UINTN=uintptr_t;using INTN=intptr_t;using BOOLEAN=bool;using EFI_STATUS=int;
enum {EFI_SUCCESS=0,EFI_TIMEOUT=1,EFI_DEVICE_ERROR=2,EFI_INVALID_PARAMETER=3,EFI_UNSUPPORTED=4,
 EFI_NOT_FOUND=5,EFI_ACCESS_DENIED=6,EFI_COMPROMISED_DATA=7,EFI_NOT_READY=8,EFI_ALREADY_STARTED=9,
 EFI_WRITE_PROTECTED=10,EFI_PROTOCOL_ERROR=11,EFI_NO_RESPONSE=12};
#define EFI_ERROR(x) ((x)!=EFI_SUCCESS)
static uint32_t ctl[70],io[70],geni;
static unsigned clocks,writes,releaseAt,holdSclAt,delayScale;
static uint64_t now;
static bool dropIrq;
static bool allowReset,dropResetLow,dropResetHigh;
struct Write {uintptr_t address;uint32_t value;uint64_t time;};
static std::vector<Write> resetWrites;
static uint64_t GetPerformanceCounter(){return now;}
static uint64_t GetTimeInNanoSecond(uint64_t n){return n;}
static void MicroSecondDelay(unsigned us){now+=uint64_t(us)*1000*delayScale;}
static void MemoryFence(){}
static bool lineHigh(unsigned pin) {
 if(ctl[pin]&(1U<<9))return io[pin]&2;
 if(pin==36)return clocks>=releaseAt;
 if(pin==37)return !holdSclAt || clocks<holdSclAt;
 return io[pin]&2;
}
static uint32_t MmioRead32(uintptr_t addr) {
 now+=1000;
 if(addr==0xa94040)return geni;
 assert(addr>=0xf500000 && addr<0xf546000);
 unsigned p=(addr-0xf500000)/0x1000;assert(p<70);
 return (addr&4)?(io[p]|(lineHigh(p)?1U:0U)):ctl[p];
}
static void MmioWrite32(uintptr_t addr,uint32_t v) {
 now+=1000;++writes;
 if(allowReset && (addr==0xf526000 || addr==0xf526004)){
  resetWrites.push_back({addr,v,now});
  if(addr==0xf526000)ctl[38]=v;
  else if(!((dropResetLow && !(v&2)) || (dropResetHigh && (v&2))))io[38]=(io[38]&~2U)|(v&2U);
  return;
 }
 // Recovery must only touch SDA/SCL output-enable, never power/latches/mux.
 if(addr==0xf527000){if(!dropIrq)ctl[39]=v;return;}
 assert(addr==0xf524000 || addr==0xf525000);
 unsigned p=(addr-0xf500000)/0x1000;
 assert(v==0 || v==(1U<<9));
 if(p==37 && (ctl[p]&(1U<<9)) && !(v&(1U<<9)))++clocks;
 ctl[p]=v;
}
static int LemonadesSpmiRead8(uint8_t,uint16_t,uint8_t*){assert(false);return 4;}
static int LemonadesRpmhTouchEnable(){assert(false);return 4;}
static int LemonadesRpmhTouchDisable(){assert(false);return 4;}
static bool LemonadesRpmhTouchOutstanding(){return false;}
static bool LemonadesRpmhTouchVoteSettled(){return false;}
#include "../devices/lemonades/package/touch/LemonadesFtsBus.inc"
static void reset(unsigned release=4) {
 for(unsigned i=0;i<70;++i){ctl[i]=0;io[i]=0;}
 ctl[38]=ctl[69]=GPIO_OE;io[38]=io[69]=GPIO_OUT;
 clocks=writes=geni=holdSclAt=0;dropIrq=false;mIrqOwned=false;releaseAt=release;delayScale=1;now=0;
 allowReset=dropResetLow=dropResetHigh=false;resetWrites.clear();mPowerOwned=true;
 mOwned=true;mLastFifoRead=true;mLastPhase=7;mAckMask=7;mLastStopResult=0;
 mLastLines=2;mLastPinsValid=1;mGpioCtl[0]=mGpioCtl[1]=0;mClockLast=0;mMaxGapNs=0;
}
static void resetReady(){reset(0);mIrqOwned=true;mActiveIrqCtl=ctl[39]=0xc3;allowReset=true;}
int main(){
 for(unsigned n=1;n<=9;++n){reset(n);assert(RecoverRead(1)==0);assert(mRecoveryPulses==9);assert(mRecoveryLines==3);assert(clocks==10);assert(ctl[36]==0&&ctl[37]==0);assert(mRecoveryElapsedNs<CLEANUP_LIMIT_NS);}
 reset(99);assert(RecoverRead(1)==EFI_NOT_READY);assert(mRecoveryPulses==9);assert(clocks==9);assert(ctl[36]==0&&ctl[37]==0);
 reset();holdSclAt=3;assert(RecoverRead(1)==EFI_TIMEOUT);assert(mRecoveryPulses==2);assert(clocks==3);
 reset();delayScale=1000;assert(RecoverRead(1)==EFI_TIMEOUT);assert(mRecoveryPulses<=1);assert(ctl[36]==0&&ctl[37]==0);
 // Fail closed on wrong phase/type, lost ownership, active controller,
 // unqualified pins/rails, stuck clock, stale ACK or failed STOP.
 for(unsigned fault=0;fault<13;++fault){reset();switch(fault){
 case 0:mOwned=false;break;case 1:mLastFifoRead=false;break;case 2:mLastPhase=4;break;
 case 3:mAckMask=3;break;case 4:mLastStopResult=1;break;case 5:mLastLines=0;break;
 case 6:mLastPinsValid=0;break;case 7:ctl[38]=0;break;case 8:ctl[36]=4;break;
 case 9:ctl[37]=4;break;case 10:geni=1;break;case 11:holdSclAt=1;clocks=1;break;
 case 12:releaseAt=0;break;}
 assert(RecoverRead(1)==EFI_UNSUPPORTED);assert(writes==0);}
 reset();assert(RecoverRead(12)==EFI_UNSUPPORTED);assert(writes==0);
 reset();mTransferStart=0;mTransferLimitNs=TRANSFER_LIMIT_NS;now=8000001;assert(!Expired());now=32000000;assert(Expired());
 mTransferLimitNs=CLEANUP_LIMIT_NS;now=8000000;assert(Expired());
 reset();ctl[39]=0x2001;io[39]=0;assert(ConfigureIrq()==0);assert(ctl[39]==0x20c3&&mIrqOwned);assert(io[39]==0);
 RestoreIrq();assert(ctl[39]==0x2001&&!mIrqOwned&&writes==2);RestoreIrq();assert(writes==2);
 reset();ctl[39]=0x2801;assert(ConfigureIrq()==0);assert(ctl[39]==0x38c3);RestoreIrq();assert(ctl[39]==0x2801);
 reset();ctl[39]=1;dropIrq=true;assert(ConfigureIrq()==EFI_WRITE_PROTECTED);RestoreIrq();assert(!mIrqOwned&&ctl[39]==1);
 resetReady();assert(ResetController()==0);assert(mAwaitReady&&mReadyStart>10000000);
 assert(resetWrites.size()==6);assert(ctl[39]==0xc3&&io[69]==2&&ctl[69]==GPIO_OE);
 assert(resetWrites[1].address==0xf526004&&!(resetWrites[1].value&2));
 assert(resetWrites[4].address==0xf526004&&(resetWrites[4].value&2));
 assert(resetWrites[4].time-resetWrites[1].time>=10000000);
 for(unsigned fault=0;fault<11;++fault){resetReady();switch(fault){
 case 0:mOwned=false;break;case 1:mPowerOwned=false;break;case 2:mIrqOwned=false;break;
 case 3:ctl[38]=0;break;case 4:ctl[69]=0;break;case 5:ctl[36]=4;break;
 case 6:ctl[37]=4;break;case 7:ctl[39]=1;break;case 8:geni=1;break;
 case 9:releaseAt=1;break;case 10:holdSclAt=1;clocks=1;break;}
 assert(ResetController()==EFI_ACCESS_DENIED);assert(writes==0&&resetWrites.empty());}
 resetReady();dropResetLow=true;assert(ResetController()==EFI_WRITE_PROTECTED);assert(now<10000000);
 resetReady();dropResetHigh=true;assert(ResetController()==EFI_WRITE_PROTECTED);assert(!High(38));
 puts("PASS: real post-CRC reset holds GPIO38 low >=10ms, requires ownership/idle pins, detects stuck writes, never cycles AVDD");
 puts("PASS: real IRQ input/pull-up/8mA config, readback rejection and exact restore");
 puts("PASS: real bus recovery 1..9-bit release, permanent SDA/SCL faults, cleanup deadline, ownership guards, no power/data writes");
}
