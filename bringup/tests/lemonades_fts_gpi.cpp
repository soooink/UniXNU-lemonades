#include <cassert>
#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>
#include "../devices/lemonades/package/touch/LemonadesFtsGpiCore.h"
int main(){
 assert(lemonadesGpiBranchReady(0x80000002,true));
 assert(!lemonadesGpiBranchReady(0x80000002,false));
 assert(!lemonadesGpiBranchReady(0x80000000,true));
 assert(lemonadesGpiBranchReady(0x20000000,false));
 assert(lemonadesGpiXoUndivided(0) && lemonadesGpiXoUndivided(1) && lemonadesGpiXoUndivided(0x100000));
 assert(!lemonadesGpiXoUndivided(2) && !lemonadesGpiXoUndivided(0x101) && !lemonadesGpiXoUndivided(0x1001));
 auto cfg=lemonadesGpiConfig(3);assert(cfg.d[0]==0x0318070a && cfg.d[2]==0x30002 && cfg.d[3]==0x220001);
 auto tx=lemonadesGpiGo(false,true,0),rx=lemonadesGpiGo(true,false,8);
 assert(tx.d[0]==0x04004901 && tx.d[3]==0x200001);
 assert(rx.d[0]==0x4902 && rx.d[2]==8 && rx.d[3]==0x200900);
 auto buf=lemonadesGpiBuffer(0x1a0002000ULL,8);assert(buf.d[0]==0xa0002000 && buf.d[1]==1 && buf.d[3]==0x100200);
 unsigned index=999;assert(lemonadesGpiRingIndex(0x1a00003f0ULL,0x1a0000000ULL,64,index)&&index==63);
 assert(!lemonadesGpiRingIndex(0x1a0000400ULL,0x1a0000000ULL,64,index));
 assert(!lemonadesGpiRingIndex(0x1a0000001ULL,0x1a0000000ULL,64,index));
 assert(!lemonadesGpiRingIndex(0xa0000000ULL,0x1a0000000ULL,64,index));
 LemonadesGpiTre ev={{0xa0001000,1,0x02000008,0x01220000}};
 assert(!lemonadesGpiCompletion(ev,1,0x1a0001000ULL,8,false));
 assert(lemonadesGpiCompletion(ev,0,0x1a0001000ULL,8,false));
 assert(lemonadesGpiCompletion(ev,1,0x1a0001010ULL,8,false)); // stale ring wrap
 assert(lemonadesGpiCompletion(ev,1,0x1a0001000ULL,9,false)); // short DMA
 ev.d[3]|=0x40;assert(lemonadesGpiCompletion(ev,1,0x1a0001000ULL,8,false)); // NACK status
 ev={{0xa0001020,1,0x04000000,0x00220000}};assert(!lemonadesGpiCompletion(ev,0,0x1a0001020ULL,0,true));
 ev.d[2]=0x10000000;assert(lemonadesGpiCompletion(ev,0,0x1a0001020ULL,0,true));
 std::map<unsigned,uint32_t> regs;std::vector<unsigned> writes;
 auto reset=[&](){regs.clear();writes.clear();regs[0x20]=(1U<<30)|(1U<<27)|16;regs[0x24]=8;regs[0x28]=0x1222;
  regs[0x800]=0x800000e0;regs[0xc00]=7;regs[0x804]=0x800004e0;regs[0xc04]=7;
  regs[0x808]=0x80000056;regs[0xc08]=3;regs[0x80c]=0x80000043;regs[0xc0c]=3;};
 auto rd=[&](unsigned o){return regs[o];};auto wr=[&](unsigned o,uint32_t v){writes.push_back(o);regs[o]=v;};
 reset();auto p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(!p.error && p.bank==6 && p.slot[0]==2 && p.slot[1]==3);
 assert(!lemonadesTouchSmmuApply(p,rd,wr));assert(regs[0xc08]==6 && regs[0xc0c]==6 && regs[0xc00]==7);
 for(auto o:writes)assert(o!=0x101c && o!=0x181c && o!=9*4096); // live UFS untouched
 // Firmware's M=0 / nonzero control fields must not exhaust the bank pool.
 reset();for(unsigned b=0;b<8;++b)regs[(2+b)*4096]=0xe0;
 p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(!p.error && p.bank==6 && p.oldSctlr==0xe0 && p.enabledMask[0]==0 && p.nonzeroMask[0]==255);
 assert(p.usedMask[0]==((1U<<7)|(1U<<3)));
 assert(!lemonadesTouchSmmuApply(p,rd,wr));assert(writes[0]==8*4096 && regs[8*4096]==0);
 assert(regs[9*4096]==0xe0 && regs[5*4096]==0xe0); // UFS and inherited touch bank untouched
 reset();regs[8*4096]=0xe1;p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(!p.error && p.bank==5 && (p.enabledMask[0]&(1U<<6)));
 reset();regs[0x810]=0x80000900;regs[0xc10]=6;
 assert(lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd).bank==5); // referenced M=0 is still owned
 reset();regs[8*4096]=0xe0;p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);regs[8*4096]=0xe1;
 assert(lemonadesTouchSmmuApply(p,rd,wr)==6 && writes.empty()); // concurrent enable must refuse all writes
 reset();regs[8*4096]=0xe0;p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(lemonadesTouchSmmuApply(p,rd,[&](unsigned o,uint32_t){writes.push_back(o);})==7);
 assert(writes.size()==1 && writes[0]==8*4096 && regs[0xc08]==3); // rejected disable: no route writes
 reset();regs[0x80c]=0x80010043;assert(lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd).error==3); // alias stream
 reset();regs[0x810]=0x80000056;assert(lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd).error==3); // duplicate
 reset();assert(lemonadesTouchSmmuPlan(1ULL<<40,0x4000,rd).error==2);
 assert(lemonadesTouchSmmuPlan((1ULL<<40)-0x1000,0x4000,rd).error==2);
 reset();p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);regs[0xc08]=4;
 assert(lemonadesTouchSmmuApply(p,rd,wr)==6 && writes.empty()); // plan changed, no mutation
 reset();for(unsigned b=1;b<7;++b)regs[(2+b)*4096]=1;
 p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(p.error==4 && p.bank==~0U && p.enabledMask[0]==0x7e); // no idle bank
 reset();p=lemonadesTouchSmmuPlan(0x1a0000000ULL,0x4000,rd);
 assert(lemonadesTouchSmmuApply(p,rd,[](unsigned,uint32_t){})==7); // write refusal
 puts("PASS: GPI TRE, >4GiB rings, stale/short/NACK completions, SMMU alias/race/live-UFS guards");
}
