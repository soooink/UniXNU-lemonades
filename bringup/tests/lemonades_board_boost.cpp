#include <cassert>
#include <cstdio>
#include <map>
#include "../devices/lemonades/package/touch/LemonadesBoardBoost.h"
struct Board {
 std::map<uint16_t,uint8_t> regs={{0x104,0x51},{0x105,0x20},{0xc404,0x10},{0xc405,0x11},
  {0xc440,1},{0xc441,0},{0xc442,4},{0xc443,0},{0xc444,0},{0xc445,1},{0xc446,0x80}};
 unsigned reads=0,writes=0,waits=0,failRead=0,failWrite=0;bool lostWrite=false;
 LemonadesBoardBoost run(){return lemonades_board_boost_enable(
  [&](unsigned sid,uint16_t addr,uint8_t *v){assert(sid==2 && regs.count(addr));
   if(++reads==failRead){*v=0xcc;return 77U;}*v=regs[addr];return 0U;},
  [&](){assert(writes==0);++writes;if(failWrite)return failWrite;
   if(!lostWrite)regs[0xc444]=0x80;return 0U;},
  [&](unsigned us){assert(us==4000 && (writes==1 || regs[0xc444]==0x80));++waits;});}
};
int main(){
 Board b;auto r=b.run();assert(!r.result && r.flags==7 && r.writes==1 && r.before==0 && r.after==0x80 && b.waits==1 && b.reads==22);
 Board high;high.regs[0xc444]=0x80;r=high.run();assert(!r.result && r.flags==15 && !high.writes && high.waits==1);
 for(unsigned i=1;i<=22;++i){Board f;f.failRead=i;r=f.run();assert(r.result==(i<=11?1U:5U) && r.readResult==77 && f.reads==i && f.writes==(i<=11?0U:1U));}
 for(auto item:Board().regs)for(unsigned bit=0;bit<8;++bit){
  if(item.first==0xc444 && bit==7)continue;
  Board f;f.regs[item.first]^=1U<<bit;r=f.run();assert((r.result==2 || r.result==3) && f.writes==0 && f.waits==0);
 }
 Board denied;denied.failWrite=6;r=denied.run();assert(r.result==4 && r.writeResult==6 && denied.writes==1 && denied.waits==0 && denied.reads==11);
 Board lost;lost.lostWrite=true;r=lost.run();assert(r.result==6 && lost.writes==1 && r.after==0);
 puts("PASS: qualified board-boost one-shot enable, already-high path, every IO/profile fault, readback, delay, no disable/retry");
}
