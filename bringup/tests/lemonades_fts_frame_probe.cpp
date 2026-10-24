#include <cassert>
#include <cstdio>
#include <vector>
#include "../devices/lemonades/package/touch/LemonadesFtsFrameProbe.h"
static LemonadesFtsSysInfo info(){uint8_t b[208]={0xa5,1};auto s=lemonades_fts_sysinfo(b,sizeof(b));s.tx=17;s.rx=37;s.msRaw=0x8b0c;s.ssTxRaw=0x8870;s.ssRxRaw=0x889a;return s;}
int main(){
 // Fault every write/read, and lose ownership at each restore guard.
 for(unsigned mode: {0U,3U})for(unsigned failWrite=0;failWrite<=4;++failWrite)
 for(unsigned failRead=0;failRead<=3;++failRead)for(unsigned unsafe=0;unsafe<=3;++unsafe){
  LemonadesFtsFrameSample s={};unsigned writes=0,reads=0,guards=0,elapsed=0;
  bool off=false;std::vector<unsigned> delays;
  std::vector<std::vector<uint8_t>> commands;
  auto write=[&](const uint8_t *w,unsigned n){
   commands.emplace_back(w,w+n);++writes;
   if(writes==1)assert(commands.back()==std::vector<uint8_t>({0xa0,(uint8_t)mode,(uint8_t)(mode?0:1)}));
   if(n==3 && w[1]==0 && w[2]==0)assert(writes==2 && elapsed==200);
   bool failed=writes==failWrite;
   if(n==3 && w[1]==0 && w[2]==0 && !failed)off=true;
   return failed?12:0;
  };
  auto read=[&](const uint8_t *w,unsigned n,uint8_t *p,unsigned rn){
   assert(off && elapsed==250 && n==3 && w[0]==0xa6 && rn==16);
   const unsigned address[]={0x8d78,0x8878,0x88b6};assert(((unsigned(w[1])<<8)|w[2])==address[reads]);
   ++reads;memset(p,0xcc,rn);return reads==failRead?1:0;
  };
  auto sleep=[&](unsigned ms){assert(ms==(delays.empty()?200U:50U));elapsed+=ms;delays.push_back(ms);};
  auto ready=[&](){return ++guards!=unsafe;};
  auto r=lemonades_fts_probe_frame(info(),s,mode,write,read,sleep,ready);
  assert(!s.active);
  if(unsafe==1){assert(!writes&&!reads&&!r.restored()&&r.flags==128);continue;}
  assert(writes>=1);
  if(failWrite!=1 && failWrite!=2){assert(reads>=1);assert(elapsed==250);}
  else assert(!reads);
  if(reads && failRead && failRead<=reads){assert(s.validMask==((1U<<(failRead-1))-1));for(unsigned plane=failRead-1;plane<3;++plane)for(auto b:s.data[plane])assert(b==0);}
  if(!reads)assert(!s.validMask&&s.result==UINT32_MAX);
  if(r.restored()){
   assert(commands[commands.size()-2]==std::vector<uint8_t>({0xa0,0,1}));
   assert(commands.back()==std::vector<uint8_t>({0xa2,3,0,0,0,3}));
  }
  if(unsafe==2)assert(writes<=2&&!r.restored());
  if(unsafe==3)assert(commands.back()!=std::vector<uint8_t>({0xa2,3,0,0,0,3})&&!r.restored());
  if(!failWrite&&!failRead&&!unsafe)assert(r.restored()&&r.flags==255&&s.validMask==7&&writes==4&&reads==3);
 }
 // Bad SysInfo or unsupported mode never changes scan state.
 for(unsigned mode: {0U,1U,2U,3U,4U}){
  auto bad=info();if(mode==0||mode==3)bad.valid=false;LemonadesFtsFrameSample s={};
  auto r=lemonades_fts_probe_frame(bad,s,mode,[](const uint8_t*,unsigned){assert(false);return 0;},
   [](const uint8_t*,unsigned,uint8_t*,unsigned){assert(false);return 0;},[](unsigned){assert(false);},[](){assert(false);return true;});
  assert(r.flags==0&&r.frameResult==3&&!s.validMask&&!s.active);
 }
 puts("PASS: original normal/locked fresh-frame timings; write/read faults, discarded partial data, ownership loss and normal-mode restoration");
}
