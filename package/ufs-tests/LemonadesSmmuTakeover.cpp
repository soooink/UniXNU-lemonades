// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>
#include "../LemonadesSmmuTakeover.h"
int main()
{
  std::array<uint32_t,0xd0000/4> r{};
  std::vector<std::pair<unsigned,uint32_t>> writes;
  unsigned drop=~0U;
  auto reset=[&]{
    r.fill(0); writes.clear(); drop=~0U;
    r[0x20/4]=0x4c017e57; r[0x24/4]=0x6000004a; r[0x28/4]=0x5111;
    // Real phone display route must remain unchanged.
    r[(0x800+16)/4]=0x84020820; r[(0xc00+16)/4]=4;
  };
  auto read=[&](unsigned at){return r.at(at/4);};
  auto plan=[&]{return planLemonadesSmmu(0xc8000000,0x22000,read);};
  auto write=[&](unsigned at,uint32_t value){
    writes.emplace_back(at,value);
    if(at!=drop) r.at(at/4)=value;
    if(at==0x800+4*86 || at==0x800+4*85) {
      assert(read(0x1800+4*73)==1 && read(0x1000+4*73)==0x10000);
      assert(read((128+73)*4096)==0);
      assert(read(0xc00+4*85)==73 && read(0xc00+4*86)==73);
    }
  };
  reset(); auto p=plan();
  assert(!p.error && p.bank==73 && p.pages==128 && p.slot[0]==86 && p.slot[1]==85);
  assert(!configureLemonadesSmmu(p,read,write) && writes.size()==7);
  assert(read(0x800+16)==0x84020820 && read(0xc00+16)==4);
  p=plan(); assert(!p.error && p.reuse[0] && p.reuse[1]);
  writes.clear(); assert(!configureLemonadesSmmu(p,read,write) && writes.empty());
  r[(0x1800+4*73)/4]=0; assert(!configureLemonadesSmmu(p,read,write));
  assert(writes.size()==1 && read(0x1800+4*73)==1);
  for(unsigned slot : {85U,86U}) {
    reset(); r[(0x800+4*slot)/4]=0x800000e0; r[(0xc00+4*slot)/4]=73;
    r[(0x1000+4*73)/4]=0x10000;
    p=plan(); assert(!p.error && p.reuse[0] && !p.reuse[1]);
    assert(!configureLemonadesSmmu(p,read,write));
  }
  reset(); r[(0x800+4*86)/4]=0x800400e0; r[(0xc00+4*86)/4]=73;
  assert(plan().error); // One mask must not accidentally capture both streams.
  reset(); r[(0x800+4*86)/4]=0x800000e0; r[(0xc00+4*86)/4]=3;
  assert(plan().error);
  reset(); r[(0x800+4*86)/4]=0x80001234; r[(0xc00+4*86)/4]=73;
  assert(plan().error);
  reset(); r[(128+73)*4096/4]=1; assert(plan().error);
  reset(); r[0x24/4]|=0x80000000U; assert(plan().error);
  reset(); r[0x20/4]=0x4c017eff; assert(plan().error);
  reset(); for(unsigned i=0;i<86;++i) {
    r[(0x800+4*i)/4]=0x80001000+i; r[(0xc00+4*i)/4]=1;
  }
  assert(plan().error); // One free slot cannot fit two streams.
  for(unsigned at : {(128+73)*4096U,0x1800+4*73U,0x1000+4*73U,
                     0xc00+4*86U,0xc00+4*85U,0x800+4*86U,0x800+4*85U}) {
    reset(); r[(128+73)*4096/4]=2; p=plan(); drop=at;
    assert(configureLemonadesSmmu(p,read,write));
    if(at<0x800 || at>=0xa00) assert(!read(0x800+4*86));
  }
  reset(); p=plan(); r[(0x800+4*86)/4]=0x80001234;
  assert(configureLemonadesSmmu(p,read,write) && writes.empty());
  reset();
  assert(!planLemonadesSmmu(0x100000000ULL,0x22000,read).error);
  assert(!planLemonadesSmmu(0x22ffde000ULL,0x22000,read).error);
  assert(lemonadesDmaInOwnedMemory(0x100000000ULL,0x22000,0x100000000ULL,0x130000000ULL));
  assert(lemonadesDmaInOwnedMemory(0x22ffde000ULL,0x22000,0x100000000ULL,0x130000000ULL));
  assert(!lemonadesDmaInOwnedMemory(0xc8000000ULL,0x22000,0x100000000ULL,0x130000000ULL));
  assert(!lemonadesDmaInOwnedMemory(0x230000000ULL,1,0x100000000ULL,0x130000000ULL));
  assert(!lemonadesDmaInOwnedMemory(UINT64_MAX,2,UINT64_MAX-1,4));
  assert(!lemonadesDmaInOwnedMemory(0x100000000ULL,0,0x100000000ULL,0x130000000ULL));
  assert(planLemonadesSmmu(0xfffffffffULL,2,read).error);
  assert(planLemonadesSmmu(0,0,read).error);
  for(unsigned shift : {0U,4U,8U}) {
    reset(); r[0x28/4]&=~(15U<<shift);
    assert(planLemonadesSmmu(0x100000000ULL,1,read).error);
  }
  puts("PASS: actual lemonades geometry; two-stream allocation/reuse; display preservation; conflicts; blocked writes; DMA widths");
}
