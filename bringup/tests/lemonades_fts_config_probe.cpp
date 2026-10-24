#include <cassert>
#include <cstdio>
#include "../devices/lemonades/package/touch/LemonadesFtsConfigProbe.h"
int main() {
    assert(!lemonades_fts_sysinfo(nullptr,0).valid);
    const uint8_t known[]="123456789";
    assert(LemonadesFtsConfigProbe::checksum(known,9)==0xcbf43926U);
    LemonadesFtsSysInfo s={};s.valid=true;s.chip0=0x3639;s.fw=0x128;s.svn=0x4053;s.config=0x4b;
    for(unsigned fail=0;fail<=52;++fail){
        LemonadesFtsConfigProbe p={};assert(p.begin(s));unsigned calls=0;
        auto read=[&](const uint8_t *w,unsigned wn,uint8_t *r,unsigned rn){
            assert(wn==3 && w[0]==0xa8 && (unsigned(w[1])<<8|w[2])==calls*64 && rn==64);
            memset(r,0xa5,rn);return calls++==fail?7U:0U;
        };
        while(!p.step(read))assert(calls<=52);
        assert(p.completed==fail && p.result==(fail<52?7U:0U));
        unsigned c=calls;assert(p.step(read) && calls==c);
        for(unsigned i=0;i<52;++i){uint8_t b[64];memset(b,0xa5,64);assert(p.crc[i]==(i<fail?LemonadesFtsConfigProbe::checksum(b,64):0));}
    }
    LemonadesFtsConfigProbe p={};s.fw=0;assert(!p.begin(s) && !p.active && p.completed==0 && p.result==0x100);
    puts("PASS: config identity, CRC vector, bounded addressed reads and every failure boundary");
}
