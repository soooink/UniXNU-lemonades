#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include "../devices/lemonades/package/touch/LemonadesFtsFrameSample.h"
static LemonadesFtsSysInfo info() {
    uint8_t bytes[208]={0xa5,1};auto s=lemonades_fts_sysinfo(bytes,sizeof(bytes));s.tx=17;s.rx=37;
    s.msRaw=0x8b0c;s.ssTxRaw=0x8870;s.ssRxRaw=0x889a;return s;
}
int main() {
    LemonadesFtsFrameSample sample={};auto s=info();
    assert(sample.begin(s));
    const unsigned expected[]={0x8d78,0x8878,0x88b6};
    unsigned call=0;
    auto read=[&](const uint8_t *w,unsigned wn,uint8_t *r,unsigned rn){
        assert(wn==3 && rn==16 && w[0]==0xa6);
        assert(((unsigned(w[1])<<8)|w[2])==expected[call]);
        memset(r,++call,rn);return 0;
    };
    assert(!sample.step(read));assert(!sample.step(read));assert(sample.step(read));
    assert(call==3 && sample.validMask==7 && !sample.active && sample.result==0);
    assert(sample.step(read) && call==3);
    for(unsigned plane=0;plane<3;++plane)for(auto b:sample.data[plane])assert(b==plane+1);
    // Every possible failed plane discards even partially filled transfer bytes.
    for(unsigned fail=0;fail<3;++fail){
        assert(sample.begin(s));call=0;
        auto broken=[&](const uint8_t *,unsigned,uint8_t *r,unsigned rn){
            memset(r,0xcc,rn);return call++==fail?9:0;
        };
        for(unsigned i=0;i<=fail;++i)assert(sample.step(broken)==(i==fail));
        assert(sample.result==9 && sample.validMask==((1U<<fail)-1) && !sample.active);
        for(unsigned plane=fail;plane<3;++plane)for(auto b:sample.data[plane])assert(b==0);
    }
    for(unsigned plane=0;plane<3;++plane){
        for(unsigned base: {0U,1U,65534U}){
            auto bad=s;
            if(plane==0)bad.msRaw=base;else if(plane==1)bad.ssTxRaw=base;else bad.ssRxRaw=base;
            assert(!sample.begin(bad) && !sample.active && !sample.validMask && sample.result==3);
        }
    }
    for(unsigned count: {0U,7U,65U,255U})for(bool tx: {false,true}){
        auto bad=s;if(tx)bad.tx=count;else bad.rx=count;
        assert(!sample.begin(bad) && !sample.active && !sample.validMask);
    }
    s.valid=false;assert(!sample.begin(s));s=info();
    s.tx=s.rx=8;s.msRaw=s.ssTxRaw=s.ssRxRaw=0x100;
    assert(sample.begin(s) && sample.addresses[0]==0x138 && sample.addresses[1]==0x100);
    s.tx=s.rx=64;s.msRaw=57344;assert(sample.begin(s)); // Last byte may be 0xffff.
    s.msRaw=57346;assert(!sample.begin(s));
}
