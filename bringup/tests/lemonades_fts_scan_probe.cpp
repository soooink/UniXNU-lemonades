#include <cassert>
#include <cstdio>
#include "../devices/lemonades/package/touch/LemonadesFtsScanProbe.h"
int main(){
    uint8_t sys[208]={};sys[0]=0xa5;sys[1]=1;sys[10]=0x39;sys[11]=0x36;
    sys[16]=0x28;sys[17]=1;sys[18]=0x53;sys[19]=0x40;sys[20]=0x4b;
    LemonadesFtsSysInfo info=lemonades_fts_sysinfo(sys,sizeof(sys));assert(info.valid);
    // Reject an unqualified firmware before any I2C operation.
    for(unsigned field=0;field<5;++field){auto wrong=info;
        switch(field){case 0:wrong.valid=false;break;case 1:++wrong.chip0;break;
            case 2:++wrong.fw;break;case 3:++wrong.svn;break;case 4:++wrong.config;}
        auto p=lemonades_fts_scan_probe(wrong,[](const uint8_t*,unsigned,uint8_t*,unsigned){assert(false);return 0U;});
        assert(p.result==0x100 && p.validMask==0);
    }
    // Inject partial-buffer failures at each read; failed tails never publish.
    for(unsigned fail=0;fail<=5;++fail){unsigned calls=0;
        auto p=lemonades_fts_scan_probe(info,[&](const uint8_t*w,unsigned wn,uint8_t*r,unsigned rn){
            assert(wn==5 && w[0]==0xfa && r && rn>0 && rn<=16);
            unsigned a=unsigned(w[1])<<24|unsigned(w[2])<<16|unsigned(w[3])<<8|w[4];
            constexpr uint32_t expected[]={0x20000050,0x20000060,0x20030000,0x200126ca,0x200156a8};
            constexpr unsigned lengths[]={2,6,8,8,16};
            assert(a==expected[calls] && rn==lengths[calls]);
            memset(r,0xa0+calls,rn);return calls++==fail?7U:0U;});
        assert(calls==(fail<5?fail+1:5));assert(p.validMask==((1U<<fail)-1));
        assert(p.result==(fail<5?7U:0U));
        for(unsigned n=0;n<5;++n)for(unsigned i=0;i<16;++i)
            assert(p.data[n][i]==(n<fail && i<lemonades_fts_scan_lengths[n]?0xa0+n:0));
    }
    puts("PASS: firmware-qualified passive scan reads and partial-transfer rejection");
}
