#include <cassert>
#include <cstdio>
#include "../devices/lemonades/package/touch/LemonadesFtsDataProbe.h"
int main(){
    uint8_t sys[208]={};sys[0]=0xa5;sys[1]=1;sys[10]=0x39;sys[11]=0x36;
    sys[16]=0x28;sys[17]=1;sys[18]=0x53;sys[19]=0x40;sys[20]=0x4b;
    LemonadesFtsSysInfo s=lemonades_fts_sysinfo(sys,sizeof(sys));assert(s.valid);
    s.tx=37;s.rx=17;s.msRaw=0x8b0c;s.ssTxRaw=0x8870;s.ssRxRaw=0x889a;
    for(unsigned i=0;i<3;++i){s.filtered[i]=0x1000+i*0x1000;s.baseline[i]=0x4000+i*0x1000;}
    for(unsigned plane=0;plane<3;++plane)for(unsigned fail=0;fail<=4;++fail){
        unsigned calls=0;
        auto p=lemonades_fts_data_probe(s,plane,[&](const uint8_t*w,unsigned wn,uint8_t*r,unsigned rn){
            assert(rn==16 && wn==(calls==1?5U:3U));
            assert(w[0]==(calls==1?0xfa:0xa6));
            if(calls==1)assert(w[1]==0x20&&w[2]==1);
            memset(r,0xa0+calls,rn);return calls++==fail?7U:0U;
        });
        assert(p.validMask==((1U<<fail)-1));assert(p.result==(fail<4?7U:0U));
        unsigned count=plane?plane==1?s.tx:s.rx:s.tx*s.rx;
        assert(p.addresses[1]==s.filtered[plane]+2*(count/2-4));
        for(unsigned n=0;n<4;++n)for(unsigned k=0;k<16;++k)assert(p.data[n][k]==(n<fail?0xa0+n:0));
    }
    auto never=[](const uint8_t*,unsigned,uint8_t*,unsigned){assert(false);return 0U;};
    for(unsigned bad=0;bad<6;++bad){auto t=s;
        switch(bad){case 0:t.valid=false;break;case 1:++t.fw;break;case 2:t.tx=7;break;
            case 3:t.msRaw=0xfffe;break;case 4:t.filtered[0]=1;break;case 5:t.baseline[0]=0;break;}
        assert(lemonades_fts_data_probe(t,0,never).result==0x100);
    }
    assert(lemonades_fts_data_probe(s,3,never).result==0x100);
    for(unsigned page=0;page<2;++page)for(unsigned fail=0;fail<2;++fail){
        auto p=lemonades_fts_engine_page(s,page,[&](const uint8_t*w,unsigned wn,uint8_t*r,unsigned rn){
            assert(wn==5&&w[0]==0xfa&&w[1]==0x20&&w[2]==3&&w[3]==0&&w[4]==page*88);
            assert(rn==(page?76U:88U));memset(r,0xff,rn);return fail;
        });
        assert(p.result==fail);for(unsigned k=0;k<88;++k)assert(p.data[k]==(!fail&&k<p.length?255:0));
    }
    assert(lemonades_fts_engine_page(s,2,never).result==0x100);
    puts("PASS: bounded read-only A6/FA data comparison and engine page failure isolation");
}
