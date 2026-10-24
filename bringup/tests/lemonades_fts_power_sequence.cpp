#include <cassert>
#include <vector>
#include "../devices/lemonades/package/touch/LemonadesFtsPowerSequence.h"
#include "../devices/lemonades/package/touch/LemonadesFtsPinConfig.h"
int main() {
    for(unsigned fault=0;fault<=13;++fault){
        unsigned pins=3,phase=0,reads=0,pinReads=0,wait=0;std::vector<unsigned> ops;
        auto r=lemonades_fts_full_cycle(fault!=1,
            [&](unsigned pin,bool high){unsigned bit=pin==38?1:2;pins=high?pins|bit:pins&~bit;ops.push_back(pin*2+high);},
            [&](){++pinReads;unsigned bad=fault==3?1:fault==7?2:fault==11?3:fault==12?4:fault==13?5:0;
                return pins^(pinReads==bad?1:0);},
            [&](bool on){ops.push_back(on?2001:2000);phase=on?2:1;
                return unsigned((fault==4&&!on)||(fault==8&&on));},
            [&](){++reads;LemonadesFtsSupplyState s={0,15,0x80,0x84,1800};
                if(phase==1 && fault!=6){s.enable=0;s.status=0;}
                if(fault==2 && !phase)s.mv=1700;
                if((fault==5&&phase==1)||(fault==9&&phase==2)){s.result=2;s.valid=1;}
                if(fault==10 && phase==2)s.status=0;
                return s;},
            [&](unsigned ms){assert(!(pins&1));wait+=ms;ops.push_back(1000+ms);});
        assert(r.result==fault);
        if(!fault){assert(r.flags==127 && pins==3 && wait==50 && reads==3);
            assert((ops==std::vector<unsigned>{76,138,2000,1020,2001,1015,139,1015,77}));}
        if(fault==1 || fault==2)assert(ops.empty());
        if(fault>=3 && fault<13)assert(!(pins&1));
        if(fault==6)assert(reads==21 && wait==20); // Never proceed if another vote holds the rail on.
        if(fault==10)assert(reads==102 && wait==120); // Bounded ready timeout.
    }
    for(uint32_t ctl: {0U,0x3ffU,0x8c3U,0xdeadbeefU}){
        auto reset=lemonades_fts_power_pin_config(ctl,38),avdd=lemonades_fts_power_pin_config(ctl,69);
        assert((reset&0x1c3)==0xc3); // pinctrl-msm encoding: pull-up/8mA.
        assert((avdd&0x1c3)==(ctl&0x1c3)); // fixed regulator preserves pad config.
        assert(!(reset&0x23c) && !(avdd&0x23c));
        assert((reset&~0x13ffU)==(ctl&~0x13ffU));
        if(ctl&0x800)assert((reset&0x1000)&&(avdd&0x1000));
    }
    for(unsigned fault=0;fault<=6;++fault) {
        unsigned pins=3,reads=0;std::vector<unsigned> ops;
        auto r=lemonades_fts_avdd_cycle(
            [&](unsigned pin,bool high){assert(pin==38||pin==69);unsigned bit=pin==38?1:2;
                pins=high?(pins|bit):(pins&~bit);ops.push_back(pin*2+high);},
            [&](){++reads;return reads==fault?(pins^1):pins;},
            [&](unsigned ms){assert(pins==0||pins==2);assert(ms==20||ms==15);ops.push_back(1000+ms);});
        if(!fault){assert(r.result==0&&r.flags==15&&r.lowLevels==0&&r.highLevels==3);
            assert((ops==std::vector<unsigned>{76,138,1020,139,1015,77}));}
        else {assert(r.result!=0);assert(r.flags!=15);
            // No subsequent pin write after the first invalid readback.
            unsigned expected[]={0,1,2,3,4,5,6};assert(ops.size()==expected[fault]);}
    }
}
