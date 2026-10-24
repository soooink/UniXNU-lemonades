#include <assert.h>
#include "../devices/lemonades/package/touch/LemonadesFtsSyncFrame.h"
struct Fake {
    unsigned reads=0,writes=0,sleeps=0,checks=0;
    unsigned failRead=0,loseOwnership=0;
    bool badInitial=false,wrongType=false,stale=false,failWrite=false,wrap=false;
    LemonadesFtsSyncFrame run() {
        return lemonades_fts_sync_frame(
            [&](const uint8_t *w,unsigned n){assert(n==3 && !memcmp(w,"\xa4\x06\x30",3));++writes;return failWrite?7U:0U;},
            [&](const uint8_t *w,unsigned n,uint8_t *r,unsigned rn){
                assert(n==3 && !memcmp(w,"\xa6\0\0",3) && rn==8);++reads;
                if(reads==failRead){memset(r,0xee,rn);return 9U;}
                memset(r,0,rn);r[0]=badInitial?0:0xa5;r[1]=(reads==1 || wrongType)?1:0x30;
                unsigned count=wrap?65535:10;if(reads>1 && !stale)count=(count+1)&65535;
                r[2]=count;r[3]=count>>8;return 0U;
            },[&](unsigned ms){assert(ms==10);++sleeps;},[&](){return ++checks!=loseOwnership;});
    }
};
int main() {
    {Fake f;auto r=f.run();assert(r.result==0 && r.flags==7 && r.beforeCount==10 && r.afterCount==11 && r.polls==1);}
    {Fake f;f.wrap=true;auto r=f.run();assert(r.result==0 && r.beforeCount==65535 && r.afterCount==0);}
    {Fake f;f.badInitial=true;auto r=f.run();assert(r.result==2 && !f.writes && !f.sleeps);}
    {Fake f;f.stale=true;auto r=f.run();assert(r.result==3 && r.polls==20 && f.sleeps==20 && r.flags==3);}
    {Fake f;f.wrongType=true;auto r=f.run();assert(r.result==3 && r.flags==3);}
    for(unsigned n=1;n<=2;++n){Fake f;f.failRead=n;auto r=f.run();assert(r.result==1 && r.readResult==9 && !(r.flags&4));if(n==1)assert(!f.writes);else for(auto b:r.after)assert(!b);}
    {Fake f;f.failWrite=true;auto r=f.run();assert(r.result==1 && r.writeResult==7 && !f.sleeps);}
    for(unsigned n=1;n<=3;++n){Fake f;f.loseOwnership=n;auto r=f.run();assert(r.result==4 && !(r.flags&4));assert(f.writes==(n==3?1U:0U));}
}
