#include <cassert>
#include <cstdio>
#include "../devices/lemonades/package/touch/LemonadesFtsRetry.h"
int main() {
    // Timeout/NACK alone are insufficient: every recovery observation must
    // prove the bus is released, owned and idle before either bounded retry.
    for(unsigned result=0;result<=12;++result)
        for(unsigned count=0;count<=5;++count)
            for(unsigned mask=0;mask<16;++mask) {
                bool retry=lemonades_fts_retry_read(result,count,mask&1,mask&2,mask&4,mask&8);
                bool expected=(result==1||result==12)&&count>=1&&count<=2&&mask==15;
                assert(retry==expected);
            }
    assert(!lemonades_fts_retry_read(1,1,false,true,true,true)); // Failed STOP.
    assert(!lemonades_fts_retry_read(1,1,true,false,true,true)); // Stuck line.
    assert(!lemonades_fts_retry_read(1,1,true,true,false,true)); // Lost ownership/power.
    assert(!lemonades_fts_retry_read(1,1,true,true,true,false)); // GENI owns the bus.
    assert(!lemonades_fts_retry_read(1,3,true,true,true,true)); // No infinite retry.
    puts("PASS: FIFO read retry matrix, STOP/line/ownership/GENI guards and three-attempt bound");
}
