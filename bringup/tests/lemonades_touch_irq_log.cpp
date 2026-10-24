#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../devices/lemonades/package/touch/LemonadesTouchLog.h"
static bool irq=true,interruptContext=false;
static std::vector<std::string> output;
static void ioLog(const char *s) {assert(irq&&!interruptContext);output.emplace_back(s);}
static LemonadesTouchLog logBuffer{};
static void debug(const char *fmt,...) {
    va_list a;va_start(a,fmt);logBuffer.append(fmt,a);va_end(a);
    logBuffer.flush(irq&&!interruptContext,ioLog);
}
int main() {
    debug("before %d",1);assert(output.size()==1);
    irq=false;
    debug("withdraw RPMh request %u",2U);debug("completion %x",0xab);
    assert(output.size()==1&&logBuffer.count==2);
    // A nested critical call must not flush before the outer IRQ restore.
    logBuffer.flush(irq&&!interruptContext,ioLog);assert(output.size()==1);
    irq=true;interruptContext=true;debug("in interrupt");assert(output.size()==1);
    interruptContext=false;debug("after");
    assert(output.size()==5&&output[1]=="withdraw RPMh request 2"&&output[2]=="completion ab");
    assert(output[3]=="in interrupt"&&output[4]=="after"&&!logBuffer.count);
    logBuffer.flush(true,ioLog);assert(output.size()==5);
    irq=false;std::string longLine(500,'x');debug("%s",longLine.c_str());
    for(unsigned n=1;n<70;++n)debug("%u",n);
    assert(logBuffer.count==64&&logBuffer.dropped==6&&strlen(logBuffer.lines[0])==199);
    irq=true;logBuffer.flush(true,ioLog);
    assert(output.size()==69&&!logBuffer.count&&output.back()=="63");
    debug("reused");assert(output.back()=="reused");
    puts("PASS: masked IRQ and interrupt contexts defer IOLog, FIFO order, nested masks, truncation, overflow and reuse");
}
