#include <asmjit/asmjit.h>
#include <iostream>
#include <sys/ptrace.h>
#include <boost/thread.hpp>
void executor()
{
}
int main(int argc, const char** argv)
{
    boost::thread thread = boost::thread([]() {
        for (;;);
    });
}