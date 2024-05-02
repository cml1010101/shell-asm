#include <asmjit/asmjit.h>
#include <iostream>
int main(int argc, const char** argv)
{
    asmjit::JitRuntime runtime;
    asmjit::CodeHolder code;
    code.init(runtime.environment());
    asmjit::x86::Assembler assembler(&code);
    asmjit::x86::rax
}