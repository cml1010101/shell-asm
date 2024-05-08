#include <asmjit/asmjit.h>
#include <asmtk/asmtk.h>
#include <iostream>
#include <sys/ptrace.h>
#include <boost/thread.hpp>
#include <atomic>
#include <wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <capstone/capstone.h>
class ShellRuntime
{
private:
    std::unique_ptr<asmjit::JitRuntime> runtime;
    std::unique_ptr<asmjit::CodeHolder> code;
    std::unique_ptr<asmtk::AsmParser> parser;
    std::unique_ptr<asmjit::x86::Assembler> assembler;
    int target_pid;
    uintptr_t base_address;
    size_t base_size;
    size_t code_size;
    size_t allocated_size;
    void allocate_first_page()
    {
        std::cerr << "Allocating first page" << std::endl;
        allocated_size = 4096;
        base_address = reinterpret_cast<uintptr_t>(mmap(nullptr, allocated_size,
            PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (base_address == -1)
        {
            std::cerr << "Failed to allocate memory" << std::endl;
            throw std::runtime_error("Failed to allocate memory");
        }
        if (base_address == 0)
        {
            std::cerr << "Failed to allocate memory: Base Address = 0x0" << std::endl;
            throw std::runtime_error("Failed to allocate memory");
        }
        std::cerr << "Base Address: " << "0x" << std::hex << base_address << std::endl;
    }
    void allocate_new_page()
    {
        std::cerr << "Allocating new page" << std::endl;
        auto new_address = reinterpret_cast<uintptr_t>(mmap(reinterpret_cast<void*>(base_address + allocated_size), 4096,
            PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        allocated_size += 4096;
        if (new_address == -1)
        {
            std::cerr << "Failed to allocate memory" << std::endl;
            throw std::runtime_error("Failed to allocate memory");
        }
    }
    void deallocate_memory()
    {
        if (base_address != 0)
        {
            munmap(reinterpret_cast<void*>(base_address), base_size);
        }
    }
    void copy_code_to_memory()
    {
        asmjit::CodeBuffer& buffer = code->sectionById(0)->buffer();
        code_size = buffer.size();
        std::cout << std::endl;
        std::cout << "Base Size: " << std::dec << base_size << std::endl;
        std::cout << "Code Size: " << std::dec << code_size << std::endl;
        std::cerr << "Copying code to memory: " << std::dec << (code_size - base_size) << std::endl;
        if (code_size > allocated_size)
        {
            if (base_address == 0)
            {
                allocate_first_page();
            }
            else
            {
                allocate_new_page();
            }
        }
        if (code_size - base_size > 0)
        {
            memcpy(reinterpret_cast<void *>(base_address + base_size), &buffer[base_size], code_size - base_size);
        }
        base_size = code_size;
    }
    void create_ptrace_thread()
    {
        target_pid = fork();
        if (target_pid == -1)
        {
            std::cerr << "Failed to create thread" << std::endl;
            throw std::runtime_error("Failed to create thread");
        }
        if (target_pid == 0)
        {
            std::cerr << "In child thread" << std::endl;
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            raise(SIGSTOP);
            void(*func)() = reinterpret_cast<void(*)()>(base_address);
            std::cerr << "Jumping to base address: " << "0x" << std::hex << base_address << std::endl;
            func();
            kill(getpid(), SIGKILL);
            for (;;)
            {
                pause();
            }
        }
        else
        {
            std::cerr << "Thread created" << std::endl;
        }
    }
    void connect_to_thread()
    {
        waitpid(target_pid, nullptr, 0);
        std::cerr << "Allowing thread to continue" << std::endl;
        if (ptrace(PTRACE_CONT, target_pid, 0, 0) == -1)
        {
            std::cerr << "Failed to connect to thread" << std::endl;
            throw std::runtime_error("Failed to connect to thread");
        }
        ptrace(PTRACE_SYSCALL, target_pid, 0, 0);
        waitpid(target_pid, nullptr, 0);
        std::cerr << "Connected to thread: " << target_pid << std::endl;
    }
    void execute_instruction()
    {
        std::cerr << "Executing instruction: 0x" << std::hex << get_instruction_pointer() << std::endl;
        csh handle;
        cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        cs_insn* insn;
        size_t count = cs_disasm(handle, reinterpret_cast<uint8_t*>(get_instruction_pointer()), 15, get_instruction_pointer(), 1, &insn);
        if (count == 0)
        {
            std::cerr << "Failed to disassemble instruction" << std::endl;
            throw std::runtime_error("Failed to disassemble instruction");
        }
        for (size_t i = 0; i < count; i++)
        {
            std::cerr << "Instruction: " << insn[i].mnemonic << " " << insn[i].op_str << std::endl;
        }
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        {
            std::cerr << "Failed to open capstone" << std::endl;
            throw std::runtime_error("Failed to open capstone");
        }
        if (ptrace(PTRACE_SINGLESTEP, target_pid, 0, 0) == -1)
        {
            std::cerr << "Failed to execute instruction" << std::endl;
            std::cerr << "RIP: " << "0x" << std::hex << get_instruction_pointer() << std::endl;
            throw std::runtime_error("Failed to execute instruction");
        }
        waitpid(target_pid, nullptr, 0);
        std::cerr << "Instruction executed" << std::endl;
    }
    void step_until_done()
    {
        while (get_instruction_pointer() < base_address + code_size)
        {
            execute_instruction();
        }
    }
    void kill_thread()
    {
        if (ptrace(PTRACE_KILL, target_pid, 0, 0) == -1)
        {
            std::cerr << "Failed to kill thread" << std::endl;
            throw std::runtime_error("Failed to kill thread");
        }
    }
public:
    uint64_t get_instruction_pointer()
    {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, target_pid, 0, &regs);
        return regs.rip;
    }
    ShellRuntime() : base_address(0), base_size(0), code_size(0), allocated_size(0)
    {
        runtime = std::make_unique<asmjit::JitRuntime>();
        code = std::make_unique<asmjit::CodeHolder>();
        code->init(runtime->environment(), runtime->cpuFeatures());
        assembler = std::make_unique<asmjit::x86::Assembler>(code.get());
        parser = std::make_unique<asmtk::AsmParser>(assembler.get());
        assembler->int3();
        copy_code_to_memory();
        create_ptrace_thread();
        connect_to_thread();
    }
    bool parse(std::string line)
    {
        return parser->parse(line.c_str()) == 0;
    }
    void execute()
    {
        copy_code_to_memory();
        step_until_done();
    }
    ~ShellRuntime()
    {
        deallocate_memory();
    }
    uint64_t get_register(std::string reg)
    {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, target_pid, 0, &regs);
        if (reg == "rax")
        {
            return regs.rax;
        }
        if (reg == "rbx")
        {
            return regs.rbx;
        }
        if (reg == "rcx")
        {
            return regs.rcx;
        }
        if (reg == "rdx")
        {
            return regs.rdx;
        }
        if (reg == "rsi")
        {
            return regs.rsi;
        }
        if (reg == "rdi")
        {
            return regs.rdi;
        }
        if (reg == "rbp")
        {
            return regs.rbp;
        }
        if (reg == "rsp")
        {
            return regs.rsp;
        }
        if (reg == "r8")
        {
            return regs.r8;
        }
        if (reg == "r9")
        {
            return regs.r9;
        }
        if (reg == "r10")
        {
            return regs.r10;
        }
        if (reg == "r11")
        {
            return regs.r11;
        }
        if (reg == "r12")
        {
            return regs.r12;
        }
        if (reg == "r13")
        {
            return regs.r13;
        }
        if (reg == "r14")
        {
            return regs.r14;
        }
        if (reg == "r15")
        {
            return regs.r15;
        }
        if (reg == "rip")
        {
            return regs.rip;
        }
        if (reg == "rflags")
        {
            return regs.eflags;
        }
        if (reg == "cs")
        {
            return regs.cs;
        }
        if (reg == "fs")
        {
            return regs.fs;
        }
        if (reg == "gs")
        {
            return regs.gs;
        }
        if (reg == "ss")
        {
            return regs.ss;
        }
        if (reg == "ds")
        {
            return regs.ds;
        }
        if (reg == "es")
        {
            return regs.es;
        }
        if (reg == "fs_base")
        {
            return regs.fs_base;
        }
        if (reg == "gs_base")
        {
            return regs.gs_base;
        }
        if (reg == "eax")
        {
            return regs.rax & 0xFFFFFFFF;
        }
        if (reg == "ebx")
        {
            return regs.rbx & 0xFFFFFFFF;
        }
        if (reg == "ecx")
        {
            return regs.rcx & 0xFFFFFFFF;
        }
        if (reg == "edx")
        {
            return regs.rdx & 0xFFFFFFFF;
        }
        if (reg == "esi")
        {
            return regs.rsi & 0xFFFFFFFF;
        }
        if (reg == "edi")
        {
            return regs.rdi & 0xFFFFFFFF;
        }
        if (reg == "ebp")
        {
            return regs.rbp & 0xFFFFFFFF;
        }
        if (reg == "esp")
        {
            return regs.rsp & 0xFFFFFFFF;
        }
        if (reg == "r8d")
        {
            return regs.r8 & 0xFFFFFFFF;
        }
        if (reg == "r9d")
        {
            return regs.r9 & 0xFFFFFFFF;
        }
        if (reg == "r10d")
        {
            return regs.r10 & 0xFFFFFFFF;
        }
        if (reg == "r11d")
        {
            return regs.r11 & 0xFFFFFFFF;
        }
        if (reg == "r12d")
        {
            return regs.r12 & 0xFFFFFFFF;
        }
        if (reg == "r13d")
        {
            return regs.r13 & 0xFFFFFFFF;
        }
        if (reg == "r14d")
        {
            return regs.r14 & 0xFFFFFFFF;
        }
        if (reg == "r15d")
        {
            return regs.r15 & 0xFFFFFFFF;
        }
        if (reg == "eip")
        {
            return regs.rip & 0xFFFFFFFF;
        }
        if (reg == "eflags")
        {
            return regs.eflags & 0xFFFFFFFF;
        }
        if (reg == "ax")
        {
            return (regs.rax & 0xFFFF);
        }
        if (reg == "bx")
        {
            return (regs.rbx & 0xFFFF);
        }
        if (reg == "cx")
        {
            return (regs.rcx & 0xFFFF);
        }
        if (reg == "dx")
        {
            return (regs.rdx & 0xFFFF);
        }
        if (reg == "bp")
        {
            return (regs.rbp & 0xFFFF);
        }
        if (reg == "si")
        {
            return (regs.rsi & 0xFFFF);
        }
        if (reg == "di")
        {
            return (regs.rdi & 0xFFFF);
        }
        if (reg == "r8w")
        {
            return (regs.r8 & 0xFFFF);
        }
        if (reg == "r9w")
        {
            return (regs.r9 & 0xFFFF);
        }
        if (reg == "r10w")
        {
            return (regs.r10 & 0xFFFF);
        }
        if (reg == "r11w")
        {
            return (regs.r11 & 0xFFFF);
        }
        if (reg == "r12w")
        {
            return (regs.r12 & 0xFFFF);
        }
        if (reg == "r13w")
        {
            return (regs.r13 & 0xFFFF);
        }
        if (reg == "r14w")
        {
            return (regs.r14 & 0xFFFF);
        }
        if (reg == "r15w")
        {
            return (regs.r15 & 0xFFFF);
        }
        if (reg == "ah")
        {
            return (regs.rax >> 8) & 0xFF;
        }
        if (reg == "bh")
        {
            return (regs.rbx >> 8) & 0xFF;
        }
        if (reg == "ch")
        {
            return (regs.rcx >> 8) & 0xFF;
        }
        if (reg == "dh")
        {
            return (regs.rdx >> 8) & 0xFF;
        }
        if (reg == "al")
        {
            return regs.rax & 0xFF;
        }
        if (reg == "bl")
        {
            return regs.rbx & 0xFF;
        }
        if (reg == "cl")
        {
            return regs.rcx & 0xFF;
        }
        if (reg == "dl")
        {
            return regs.rdx & 0xFF;
        }
        if (reg == "spl")
        {
            return (regs.rsp >> 8) & 0xFF;
        }
        if (reg == "bpl")
        {
            return (regs.rbp >> 8) & 0xFF;
        }
        if (reg == "sil")
        {
            return (regs.rsi >> 8) & 0xFF;
        }
        if (reg == "dil")
        {
            return (regs.rdi >> 8) & 0xFF;
        }
        throw std::runtime_error("Invalid register");
    }
};
bool is_register(std::string reg)
{
    return reg == "rax" || reg == "rbx" || reg == "rcx" || reg == "rdx" || reg == "rsi" || reg == "rdi"
        || reg == "rbp" || reg == "rsp" || reg == "r8" || reg == "r9" || reg == "r10" || reg == "r11"
        || reg == "r12" || reg == "r13" || reg == "r14" || reg == "r15" || reg == "rip" || reg == "rflags"
        || reg == "cs" || reg == "fs" || reg == "gs" || reg == "ss" || reg == "ds" || reg == "es"
        || reg == "fs_base" || reg == "gs_base" || reg == "eax" || reg == "ebx" || reg == "ecx"
        || reg == "edx" || reg == "esi" || reg == "edi" || reg == "ebp" || reg == "esp" || reg == "r8d"
        || reg == "r9d" || reg == "r10d" || reg == "r11d" || reg == "r12d" || reg == "r13d" || reg == "r14d"
        || reg == "r15d" || reg == "eip" || reg == "eflags" || reg == "ax" || reg == "bx" || reg == "cx"
        || reg == "dx" || reg == "bp" || reg == "si" || reg == "di" || reg == "r8w" || reg == "r9w"
        || reg == "r10w" || reg == "r11w" || reg == "r12w" || reg == "r13w" || reg == "r14w" || reg == "r15w"
        || reg == "ah" || reg == "bh" || reg == "ch" || reg == "dh" || reg == "al" || reg == "bl" || reg == "cl"
        || reg == "dl" || reg == "spl" || reg == "bpl" || reg == "sil" || reg == "dil";
}
int main(int argc, const char** argv)
{
    ShellRuntime runtime;
    while (true)
    {
        std::cout << ">> ";
        std::string line;
        std::getline(std::cin, line);
        if (line == "exit")
        {
            break;
        }
        if (line.empty())
        {
            continue;
        }
        if (line == "clear")
        {
            system("clear");
            continue;
        }
        if (line == "rip")
        {
            std::cout << "RIP: " << "0x" << std::hex << runtime.get_instruction_pointer() << std::endl;
            continue;
        }
        if (runtime.parse(line))
        {
            runtime.execute();
        }
        else
        {
            if (is_register(line))
            {
                std::cout << line << ": " << "0x" << std::hex << runtime.get_register(line) << std::endl;
            }
            else
            {
                std::cerr << "Invalid command" << std::endl;
            }
        }
    }
    return 0;
}