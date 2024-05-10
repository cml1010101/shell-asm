#ifndef TRACEDPROCESS_HPP
#define TRACEDPROCESS_HPP
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <functional>
#include <stdexcept>
#include <iostream>
#include <iomanip>
class TracedProcess
{
public:
    inline TracedProcess(std::function<void()> callback)
    {
        pid = fork();
        if (pid == 0)
        {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            {
                throw std::runtime_error("Failed to trace child process");
            }
            raise(SIGSTOP);
            callback();
        }
        else
        {
            int status;
            waitpid(pid, &status, 0);
        }
    }
    inline void continue_execution()
    {
        int status;
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
    inline void step()
    {
        int status;
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
    inline void print_registers(std::ostream& out = std::cout)
    {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        out << "RIP: " << std::hex << std::setw(16) << std::setfill('0') << regs.rip << std::endl;
        out << "RAX: " << std::hex << std::setw(16) << std::setfill('0') << regs.rax << std::endl;
        out << "RBX: " << std::hex << std::setw(16) << std::setfill('0') << regs.rbx << std::endl;
        out << "RCX: " << std::hex << std::setw(16) << std::setfill('0') << regs.rcx << std::endl;
        out << "RDX: " << std::hex << std::setw(16) << std::setfill('0') << regs.rdx << std::endl;
        out << "RDI: " << std::hex << std::setw(16) << std::setfill('0') << regs.rdi << std::endl;
        out << "RSI: " << std::hex << std::setw(16) << std::setfill('0') << regs.rsi << std::endl;
        out << "RBP: " << std::hex << std::setw(16) << std::setfill('0') << regs.rbp << std::endl;
        out << "RSP: " << std::hex << std::setw(16) << std::setfill('0') << regs.rsp << std::endl;
        out << "R8:  " << std::hex << std::setw(16) << std::setfill('0') << regs.r8 << std::endl;
        out << "R9:  " << std::hex << std::setw(16) << std::setfill('0') << regs.r9 << std::endl;
        out << "R10: " << std::hex << std::setw(16) << std::setfill('0') << regs.r10 << std::endl;
        out << "R11: " << std::hex << std::setw(16) << std::setfill('0') << regs.r11 << std::endl;
        out << "R12: " << std::hex << std::setw(16) << std::setfill('0') << regs.r12 << std::endl;
        out << "R13: " << std::hex << std::setw(16) << std::setfill('0') << regs.r13 << std::endl;
        out << "R14: " << std::hex << std::setw(16) << std::setfill('0') << regs.r14 << std::endl;
        out << "R15: " << std::hex << std::setw(16) << std::setfill('0') << regs.r15 << std::endl;
    }
    inline ~TracedProcess()
    {
        kill(pid, SIGKILL);
    }
private:
    pid_t pid;
};
#endif