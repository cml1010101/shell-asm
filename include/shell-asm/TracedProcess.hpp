#ifndef TRACEDPROCESS_HPP
#define TRACEDPROCESS_HPP
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <functional>
#include <stdexcept>
#include <iostream>
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
        out << "RAX: " << regs.rax << std::endl;
        out << "RBX: " << regs.rbx << std::endl;
        out << "RCX: " << regs.rcx << std::endl;
        out << "RDX: " << regs.rdx << std::endl;
        out << "RDI: " << regs.rdi << std::endl;
        out << "RSI: " << regs.rsi << std::endl;
        out << "RBP: " << regs.rbp << std::endl;
        out << "RSP: " << regs.rsp << std::endl;
        out << "RIP: " << regs.rip << std::endl;
        out << "R8: " << regs.r8 << std::endl;
        out << "R9: " << regs.r9 << std::endl;
        out << "R10: " << regs.r10 << std::endl;
        out << "R11: " << regs.r11 << std::endl;
        out << "R12: " << regs.r12 << std::endl;
        out << "R13: " << regs.r13 << std::endl;
        out << "R14: " << regs.r14 << std::endl;
        out << "R15: " << regs.r15 << std::endl;
    }
    inline ~TracedProcess()
    {
        kill(pid, SIGKILL);
    }
private:
    pid_t pid;
};
#endif