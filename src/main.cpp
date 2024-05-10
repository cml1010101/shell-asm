#include <shell-asm/AssemblerUtils.hpp>
#include <shell-asm/TracedProcess.hpp>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <memory>
class ProcessMemory
{
public:
    ProcessMemory()
    {
        fd = shm_open("/process_memory", O_CREAT | O_RDWR, 0666);
        if (fd == -1)
        {
            throw std::runtime_error("Failed to create shared memory");
        }
        if (ftruncate(fd, 0x1000) == -1)
        {
            throw std::runtime_error("Failed to resize shared memory");
        }
        base = (uintptr_t)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
        if (base == (uintptr_t)MAP_FAILED)
        {
            throw std::runtime_error("Failed to allocate memory");
        }
        code_size = 0;
        allocated_size = 0x1000;
    }
    ~ProcessMemory()
    {
        munmap((void *)base, allocated_size);
    }
    void write(const std::vector<uint8_t> &bytes)
    {
        while (code_size + bytes.size() > allocated_size)
        {
            if (mmap((void *)(base + allocated_size), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED, -1, 0)
                != (void *)(base + allocated_size))
            {
                throw std::runtime_error("Failed to reallocate memory");
            }
            if (ftruncate(fd, allocated_size + 0x1000) == -1)
            {
                throw std::runtime_error("Failed to resize shared memory");
            }
            allocated_size += 0x1000;
        }
        std::copy(bytes.begin(), bytes.end(), (uint8_t *)(base + code_size));
        code_size += bytes.size();
    }
    uintptr_t get_base() const
    {
        return base;
    }
    uintptr_t get_address() const
    {
        return base + code_size;
    }
private:
    uintptr_t base;
    size_t code_size;
    size_t allocated_size;
    int fd;
};
void dump_memory(ProcessMemory &memory, size_t size)
{
    for (size_t i = 0; i < size; i += 16)
    {
        std::cout << std::hex << i << ": ";
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < size)
            {
                std::cout << std::hex << (uint32_t)*(uint8_t *)(memory.get_base() + i + j) << " ";
            }
            else
            {
                std::cout << "   ";
            }
        }
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < size)
            {
                char c = *(char *)(memory.get_base() + i + j);
                std::cout << (c >= 32 && c <= 126 ? c : '.');
            }
            else
            {
                std::cout << " ";
            }
        }
        std::cout << std::endl;
    }
}
int main()
{
    Assembler assembler;
    ProcessMemory memory;
    memory.write(assembler.assemble(memory.get_address(), {
        "int 3"
    }).first);
    TracedProcess process([&]() {
        std::cout << "Child process running" << std::endl;
        ((void (*)())memory.get_base())();
    });
    std::cout << "Child process started" << std::endl;
    process.continue_execution();
    process.print_registers();
    std::cout << "Child process reached breakpoint" << std::endl;
    while (true)
    {
        std::string line;
        std::cout << "> ";
        std::getline(std::cin, line);
        if (line == "quit")
        {
            break;
        }
        if (line == "dump")
        {
            dump_memory(memory, memory.get_address());
            continue;
        }
        if (line == "step")
        {
            process.step();
            process.print_registers();
            continue;
        }
        try
        {
            auto [insns, insn_count] = assembler.assemble(memory.get_address(), {line});
            memory.write(insns);
            for (size_t i = 0; i < insn_count; i++)
            {
                process.step();
            }
            process.print_registers();
        }
        catch(const std::invalid_argument& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    return 0;
}