#ifndef ASSEMBLERUTILS_HPP
#define ASSEMBLERUTILS_HPP
#include <vector>
#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include <string>
#include <stdexcept>
class Assembler
{
public:
    inline Assembler()
    {
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        {
            throw std::runtime_error("Failed to initialize keystone");
        }
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
        {
            throw std::runtime_error("Failed to initialize capstone");
        }
    }
    std::vector<uint8_t> assemble(const std::vector<std::string> &lines)
    {
        std::vector<uint8_t> bytes;
        for (auto &line : lines)
        {
            size_t size;
            size_t count;
            uint8_t* data;
            if (ks_asm(ks, line.c_str(), 0, &data, &size, &count) != KS_ERR_OK)
            {
                throw std::invalid_argument("Failed to assemble instruction");
            }
            bytes.reserve(bytes.size() + size);
            bytes.insert(bytes.end(), data, data + size);
            ks_free(data);
        }
        return bytes;
    }
    inline std::vector<std::string> disassemble(const std::vector<uint8_t> &bytes)
    {
        std::vector<std::string> lines;
        cs_insn* insn;
        size_t count = cs_disasm(cs, bytes.data(), bytes.size(), 0, 0, &insn);
        if (count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                lines.push_back((std::string)insn[i].mnemonic + " " + insn[i].op_str);
            }
            cs_free(insn, count);
        }
        else
        {
            throw std::runtime_error("Failed to disassemble instructions");
        }
        return lines;
    }
    inline ~Assembler()
    {
        ks_close(ks);
        cs_close(&cs);
    }
private:
    ks_engine* ks;
    csh cs;
};
#endif