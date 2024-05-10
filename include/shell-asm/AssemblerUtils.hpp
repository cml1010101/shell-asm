#ifndef ASSEMBLERUTILS_HPP
#define ASSEMBLERUTILS_HPP
#include <vector>
#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include <string>
#include <stdexcept>
#include <map>
#include <iostream>
class Assembler
{
public:
    inline Assembler()
    {
        self = this;
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        {
            throw std::runtime_error("Failed to initialize keystone");
        }
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
        {
            throw std::runtime_error("Failed to initialize capstone");
        }
        if (ks_option(ks, KS_OPT_SYM_RESOLVER, (uint64_t)&Assembler::symbol_resolver) != KS_ERR_OK)
        {
            throw std::runtime_error("Failed to set symbol resolver");
        }
    }
    std::pair<std::vector<uint8_t>, size_t> assemble(uint64_t offset, const std::vector<std::string> &lines)
    {
        size_t insn_count = 0;
        std::vector<uint8_t> bytes;
        for (auto &line : lines)
        {
            if (line.empty())
            {
                continue;
            }
            if (line.find(':') != std::string::npos)
            {
                std::string symbol = line.substr(0, line.find_last_of(':'));
                symbol = symbol.substr(line.find_last_of(' ') + 1);
                add_symbol(symbol, offset);
                continue;
            }
            size_t size;
            size_t count;
            uint8_t* data;
            if (ks_asm(ks, line.c_str(), offset, &data, &size, &count) != KS_ERR_OK)
            {
                throw std::invalid_argument("Failed to assemble instruction");
            }
            bytes.reserve(bytes.size() + size);
            bytes.insert(bytes.end(), data, data + size);
            ks_free(data);
            insn_count += count;
        }
        return {bytes, insn_count};
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
    inline static bool symbol_resolver(const char* symbol, uint64_t* value)
    {
        std::cout << "Searching for symbol: " << symbol << std::endl;
        auto it = self->symbols.find(symbol);
        if (it != self->symbols.end())
        {
            std::cout << "Resolved symbol " << symbol << " at " << std::hex << it->second << std::endl;
            *value = it->second;
            return true;
        }
        std::cerr << "Failed to resolve symbol: " << symbol << std::endl;
        return false;
    }
    inline void add_symbol(const std::string &name, uint64_t value)
    {
        std::cout << "Adding symbol " << name << " at " << std::hex << value << std::endl;
        symbols[name] = value;
    }
    inline ~Assembler()
    {
        ks_close(ks);
        cs_close(&cs);
    }
private:
    ks_engine* ks;
    csh cs;
    std::map<std::string, uint64_t> symbols;
    static Assembler* self;
};
Assembler* Assembler::self = nullptr;
#endif