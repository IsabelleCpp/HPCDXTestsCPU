#include "pch.h"
bool __fastcall FindPattern(unsigned __int64* pResult, std::string Pattern, int Skips, HMODULE moduleBase)
{
    struct PatternByte {
        uint8_t byte;
        bool isWildcard;
    };
    std::vector<PatternByte> patternBytes;

    std::istringstream iss(Pattern);
    std::string token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            patternBytes.push_back({ 0, true });
        }
        else if (token.size() == 2 && std::isxdigit(token[0]) && std::isxdigit(token[1])) {
            patternBytes.push_back({ static_cast<uint8_t>(std::stoi(token, nullptr, 16)), false });
        }
        else {
            return false;
        }
    }
    if (patternBytes.empty())
        return false;

    uintptr_t ModuleHandleA = moduleBase ? (uintptr_t)moduleBase : (uintptr_t)GetModuleHandleA(0);
    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleHandleA + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleHandleA)->e_lfanew);
    auto* Section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++Section) {
        if ((Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (Section->Characteristics & IMAGE_SCN_MEM_READ)) {
            uintptr_t SectionStartAddr = ModuleHandleA + Section->VirtualAddress;
            uintptr_t SectionEnd = SectionStartAddr + Section->Misc.VirtualSize - patternBytes.size();

            for (; SectionStartAddr < SectionEnd; ++SectionStartAddr) {
                bool found = true;
                for (size_t j = 0; j < patternBytes.size(); ++j) {
                    if (!patternBytes[j].isWildcard &&
                        *(uint8_t*)(SectionStartAddr + j) != patternBytes[j].byte) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    if (!Skips) {
                        *pResult = SectionStartAddr;
                        return true;
                    }
                    --Skips;
                }
            }
        }
    }
    return false;
}