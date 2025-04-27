// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"
bool __fastcall FindPattern(unsigned __int64* pResult, std::string Pattern, int Skips)
{
    size_t ByteArraySize; // eax
    char c1; // r12
    char c2; // r15
    uintptr_t ModuleHandleA; // rax
    PIMAGE_NT_HEADERS ntHeaders; // rdx
    PIMAGE_SECTION_HEADER First_Section;
    uintptr_t SectionStartAddr; // r8
    uintptr_t SectionEnd; // r9
    bool WasPatternFound = false; // al
    _Vector_val_1 byteArray; // [rsp+0x28] [rbp-0x71] BYREF
    Vector_Type1 ByteData{}; // [rsp+0x40] [rbp-0x59] BYREF
    std::string ByteString; // [rsp+0x90] [rbp-0x9] BYREF

    if (Pattern.size())
    {
        std::erase(Pattern, ' ');
    }
    std::size_t PatternStringSize = Pattern.size();
    if (!PatternStringSize || (PatternStringSize & 1) != 0)
    {
        return WasPatternFound;
    }
    ByteArraySize = PatternStringSize / 2;

    for (std::size_t i = 0; i < ByteArraySize; ++i) {
        c1 = Pattern[2 * i];

        c2 = Pattern[2 * i + 1];
        if (c1 == '?' || c2 == '?')
        {
            if (c1 != c2)
            {
                return WasPatternFound;
            }
        }
        else
        {
            ByteString = Pattern.substr(2 * i, 2);
            ByteData.index = i;
            ByteData.Byte = std::stoi(ByteString, nullptr, 16);
            byteArray.push_back(ByteData);
        }
    }
    ModuleHandleA = (uintptr_t)GetModuleHandleA(0i64);
    ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleHandleA + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleHandleA)->e_lfanew);
    First_Section = IMAGE_FIRST_SECTION(ntHeaders);
    SectionStartAddr = ModuleHandleA + First_Section->VirtualAddress;
    SectionEnd = SectionStartAddr + First_Section->Misc.VirtualSize - ByteArraySize;

    if (!byteArray.size())
    {
        return WasPatternFound;
    }

    for (; SectionStartAddr < SectionEnd; ++SectionStartAddr)
    {
        WasPatternFound = true;

        for (const auto& ByteStruct : byteArray)
        {
            if (*(BYTE*)(ByteStruct.index + SectionStartAddr) != ByteStruct.Byte)
            {
                WasPatternFound = false;
                break;
            }
        }

        if (WasPatternFound)
        {
            if (!Skips)
            {
                *pResult = SectionStartAddr;
                break;
            }
            --Skips;
        }
    }


    return WasPatternFound;
}