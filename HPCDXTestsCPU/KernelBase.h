#pragma once
#include "intrin.h"
#include <Windows.h>
#include <winternl.h>

NTSTATUS __fastcall Basep8BitStringToDynamicUnicodeString(
    struct _UNICODE_STRING* DstStringUnicodeString,
    const char* SourceString);
HMODULE __stdcall GetModuleHandleA_EAC(LPCSTR lpModuleName);
HMODULE __stdcall GetModuleHandleW_EAC(LPCWSTR lpModuleName);
__int64 __fastcall BaseSetLastNTError(NTSTATUS a1);