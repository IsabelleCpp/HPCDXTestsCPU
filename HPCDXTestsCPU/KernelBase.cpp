#include "KernelBaseInternal.h"
#include "KernelBaseInternalFuncs.h"
#include "ntdll_internal_funcs.h"

_PEB* NtCurrentPeb() {
#ifdef _M_X64
    return (_PEB*)(__readgsqword(0x60));
#elif _M_IX86
    return (_PEB*)(__readfsdword(0x30));
#else
#error "NtCurrentPeb architecture is not unsupported"
#endif
}

__int64 __fastcall BaseSetLastNTError(NTSTATUS a1)
{
    ULONG v1; // ebx

    v1 = RtlNtStatusToDosError(a1);
    RtlSetLastWin32Error(v1);
    return v1;
}

NTSTATUS __fastcall Basep8BitStringToDynamicUnicodeString(
    struct _UNICODE_STRING* DstStringUnicodeString,
    const char* SourceString)
{
    NTSTATUS Status; // eax
    struct _STRING SourceAnsiString; // [rsp+20h] [rbp-18h] BYREF

    if (RtlInitAnsiStringEx(&SourceAnsiString, SourceString) < 0)
        goto Error;
    Status = RtlAnsiStringToUnicodeString(DstStringUnicodeString, &SourceAnsiString, 1u);
    if (Status >= 0)
        return 1;
    if (Status == 0x80000005)
        Error:
    RtlSetLastWin32Error(0xCEu);
    else
        BaseSetLastNTError(Status);
    return 0;
}

HMODULE __stdcall GetModuleHandleW_EAC(LPCWSTR lpModuleName)
{
    HMODULE DllHandleInvalidResult; // rbx
    int Status; // eax
    int Status_1; // edi
    HMODULE DllHandleResult; // rcx
    struct _UNICODE_STRING DestinationString; // [rsp+20h] [rbp-18h] BYREF
    PVOID DllHandle; // [rsp+40h] [rbp+8h] BYREF

    DllHandleInvalidResult = 0;
    if (!lpModuleName)
        return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
    RtlInitUnicodeString(&DestinationString, lpModuleName);
    Status = LdrGetDllHandle(0, 0, &DestinationString, &DllHandle);
    Status_1 = Status;
    if (Status < 0)
    {
        BaseSetLastNTError(Status);
        DllHandleResult = 0;
    }
    else
    {
        DllHandleResult = (HMODULE)DllHandle;
    }
    if (Status_1 >= 0)
        return DllHandleResult;
    return DllHandleInvalidResult;
}

HMODULE __stdcall GetModuleHandleA_EAC(LPCSTR lpModuleName)
{
    HMODULE ModuleHandleW; // rbx
    UNICODE_STRING UnicodeString; // [rsp+20h] [rbp-18h] BYREF

    if (!lpModuleName)
        return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
    if (!Basep8BitStringToDynamicUnicodeString(&UnicodeString, lpModuleName))
        return 0;
    ModuleHandleW = GetModuleHandleW_EAC(UnicodeString.Buffer);
    RtlFreeUnicodeString(&UnicodeString);
    return ModuleHandleW;
}