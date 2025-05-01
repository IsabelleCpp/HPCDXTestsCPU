#include "ntdll_internal.h"
#include "ntdll_internal_funcs.h"
#include "defs.h"
NTSTATUS __stdcall LdrGetDllHandle(WCHAR* DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
{
	return STATUS_SUCCESS;
}

void __stdcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) 
{
    __int64 v2; // rax
    unsigned __int64 v3; // rax

    *(_QWORD*)&DestinationString->Length = 0;
    DestinationString->Buffer = (wchar_t*)SourceString;
    if (SourceString)
    {
        v2 = -1;
        do
            ++v2;
        while (SourceString[v2]);
        v3 = 2 * v2;
        if (v3 >= 0xFFFE)
            LOWORD(v3) = 0xFFFC;
        DestinationString->Length = v3;
        DestinationString->MaximumLength = v3 + 2;
    }
}

NTSTATUS __stdcall RtlInitAnsiStringEx(_STRING* DestinationString, const char* SourceString)
{
    unsigned __int64 v2; // rax

    *(_QWORD*)&DestinationString->Length = 0;
    DestinationString->Buffer = (char*)SourceString;
    if (!SourceString)
        return 0;
    v2 = -1;
    do
        ++v2;
    while (SourceString[v2]);
    if (v2 <= 0xFFFE)
    {
        DestinationString->Length = v2;
        DestinationString->MaximumLength = v2 + 1;
        return 0;
    }
    return 0xC0000106;
}

NTSTATUS __stdcall RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, _STRING* SourceString, BOOLEAN AllocateDestinationString)
{
	return STATUS_SUCCESS;
}
void __stdcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
{

}
void __stdcall RtlSetLastWin32Error(ULONG LastError)
{

}
ULONG __stdcall RtlNtStatusToDosError(NTSTATUS Status)
{
	return 0;
}