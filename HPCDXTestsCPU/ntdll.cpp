#include "ntdll_internal.h"
#include "ntdll_internal_funcs.h"

NTSTATUS __stdcall LdrGetDllHandle(WCHAR* DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
{
	return STATUS_SUCCESS;
}
void __stdcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{

}
NTSTATUS __stdcall RtlInitAnsiStringEx(_STRING* DestinationString, const char* SourceString)
{
	return STATUS_SUCCESS;
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