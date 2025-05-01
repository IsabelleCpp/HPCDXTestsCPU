#pragma once

_PEB* NtCurrentPeb();
NTSTATUS __stdcall LdrGetDllHandle(WCHAR* DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
void __stdcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS __stdcall RtlInitAnsiStringEx(_STRING* DestinationString, const char* SourceString);
NTSTATUS __stdcall RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, _STRING* SourceString, BOOLEAN AllocateDestinationString);
void __stdcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
void __stdcall RtlSetLastWin32Error(ULONG LastError);
ULONG __stdcall RtlNtStatusToDosError(NTSTATUS Status);