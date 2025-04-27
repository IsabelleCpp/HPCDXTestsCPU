// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

uintptr_t DevMenuAddr = 0x0;
int getDevMenu()
{
    uintptr_t Result;

    if (!FindPattern(&Result, "48 89 5C 24 08 48 89 7C 24 10 45 33 D2 4C 8B", 0))
        return -1;
	DevMenuAddr = Result;
	return 0;
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    DisableThreadLibraryCalls(hModule);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if(getDevMenu() == -1)
		{
			MessageBoxA(0, "Failed to find DevMenu pattern", "Error", MB_ICONERROR);
			return FALSE;
		}
        globals::mainModule = hModule;
        hooks::Init();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

