// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

uintptr_t DevMenuAddr = 0x0;
int getDevMenu()
{
    uintptr_t Result;

    if (!FindPattern(&Result, "48 8B 05 ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? 4C", 0))
        return -1;
	DevMenuAddr = Result;
	return 0;
}

void AllocateConsole()
{
    // Allocate a console
    if (AllocConsole())
    {
        // Redirect standard output to the console
        FILE* fileStream;
        freopen_s(&fileStream, "CONOUT$", "w", stdout);
    }
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
            Beep(666, 1000);
			//MessageBoxA(0, "Failed to find DevMenu pattern", "Error", MB_ICONERROR);
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

