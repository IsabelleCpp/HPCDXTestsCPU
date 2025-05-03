#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    DisableThreadLibraryCalls(hModule);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        globals::mainModule = hModule;
        hooks::Init();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

