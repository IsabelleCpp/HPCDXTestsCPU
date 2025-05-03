#ifndef PCH_H
#define PCH_H

#include "framework.h"
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
struct VirtualKeyDataEntry
{
	ULONGLONG TickCountWhenPressed;
	DWORD isWithAlt;
	DWORD wasDownBefore;
	DWORD isUpNow;
};
bool __fastcall FindPattern(unsigned __int64* pResult, std::string Pattern, int Skips, HMODULE moduleBase = nullptr);

#include <dxgi.h>
#include <d3d12.h>
#include <dxgi1_4.h>

#if defined _M_X64
typedef uint64_t uintx_t;
#elif defined _M_IX86
typedef uint32_t uintx_t;
#endif

#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/backends/imgui_impl_dx12.h"

#include "namespaces.h"

#endif //PCH_H
