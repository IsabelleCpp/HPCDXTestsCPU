// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include <string>
#include <vector>
struct Vector_Type1 {
    size_t index;
    BYTE Byte;
};
struct VectorValTest1 {
    Vector_Type1* _Myfirst; // pointer to beginning of array
    Vector_Type1* _Mylast; // pointer to current end of sequence
    Vector_Type1* _Myend; // pointer to end of array
};
typedef std::vector<Vector_Type1> _Vector_val_1;
bool __fastcall FindPattern(unsigned __int64* pResult, std::string Pattern, int Skips);

#include <dxgi.h>
#include <d3d12.h>
//#pragma comment(lib, "d3d12.lib")

#if defined _M_X64
typedef uint64_t uintx_t;
#elif defined _M_IX86
typedef uint32_t uintx_t;
#endif

#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/backends/imgui_impl_dx12.h"
#include <d3d12.h>
#include <dxgi1_4.h>

#include "namespaces.h"
#include "kiero.h"

#endif //PCH_H
