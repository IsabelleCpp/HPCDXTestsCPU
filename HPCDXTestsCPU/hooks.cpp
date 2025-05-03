#include "pch.h"
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_dx12.h"
#include "imgui/backends/imgui_impl_win32.h"
# include "minhook/MinHook.h"
namespace hooks {
	void Init() {
		HMODULE libDXGI;
		if ((libDXGI = ::GetModuleHandle(TEXT("dxgi.dll"))) == NULL)
		{
			Beep(220, 100);
			return;
		}
		MH_Initialize();
		// Find and Hook CDXGISwapChain::Present
		uintptr_t CDXGISwapChain_Present = 0;
		bool CDXGISwapChain_Present_Found = FindPattern(&CDXGISwapChain_Present, "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 45 33 F6", 0, libDXGI);
		if (!CDXGISwapChain_Present_Found || !CDXGISwapChain_Present)
		{
			Beep(220, 100);
			return;
		}
		MH_CreateHook((void*)CDXGISwapChain_Present, d3d12hook::hookPresentD3D12, (void**)&d3d12hook::oPresentD3D12);
		MH_EnableHook((void*)CDXGISwapChain_Present);
		Beep(626, 100);
	}
	void onDetach() {
		d3d12hook::release();

		MH_DisableHook(MH_ALL_HOOKS);

		inputhook::Remove(globals::mainWindow);

		Beep(220, 100);

		FreeLibraryAndExitThread(globals::mainModule, 0);
	}

	void release() {
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)onDetach, globals::mainModule, 0, 0);
	}
}