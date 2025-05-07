#include "pch.h"

namespace menu {
	bool isOpen = true;
	uintptr_t DevMenuAddr = 0x0;
	int getDevMenu()
	{
		uintptr_t Result;

		if (!FindPattern(&Result, "48 8B 05 ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? C5 ?? ?? ?? ?? ?? ?? ?? 4C", 0))
			return -1;
		DevMenuAddr = *(uintptr_t*)(Result + *(DWORD*)(Result + 3) + 7);
		return 0;
	}

	bool IsBadReadPtr(void* p)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (::VirtualQuery(p, &mbi, sizeof(mbi)))
		{
			DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
			bool b = !(mbi.Protect & mask);
			// check the page is not a guard page
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

			return b;
		}
		return true;
	}

	// Safe helper to read a byte at (DevMenuAddr + offset1) + offset2
	inline uint8_t ReadMenuToggle(uintptr_t offset1, uintptr_t offset2) {
		uintptr_t ptr1_addr = DevMenuAddr + offset1;
		if (IsBadReadPtr((void*)ptr1_addr)) return 0;
		uintptr_t ptr1 = *(uintptr_t*)ptr1_addr;
		if (IsBadReadPtr((void*)(ptr1 + offset2))) return 0;
		return *(uint8_t*)(ptr1 + offset2);
	}

	// Safe helper to write a byte at (DevMenuAddr + offset1) + offset2
	inline void WriteMenuToggle(uintptr_t offset1, uintptr_t offset2, uint8_t value) {
		uintptr_t ptr1_addr = DevMenuAddr + offset1;
		if (IsBadReadPtr((void*)ptr1_addr)) return;
		uintptr_t ptr1 = *(uintptr_t*)ptr1_addr;
		if (IsBadReadPtr((void*)(ptr1 + offset2))) return;
		*(uint8_t*)(ptr1 + offset2) = value;
	}

	// Specific helpers for each menu
	inline bool GetDevMenuEnabled() { return ReadMenuToggle(0x80, 0xC0) != 0; }
	inline void SetDevMenuEnabled(bool enable) { WriteMenuToggle(0x80, 0xC0, enable ? 1 : 0); }

	inline bool GetQuickMenuEnabled() { return ReadMenuToggle(0x78, 0xC0) != 0; }
	inline void SetQuickMenuEnabled(bool enable) { WriteMenuToggle(0x78, 0xC0, enable ? 1 : 0); }

	inline bool GetFavoritesMenuEnabled() { return ReadMenuToggle(0x88, 0xC0) != 0; }
	inline void SetFavoritesMenuEnabled(bool enable) { WriteMenuToggle(0x88, 0xC0, enable ? 1 : 0); }

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
	void CloseConsole()
	{
		// Free the console
		if (FreeConsole())
		{
			// Close the standard output
			fclose(stdout);
		}
	}
	void Init() {
		static bool no_titlebar = false;
		static bool no_border = true;
		static bool no_resize = false;
		static bool auto_resize = false;
		static bool no_move = false;
		static bool no_scrollbar = false;
		static bool no_collapse = false;
		static bool no_menu = true;
		static bool start_pos_set = false;

		ImVec4* colors = ImGui::GetStyle().Colors;
		colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
		colors[ImGuiCol_WindowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.83f);
		colors[ImGuiCol_ChildBg] = ImVec4(1.00f, 1.00f, 1.00f, 0.00f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
		colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
		colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.29f, 0.48f, 0.54f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.40f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
		colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
		colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.29f, 0.48f, 1.00f);
		colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		colors[ImGuiCol_MenuBarBg] = ImVec4(1.00f, 0.00f, 0.00f, 0.61f);
		colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
		colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.16f, 0.29f, 0.48f, 0.54f);
		colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
		colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
		colors[ImGuiCol_CheckMark] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		colors[ImGuiCol_SliderGrab] = ImVec4(0.24f, 0.52f, 0.88f, 1.00f);
		colors[ImGuiCol_SliderGrabActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		colors[ImGuiCol_Button] = ImVec4(0.26f, 0.59f, 0.98f, 0.40f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		colors[ImGuiCol_ButtonActive] = ImVec4(0.06f, 0.53f, 0.98f, 1.00f);
		colors[ImGuiCol_Header] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		colors[ImGuiCol_Separator] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
		colors[ImGuiCol_SeparatorHovered] = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
		colors[ImGuiCol_SeparatorActive] = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
		colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
		colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
		colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
		colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
		colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
		colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
		colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
		colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
		colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
		colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);

		ImGuiWindowFlags	window_flags = 0;
		if (no_titlebar)	window_flags |= ImGuiWindowFlags_NoTitleBar;
		if (no_resize)		window_flags |= ImGuiWindowFlags_NoResize;
		if (auto_resize)	window_flags |= ImGuiWindowFlags_AlwaysAutoResize;
		if (no_move)		window_flags |= ImGuiWindowFlags_NoMove;
		if (no_scrollbar)	window_flags |= ImGuiWindowFlags_NoScrollbar;
		if (no_collapse)	window_flags |= ImGuiWindowFlags_NoCollapse;
		if (!no_menu)		window_flags |= ImGuiWindowFlags_MenuBar;
		ImGui::SetNextWindowSize(ImVec2(450, 600));
		if (!start_pos_set) { ImGui::SetNextWindowPos(ImVec2(25, 25)); start_pos_set = true; }

		ImGui::GetIO().MouseDrawCursor = isOpen;

		if (isOpen)
		{
			ImGui::Begin("Menu", &isOpen, window_flags);
			// Dev Menu Toggle
			{
				bool devMenu = menu::GetDevMenuEnabled();
				if (ImGui::Checkbox("Show Dev Menu", &devMenu)) {
					menu::SetDevMenuEnabled(devMenu);
				}
			}

			// Quick Menu Toggle
			{
				bool quickMenu = menu::GetQuickMenuEnabled();
				if (ImGui::Checkbox("Show Quick Menu", &quickMenu)) {
					menu::SetQuickMenuEnabled(quickMenu);
				}
			}

			// Favorites Menu Toggle
			{
				bool favMenu = menu::GetFavoritesMenuEnabled();
				if (ImGui::Checkbox("Show Favorites Menu", &favMenu)) {
					menu::SetFavoritesMenuEnabled(favMenu);
				}
			}
			// Uninject
			if (ImGui::Button("Uninject"))
			{
				hooks::release();
			}
			// Allocate Console
			if (ImGui::Button("Allocate Console"))
			{
				AllocateConsole();
			}
			// Close Console
			if (ImGui::Button("Close Console"))
			{
				CloseConsole();
			}
			ImGui::End();
		}
	}
}