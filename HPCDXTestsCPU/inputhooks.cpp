#include "pch.h"
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
using namespace ImGui;

namespace inputhook {
	WNDPROC	oWndProc;
	VirtualKeyDataEntry VkStatesArray[0xFF]{};

	void Init(HWND hWindow)
	{
		oWndProc = (WNDPROC)SetWindowLongPtr(hWindow, GWLP_WNDPROC, (__int3264)(LONG_PTR)WndProc);
	}

	void Remove(HWND hWindow)
	{
		SetWindowLongPtr(hWindow, GWLP_WNDPROC, (LONG_PTR)oWndProc);
	}

	void __fastcall UpdateKeyState(DWORD key, WORD repeats, BYTE scanCode, BOOL isExtended, BOOL isWithAlt, BOOL wasDownBefore, BOOL isUpNow)
	{
		if (key < 0xFF)
		{
			VkStatesArray[key].TickCountWhenPressed = GetTickCount64();
			VkStatesArray[key].isWithAlt = isWithAlt;
			VkStatesArray[key].wasDownBefore = wasDownBefore;
			VkStatesArray[key].isUpNow = isUpNow;
		}
	}

	LRESULT APIENTRY WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
        switch (uMsg) {
			case WM_KEYDOWN:
			case WM_SYSKEYDOWN:
			case WM_KEYUP:
			case WM_SYSKEYUP: {

				WORD vkCode = LOWORD(wParam);                                 // virtual-key code

				WORD repeatCount = LOWORD(lParam);                            // repeat count, > 0 if several keydown messages was combined into one message

				WORD keyFlags = HIWORD(lParam);

				BYTE scanCode = LOBYTE(keyFlags);                             // scan code

				BOOL isExtendedKey = (keyFlags & KF_EXTENDED) == KF_EXTENDED; // extended-key flag, 1 if scancode has 0xE0 prefix

				BOOL wasKeyDown = (keyFlags & KF_REPEAT) == KF_REPEAT;        // previous key-state flag, 1 on autorepeat

				BOOL isKeyReleased = (keyFlags & KF_UP) == KF_UP;             // transition-state flag, 1 on keyup

				BOOL isWithAlt = (keyFlags & KF_ALTDOWN) == KF_ALTDOWN;

				UpdateKeyState(vkCode, repeatCount, scanCode, isExtendedKey, isWithAlt, wasKeyDown, isKeyReleased);

				break;
			}
        }

		if (menu::isOpen) {
			ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
			return true;
		}
		return CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
	}
}