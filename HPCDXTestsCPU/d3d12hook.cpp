#include "pch.h"
#include "minhook/MinHook.h"

namespace d3d12hook {
	struct ID3D12CommandQueueVtbl
	{
		HRESULT(__stdcall* QueryInterface)(ID3D12CommandQueue* This, const IID* const riid, void** ppvObject);
		ULONG(__stdcall* AddRef)(ID3D12CommandQueue* This);
		ULONG(__stdcall* Release)(ID3D12CommandQueue* This);
		HRESULT(__stdcall* GetPrivateData)(ID3D12CommandQueue* This, const GUID* const guid, UINT* pDataSize, void* pData);
		HRESULT(__stdcall* SetPrivateData)(ID3D12CommandQueue* This, const GUID* const guid, UINT DataSize, const void* pData);
		HRESULT(__stdcall* SetPrivateDataInterface)(ID3D12CommandQueue* This, const GUID* const guid, const IUnknown* pData);
		HRESULT(__stdcall* SetName)(ID3D12CommandQueue* This, LPCWSTR Name);
		HRESULT(__stdcall* GetDevice)(ID3D12CommandQueue* This, const IID* const riid, void** ppvDevice);
		void(__stdcall* UpdateTileMappings)(ID3D12CommandQueue* This, ID3D12Resource* pResource, UINT NumResourceRegions, const D3D12_TILED_RESOURCE_COORDINATE* pResourceRegionStartCoordinates, const D3D12_TILE_REGION_SIZE* pResourceRegionSizes, ID3D12Heap* pHeap, UINT NumRanges, const D3D12_TILE_RANGE_FLAGS* pRangeFlags, const UINT* pHeapRangeStartOffsets, const UINT* pRangeTileCounts, D3D12_TILE_MAPPING_FLAGS Flags);
		void(__stdcall* CopyTileMappings)(ID3D12CommandQueue* This, ID3D12Resource* pDstResource, const D3D12_TILED_RESOURCE_COORDINATE* pDstRegionStartCoordinate, ID3D12Resource* pSrcResource, const D3D12_TILED_RESOURCE_COORDINATE* pSrcRegionStartCoordinate, const D3D12_TILE_REGION_SIZE* pRegionSize, D3D12_TILE_MAPPING_FLAGS Flags);
		void(__stdcall* ExecuteCommandLists)(ID3D12CommandQueue* This, UINT NumCommandLists, ID3D12CommandList* const* ppCommandLists);
		void(__stdcall* SetMarker)(ID3D12CommandQueue* This, UINT Metadata, const void* pData, UINT Size);
		void(__stdcall* BeginEvent)(ID3D12CommandQueue* This, UINT Metadata, const void* pData, UINT Size);
		void(__stdcall* EndEvent)(ID3D12CommandQueue* This);
		HRESULT(__stdcall* Signal)(ID3D12CommandQueue* This, ID3D12Fence* pFence, UINT64 Value);
		HRESULT(__stdcall* Wait)(ID3D12CommandQueue* This, ID3D12Fence* pFence, UINT64 Value);
		HRESULT(__stdcall* GetTimestampFrequency)(ID3D12CommandQueue* This, UINT64* pFrequency);
		HRESULT(__stdcall* GetClockCalibration)(ID3D12CommandQueue* This, UINT64* pGpuTimestamp, UINT64* pCpuTimestamp);
		D3D12_COMMAND_QUEUE_DESC(__stdcall* GetDesc)(ID3D12CommandQueue* This);
	};
	ID3D12Device* d3d12Device = nullptr;
	ID3D12DescriptorHeap* d3d12DescriptorHeapBackBuffers = nullptr;
	ID3D12DescriptorHeap* d3d12DescriptorHeapImGuiRender = nullptr;
	ID3D12GraphicsCommandList* d3d12CommandList = nullptr;
	ID3D12Fence* d3d12Fence = nullptr;
	UINT64 d3d12FenceValue = 0;
	ID3D12CommandQueue* d3d12CommandQueue = nullptr;

	PresentD3D12 oPresentD3D12;

	void(*oExecuteCommandListsD3D12)(ID3D12CommandQueue*, UINT, ID3D12CommandList*);
	HRESULT(*oSignalD3D12)(ID3D12CommandQueue*, ID3D12Fence*, UINT64);

	struct __declspec(uuid("189819f1-1db6-4b57-be54-1821339b85f7")) ID3D12Device;

	struct FrameContext {
		ID3D12CommandAllocator* commandAllocator = nullptr;
		ID3D12Resource* main_render_target_resource = nullptr;
		D3D12_CPU_DESCRIPTOR_HANDLE main_render_target_descriptor;
	};

	uintx_t buffersCounts = -1;
	FrameContext* frameContext;

	bool shutdown = false;

	long __fastcall hookPresentD3D12(IDXGISwapChain3* pSwapChain, UINT SyncInterval, UINT Flags) {
		static bool init = false;

		if (inputhook::VkStatesArray[globals::openQuickMenuKey].TickCountWhenPressed && !inputhook::VkStatesArray[globals::openQuickMenuKey].wasDownBefore && !inputhook::VkStatesArray[globals::openQuickMenuKey].isUpNow) {
			inputhook::VkStatesArray[globals::openQuickMenuKey] = VirtualKeyDataEntry{ 0 };
			static bool quickMenu = false;
			quickMenu = !quickMenu;
			menu::SetQuickMenuEnabled(quickMenu);
		}
		if (inputhook::VkStatesArray[globals::openFavoritesMenuKey].TickCountWhenPressed && !inputhook::VkStatesArray[globals::openFavoritesMenuKey].wasDownBefore && !inputhook::VkStatesArray[globals::openFavoritesMenuKey].isUpNow) {
			inputhook::VkStatesArray[globals::openFavoritesMenuKey] = VirtualKeyDataEntry{ 0 };
			static bool favMenu = false;
			favMenu = !favMenu;
			menu::SetFavoritesMenuEnabled(favMenu);
		}
		if (inputhook::VkStatesArray[globals::openDevMenuKey].TickCountWhenPressed && !inputhook::VkStatesArray[globals::openDevMenuKey].wasDownBefore && !inputhook::VkStatesArray[globals::openDevMenuKey].isUpNow) {
			inputhook::VkStatesArray[globals::openDevMenuKey] = VirtualKeyDataEntry{ 0 };
			static bool devMenu = false;
			devMenu = !devMenu;
			menu::SetDevMenuEnabled(devMenu);
		}
		if (inputhook::VkStatesArray[globals::uninjectKey].TickCountWhenPressed && !inputhook::VkStatesArray[globals::uninjectKey].wasDownBefore && !inputhook::VkStatesArray[globals::uninjectKey].isUpNow) {
			inputhook::VkStatesArray[globals::uninjectKey] = VirtualKeyDataEntry{ 0 };
			hooks::release();
			return oPresentD3D12(pSwapChain, SyncInterval, Flags);
		}

		if (!init) {
			if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D12Device), (void**)&d3d12Device))) {
				if (!globals::mainWindow)
					pSwapChain->GetHwnd(&globals::mainWindow);
				if (!globals::mainWindow)
					globals::mainWindow = GetForegroundWindow();

				inputhook::Init(globals::mainWindow);
			}
			menu::getDevMenu();
			init = true;
		}

		return oPresentD3D12(pSwapChain, SyncInterval, Flags);
	}

	void hookExecuteCommandListsD3D12(ID3D12CommandQueue* queue, UINT NumCommandLists, ID3D12CommandList* ppCommandLists) {
		if (!d3d12CommandQueue)
			d3d12CommandQueue = queue;

		oExecuteCommandListsD3D12(queue, NumCommandLists, ppCommandLists);
	}

	HRESULT hookSignalD3D12(ID3D12CommandQueue* queue, ID3D12Fence* fence, UINT64 value) {
		if (d3d12CommandQueue != nullptr && queue == d3d12CommandQueue) {
			d3d12Fence = fence;
			d3d12FenceValue = value;
		}

		return oSignalD3D12(queue, fence, value);
	}

	void release() {
		shutdown = true;
	}
}