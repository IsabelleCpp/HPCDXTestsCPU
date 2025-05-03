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

		if (GetAsyncKeyState(globals::openMenuKey) & 0x1) {
			menu::isOpen ? menu::isOpen = false : menu::isOpen = true;
		}

		if (GetAsyncKeyState(globals::uninjectKey) & 0x1) {
			hooks::release();
			return oPresentD3D12(pSwapChain, SyncInterval, Flags);
		}

		if (!init) {
			if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D12Device), (void**)&d3d12Device))) {
				ImGui::CreateContext();

				unsigned char* pixels;
				int width, height;
				ImGuiIO& io = ImGui::GetIO(); (void)io;
				ImGui::StyleColorsDark();
				io.Fonts->AddFontDefault();
				io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
				io.IniFilename = NULL;

				CreateEvent(nullptr, false, false, nullptr);

				DXGI_SWAP_CHAIN_DESC sdesc;
				pSwapChain->GetDesc(&sdesc);
				sdesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

				if (!globals::mainWindow)
					pSwapChain->GetHwnd(&globals::mainWindow);
				if (!globals::mainWindow)
					globals::mainWindow = GetForegroundWindow();

				sdesc.OutputWindow = globals::mainWindow;
				sdesc.Windowed = ((GetWindowLongPtr(globals::mainWindow, GWL_STYLE) & WS_POPUP) != 0) ? false : true;

				buffersCounts = sdesc.BufferCount;
				frameContext = new FrameContext[buffersCounts];

				D3D12_DESCRIPTOR_HEAP_DESC descriptorImGuiRender = {};
				descriptorImGuiRender.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
				descriptorImGuiRender.NumDescriptors = buffersCounts;
				descriptorImGuiRender.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

				if (d3d12Device->CreateDescriptorHeap(&descriptorImGuiRender, IID_PPV_ARGS(&d3d12DescriptorHeapImGuiRender)) != S_OK)
					return false;

				ID3D12CommandAllocator* allocator;
				if (d3d12Device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator)) != S_OK)
					return false;

				for (size_t i = 0; i < buffersCounts; i++) {
					frameContext[i].commandAllocator = allocator;
				}

				if (d3d12Device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, NULL, IID_PPV_ARGS(&d3d12CommandList)) != S_OK ||
					d3d12CommandList->Close() != S_OK)
					return false;

				D3D12_DESCRIPTOR_HEAP_DESC descriptorBackBuffers;
				descriptorBackBuffers.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
				descriptorBackBuffers.NumDescriptors = buffersCounts;
				descriptorBackBuffers.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
				descriptorBackBuffers.NodeMask = 1;

				if (d3d12Device->CreateDescriptorHeap(&descriptorBackBuffers, IID_PPV_ARGS(&d3d12DescriptorHeapBackBuffers)) != S_OK)
					return false;

				const auto rtvDescriptorSize = d3d12Device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
				D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = d3d12DescriptorHeapBackBuffers->GetCPUDescriptorHandleForHeapStart();

				for (size_t i = 0; i < buffersCounts; i++) {
					ID3D12Resource* pBackBuffer = nullptr;

					frameContext[i].main_render_target_descriptor = rtvHandle;
					pSwapChain->GetBuffer(i, IID_PPV_ARGS(&pBackBuffer));
					d3d12Device->CreateRenderTargetView(pBackBuffer, nullptr, rtvHandle);
					frameContext[i].main_render_target_resource = pBackBuffer;
					rtvHandle.ptr += rtvDescriptorSize;
				}

				ImGui_ImplWin32_Init(globals::mainWindow);
				ImGui_ImplDX12_Init(d3d12Device, buffersCounts,
					DXGI_FORMAT_R8G8B8A8_UNORM, d3d12DescriptorHeapImGuiRender,
					d3d12DescriptorHeapImGuiRender->GetCPUDescriptorHandleForHeapStart(),
					d3d12DescriptorHeapImGuiRender->GetGPUDescriptorHandleForHeapStart());

				ImGui_ImplDX12_CreateDeviceObjects();

				inputhook::Init(globals::mainWindow);
				D3D12_COMMAND_QUEUE_DESC queueDesc;
				queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
				queueDesc.Priority = 0;
				queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
				queueDesc.NodeMask = 0;
				ID3D12CommandQueue* commandQueue;
				if (SUCCEEDED(d3d12Device->CreateCommandQueue(&queueDesc, __uuidof(ID3D12CommandQueue), (void**)&commandQueue)))
				{
					// Usage in your code  
					ID3D12CommandQueueVtbl* commandQueueVtable = *reinterpret_cast<ID3D12CommandQueueVtbl**>(commandQueue);
					MH_CreateHook(commandQueueVtable->ExecuteCommandLists, d3d12hook::hookExecuteCommandListsD3D12, (void**)&d3d12hook::oExecuteCommandListsD3D12);
					MH_EnableHook(commandQueueVtable->ExecuteCommandLists);
					MH_CreateHook(commandQueueVtable->Signal, d3d12hook::hookSignalD3D12, (void**)&d3d12hook::oSignalD3D12);
					MH_EnableHook(commandQueueVtable->Signal);
					commandQueue->Release();
				}
			}
			menu::getDevMenu();
			init = true;
		}

		if (shutdown == false) {
			if (d3d12CommandQueue == nullptr)
				return oPresentD3D12(pSwapChain, SyncInterval, Flags);

			ImGui_ImplDX12_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();

			menu::Init();

			FrameContext& currentFrameContext = frameContext[pSwapChain->GetCurrentBackBufferIndex()];
			currentFrameContext.commandAllocator->Reset();

			D3D12_RESOURCE_BARRIER barrier;
			barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
			barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
			barrier.Transition.pResource = currentFrameContext.main_render_target_resource;
			barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
			barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
			barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

			d3d12CommandList->Reset(currentFrameContext.commandAllocator, nullptr);
			d3d12CommandList->ResourceBarrier(1, &barrier);
			d3d12CommandList->OMSetRenderTargets(1, &currentFrameContext.main_render_target_descriptor, FALSE, nullptr);
			d3d12CommandList->SetDescriptorHeaps(1, &d3d12DescriptorHeapImGuiRender);

			ImGui::Render();
			ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), d3d12CommandList);

			barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
			barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;

			d3d12CommandList->ResourceBarrier(1, &barrier);
			d3d12CommandList->Close();

			d3d12CommandQueue->ExecuteCommandLists(1, reinterpret_cast<ID3D12CommandList* const*>(&d3d12CommandList));
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
		d3d12Device->Release();
		d3d12DescriptorHeapBackBuffers->Release();
		d3d12DescriptorHeapImGuiRender->Release();
		d3d12CommandList->Release();
		d3d12Fence->Release();
		d3d12CommandQueue->Release();
	}
}