#include "pch.h"

const char* ExceptionCodeToString(DWORD code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    default:                                return "UNKNOWN_EXCEPTION";
    }
}

void VectoredHandler(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT Context)
{
    auto GetModuleInfo = [](PVOID address, std::string& moduleName, ptrdiff_t& relativeAddr) -> HMODULE {
        MEMORY_BASIC_INFORMATION mbi = {};
        HMODULE hModule = nullptr;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
            hModule = (HMODULE)mbi.AllocationBase;
            char buf[MAX_PATH];
            if (GetModuleFileNameA(hModule, buf, MAX_PATH)) {
                moduleName = buf;
                relativeAddr = static_cast<const char*>(address) - reinterpret_cast<const char*>(hModule);
            }
            else {
                moduleName = "<error>";
                relativeAddr = 0;
            }
        }
        else {
            moduleName = "<unknown>";
            relativeAddr = 0;
        }
        return hModule;
        };

    DWORD code = ExceptionRecord->ExceptionCode;
    PVOID address = ExceptionRecord->ExceptionAddress;
    std::string moduleName;
    ptrdiff_t relativeAddr = 0;
    HMODULE hModule = GetModuleInfo(address, moduleName, relativeAddr);

    std::ostringstream oss;
    oss << "Exception code: 0x" << std::hex << std::setw(8) << std::setfill('0') << code
        << " (" << ExceptionCodeToString(code) << ")\r\n";

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR accessType = ExceptionRecord->ExceptionInformation[0];
        PVOID faultingAddress = reinterpret_cast<PVOID>(ExceptionRecord->ExceptionInformation[1]);
        oss << "Access type: " << (accessType == 0 ? "Read" : (accessType == 1 ? "Write" : "Execute")) << "\r\n";
        oss << "Faulting address: " << faultingAddress << "\r\n";
        if (accessType == 1 && ExceptionRecord->NumberParameters > 2) {
            ULONG_PTR valueBeingWritten = ExceptionRecord->ExceptionInformation[2];
            oss << "Value being written: 0x" << std::hex << valueBeingWritten << "\r\n";
        }
    }
    else if (code == EXCEPTION_IN_PAGE_ERROR) {
        ULONG_PTR accessType = ExceptionRecord->ExceptionInformation[0];
        PVOID faultingAddress = reinterpret_cast<PVOID>(ExceptionRecord->ExceptionInformation[1]);
        ULONG_PTR ntStatus = (ExceptionRecord->NumberParameters >= 3) ? ExceptionRecord->ExceptionInformation[2] : 0;
        oss << "Access type: "
            << (accessType == 0 ? "Read" : (accessType == 1 ? "Write" : (accessType == 8 ? "Execute" : "Unknown"))) << "\r\n";
        oss << "Faulting address: " << faultingAddress << "\r\n";
        oss << "NTSTATUS code: 0x" << std::hex << ntStatus << "\r\n";
    }
    else {
        LPWSTR pMessage = NULL;
        FormatMessage(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            GetModuleHandle(L"ntdll.dll"),
            code,
            0,
            (LPWSTR)&pMessage,
            0,
            NULL);

        oss << "Exception at: 0x" << std::hex << address << "\r\n";
        oss << "Code: 0x" << std::hex << code;
        if (pMessage) {
            std::wstring ws(pMessage);
            std::string msg(ws.begin(), ws.end());
            oss << ": " << msg;
            LocalFree(pMessage);
        }
        oss << "\r\n";
    }

    oss << "Location: " << moduleName << "+0x" << std::hex << relativeAddr;
    oss << "\r\n";

    // Stack trace helper
    auto AppendStackTrace = [&oss, &GetModuleInfo]() {
        std::vector<void*> stack(16);
        USHORT frames = CaptureStackBackTrace(0, static_cast<DWORD>(stack.size()), stack.data(), NULL);
        oss << "Stack trace:\r\n";
        for (USHORT i = 0; i < frames; ++i) {
            std::string frameModuleName;
            ptrdiff_t frameRelAddr = 0;
            GetModuleInfo(stack[i], frameModuleName, frameRelAddr);
            oss << "  " << frameModuleName << "+0x" << std::hex << frameRelAddr;
            oss << "\r\n";
        }
    };
    AppendStackTrace();

    // Write to file (atomic append)
    const char* logFilePath = "E:\\Helper\\HPCDXTestsCPU\\x64\\Release\\ExceptionLog.txt";
    std::ofstream logFile(logFilePath, std::ios::app | std::ios::out | std::ios::binary);
    if (logFile.is_open()) {
        logFile << oss.str();
        logFile.close();
    }

    ExitProcess(0);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hModule);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        uintptr_t KiUserExceptionDispatcherAddr;
        FindPattern(&KiUserExceptionDispatcherAddr, "FC 48 8B 05", 0, GetModuleHandleA("NTDLL.DLL"));

        PDWORD pWow64PrepareForExceptionRVA = (PDWORD)(KiUserExceptionDispatcherAddr + 0x4);
        uintptr_t* pWow64PrepareForException = (uintptr_t*)((KiUserExceptionDispatcherAddr + 0x8) + *pWow64PrepareForExceptionRVA);
        DWORD oldProtect;
        if (VirtualProtect(pWow64PrepareForException, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect)) {
            *pWow64PrepareForException = (uintptr_t)VectoredHandler; 
			VirtualProtect(pWow64PrepareForException, sizeof(uintptr_t), oldProtect, &oldProtect);
        }
        else {
			ExitProcess(0);
        }
		*(uintptr_t*)0xDEADBEEF = 0xDEADC0DE;
        globals::mainModule = hModule;
        hooks::Init();
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
