#include "pch.h"
#include "minhook/MinHook.h"

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

void Wow64PrepareForExceptionHook(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT Context)
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

    // Log register state
    oss << "Register state:\r\n";
    oss << "RAX=0x" << std::hex << Context->Rax
        << " RBX=0x" << Context->Rbx
        << " RCX=0x" << Context->Rcx
        << " RDX=0x" << Context->Rdx << "\r\n";
    oss << "RSI=0x" << Context->Rsi
        << " RDI=0x" << Context->Rdi
        << " RBP=0x" << Context->Rbp
        << " RSP=0x" << Context->Rsp << "\r\n";
    oss << "R8 =0x" << Context->R8
        << " R9 =0x" << Context->R9
        << " R10=0x" << Context->R10
        << " R11=0x" << Context->R11 << "\r\n";
    oss << "R12=0x" << Context->R12
        << " R13=0x" << Context->R13
        << " R14=0x" << Context->R14
        << " R15=0x" << Context->R15 << "\r\n";
    oss << "RIP=0x" << Context->Rip
        << " EFlags=0x" << Context->EFlags << "\r\n";

    // Write to file (atomic append)
    const char* logFilePath = "E:\\Helper\\HPCDXTestsCPU\\x64\\Release\\ExceptionLog.txt";
    std::ofstream logFile(logFilePath, std::ios::app | std::ios::out | std::ios::binary);
    if (logFile.is_open()) {
        logFile << oss.str();
        logFile.close();
    }

    ExitProcess(0);
}

LONG VectoredExceptionHander(EXCEPTION_POINTERS* ExceptionInfo)
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
	auto ExceptionRecord = ExceptionInfo->ExceptionRecord;
	auto Context = ExceptionInfo->ContextRecord;
    DWORD code = ExceptionRecord->ExceptionCode;

    // Skip logging for specific exception codes
    switch (code) {
    case 0x40010006: // Debugger printed exception on control C
    case 0x406d1388: // UNKNOWN_EXCEPTION
    case 0xe06d7363: // UNKNOWN_EXCEPTION
        return EXCEPTION_CONTINUE_SEARCH;
    }

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

    // Log register state
    oss << "Register state:\r\n";
    oss << "RAX=0x" << std::hex << Context->Rax
        << " RBX=0x" << Context->Rbx
        << " RCX=0x" << Context->Rcx
        << " RDX=0x" << Context->Rdx << "\r\n";
    oss << "RSI=0x" << Context->Rsi
        << " RDI=0x" << Context->Rdi
        << " RBP=0x" << Context->Rbp
        << " RSP=0x" << Context->Rsp << "\r\n";
    oss << "R8 =0x" << Context->R8
        << " R9 =0x" << Context->R9
        << " R10=0x" << Context->R10
        << " R11=0x" << Context->R11 << "\r\n";
    oss << "R12=0x" << Context->R12
        << " R13=0x" << Context->R13
        << " R14=0x" << Context->R14
        << " R15=0x" << Context->R15 << "\r\n";
    oss << "RIP=0x" << Context->Rip
        << " EFlags=0x" << Context->EFlags << "\r\n";

    // Write to file (atomic append)
    const char* logFilePath = "E:\\Helper\\HPCDXTestsCPU\\x64\\Release\\ExceptionLog.txt";
    std::ofstream logFile(logFilePath, std::ios::app | std::ios::out | std::ios::binary);
    if (logFile.is_open()) {
        logFile << oss.str();
        logFile.close();
    }

	return EXCEPTION_CONTINUE_SEARCH;
}

typedef BOOLEAN(__fastcall* RtlDispatchException_t)(PEXCEPTION_RECORD, PCONTEXT);
RtlDispatchException_t oRtlDispatchException = nullptr;
BOOLEAN RtlDispatchExceptionHook(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT Context)
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

    // Log register state
    oss << "Register state:\r\n";
    oss << "RAX=0x" << std::hex << Context->Rax
        << " RBX=0x" << Context->Rbx
        << " RCX=0x" << Context->Rcx
        << " RDX=0x" << Context->Rdx << "\r\n";
    oss << "RSI=0x" << Context->Rsi
        << " RDI=0x" << Context->Rdi
        << " RBP=0x" << Context->Rbp
        << " RSP=0x" << Context->Rsp << "\r\n";
    oss << "R8 =0x" << Context->R8
        << " R9 =0x" << Context->R9
        << " R10=0x" << Context->R10
        << " R11=0x" << Context->R11 << "\r\n";
    oss << "R12=0x" << Context->R12
        << " R13=0x" << Context->R13
        << " R14=0x" << Context->R14
        << " R15=0x" << Context->R15 << "\r\n";
    oss << "RIP=0x" << Context->Rip
        << " EFlags=0x" << Context->EFlags << "\r\n";

    // Write to file (atomic append)
    const char* logFilePath = "E:\\Helper\\HPCDXTestsCPU\\x64\\Release\\ExceptionLog.txt";
    std::ofstream logFile(logFilePath, std::ios::app | std::ios::out | std::ios::binary);
    if (logFile.is_open()) {
        logFile << oss.str();
        logFile.close();
    }

	return TRUE;
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
        bool KiUserExceptionDispatcherAddrFound = FindPattern(&KiUserExceptionDispatcherAddr, "FC 48 8B 05", 0, GetModuleHandleA("NTDLL.DLL"));
		if (!KiUserExceptionDispatcherAddrFound)
		{
			ExitProcess(0);
		}
        PDWORD pWow64PrepareForExceptionRVA = (PDWORD)(KiUserExceptionDispatcherAddr + 0x4);
        uintptr_t* pWow64PrepareForException = (uintptr_t*)((KiUserExceptionDispatcherAddr + 0x8) + *pWow64PrepareForExceptionRVA);
        DWORD oldProtect;
        if (VirtualProtect(pWow64PrepareForException, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect)) {
            *pWow64PrepareForException = (uintptr_t)Wow64PrepareForExceptionHook; 
			VirtualProtect(pWow64PrepareForException, sizeof(uintptr_t), oldProtect, &oldProtect);
        }
        else {
			ExitProcess(0);
        }
		uintptr_t RtlDispatchExceptionAddr;
		bool RtlDispatchExceptionAddrFound = FindPattern(&RtlDispatchExceptionAddr, "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8D 6C 24 ?? 48 89 9D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C5 48 89 85 ?? ?? ?? ?? 65 48 8B 04 25", 0, GetModuleHandleA("NTDLL.DLL"));
		if (!RtlDispatchExceptionAddrFound) 
		{
			ExitProcess(0);
		}

        //MH_Initialize();
		//MH_CreateHook((void*)RtlDispatchExceptionAddr, (void*)RtlDispatchExceptionHook, (void**)&oRtlDispatchException);
        //*(uintptr_t*)0xDEADBEEF = 0xDEADC0DE;
		AddVectoredExceptionHandler(1, VectoredExceptionHander);
        globals::mainModule = hModule;
        hooks::Init();
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
