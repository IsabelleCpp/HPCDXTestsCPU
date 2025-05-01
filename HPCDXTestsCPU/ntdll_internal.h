#pragma once
struct _CONTEXT;
struct _UNWIND_HISTORY_TABLE;
struct _IMAGE_RUNTIME_FUNCTION_ENTRY;
struct _KNONVOLATILE_CONTEXT_POINTERS;
struct _EXCEPTION_RECORD;
struct _RTL_CRITICAL_SECTION_DEBUG;
struct _TEB_ACTIVE_FRAME_CONTEXT;
struct _RTL_BALANCED_NODE;
struct _KPCR;
struct _KDPC;
struct _KSCHEDULING_GROUP;
struct _KSCB;
struct _KTRAP_FRAME;
struct _KPROCESS;
struct _KTHREAD;
struct _KQUEUE;
struct _KWAIT_BLOCK;
struct _KTIMER;
struct _THREAD_PERFORMANCE_DATA;
struct _KTHREAD_COUNTERS;
struct _XSTATE_SAVE;
struct _XSAVE_AREA_HEADER;
struct _XSAVE_AREA;
struct _RTL_UMS_CONTEXT;
struct _UMS_CONTROL_BLOCK;
struct _KEXCEPTION_FRAME;
struct _KUMS_CONTEXT_HEADER;
struct _KAPC;
struct _KPRCB;
struct _KLOCK_ENTRY;
struct _KNODE;
struct _KSPIN_LOCK_QUEUE;
struct _LOOKASIDE_LIST_EX;
struct _GENERAL_LOOKASIDE;
struct _KSTATIC_AFFINITY_BLOCK;
struct _RTL_HASH_TABLE;
struct _PROCESSOR_IDLE_CONSTRAINTS;
struct _PROCESSOR_IDLE_DEPENDENCY;
struct _PROCESSOR_IDLE_PREPARE_INFO;
struct _PERFINFO_PPM_STATE_SELECTION;
struct _PPM_SELECTION_DEPENDENCY;
struct _PPM_SELECTION_MENU_ENTRY;
struct _PPM_VETO_ENTRY;
struct _PPM_IDLE_STATES;
struct _PROC_IDLE_ACCOUNTING;
struct _PROC_FEEDBACK_COUNTER;
struct _PERF_CONTROL_STATE_SELECTION;
struct _PROC_PERF_CONSTRAINT;
struct _PROC_PERF_DOMAIN;
struct _PROC_PERF_CHECK;
struct _PROC_PERF_LOAD;
struct _PROC_PERF_HISTORY;
struct _PPM_CONCURRENCY_ACCOUNTING;
struct _KSHARED_READY_QUEUE;
struct _PROCESSOR_PROFILE_CONTROL_AREA;
struct _REQUEST_MAILBOX;
union _KIDTENTRY64;
struct _ETHREAD;
struct _DEVICE_OBJECT;
struct _DRIVER_OBJECT;
struct _IO_CLIENT_EXTENSION;
struct _VPB;
struct _SECTION_OBJECT_POINTERS;
struct _FILE_OBJECT;
struct _IO_COMPLETION_CONTEXT;
struct _OWNER_ENTRY;
struct _FS_FILTER_SECTION_SYNC_OUTPUT;
struct _MDL;
struct _EPROCESS;
struct _IRP;
struct _SECURITY_QUALITY_OF_SERVICE;
struct _ACCESS_STATE;
struct _IO_SECURITY_CONTEXT;
struct _NAMED_PIPE_CREATE_PARAMETERS;
struct _MAILSLOT_CREATE_PARAMETERS;
struct _FILE_GET_QUOTA_INFORMATION;
struct _INTERFACE;
struct _DEVICE_CAPABILITIES;
struct _IO_RESOURCE_REQUIREMENTS_LIST;
struct _POWER_SEQUENCE;
struct _CM_RESOURCE_LIST;
struct _IO_STACK_LOCATION;
struct _FS_FILTER_CALLBACK_DATA;
struct _FS_FILTER_CALLBACKS;
struct _DRIVER_EXTENSION;
struct _FILE_BASIC_INFORMATION;
struct _FILE_STANDARD_INFORMATION;
struct _FILE_NETWORK_OPEN_INFORMATION;
struct _COMPRESSED_DATA_INFO;
struct _FAST_IO_DISPATCH;
struct _IO_TIMER;
struct _DEVOBJ_EXTENSION;
struct _THREAD_ENERGY_VALUES;
struct _EJOB;
struct _IO_MINI_COMPLETION_PACKET_USER;
struct _OBJECT_DIRECTORY_ENTRY;
struct _DEVICE_MAP;
struct _OBJECT_DIRECTORY;
struct _EX_TIMEZONE_STATE;
struct _SILO_USER_SHARED_DATA;
struct _ESERVERSILO_GLOBALS;
struct _PROCESS_EXTENDED_ENERGY_VALUES;
union _JOBOBJECT_ENERGY_TRACKING_STATE;
struct _HANDLE_TABLE;
struct _EWOW64PROCESS;
struct _OBJECT_NAME_INFORMATION;
struct _PO_DIAG_STACK_RECORD;
struct _DYNAMIC_FUNCTION_TABLE;
struct _INVERTED_FUNCTION_TABLE;
struct _HANDLE_TABLE_ENTRY_INFO;
union _HANDLE_TABLE_ENTRY;
struct _HANDLE_TRACE_DEBUG_INFO;
struct _HEAP;
struct _HEAP_TAG_ENTRY;
struct _HEAP_PSEUDO_TAG_ENTRY;
struct _HEAP_LOCK;
struct _HEAP_LOCAL_DATA;
struct _LFH_HEAP;
struct _HEAP_SUBSEGMENT;
struct _HEAP_USERDATA_HEADER;
struct _RTL_TRACE_SEGMENT;
struct _RTL_TRACE_BLOCK;
struct _DPH_HEAP_BLOCK;
struct __crt_locale_pointers;
struct _OBJECT_ATTRIBUTES;
struct _iobuf;

/* 1 */
typedef struct _CONTEXT* PCONTEXT;

/* 3 */
typedef unsigned __int64 DWORD64;

/* 4 */
typedef unsigned int DWORD;

/* 5 */
typedef unsigned __int16 WORD;

/* 10 */
typedef unsigned __int8 BYTE;
typedef BYTE _BYTE;

/* 13 */
typedef unsigned __int64 ULONGLONG;

/* 14 */
typedef __int64 LONGLONG;

/* 12 */
struct __declspec(align(16)) _M128A
{
    ULONGLONG Low;
    LONGLONG High;
};

/* 11 */
typedef struct _M128A M128A;

/* 9 */
struct __declspec(align(16)) _XSAVE_FORMAT
{
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

/* 8 */
typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

/* 7 */
typedef XSAVE_FORMAT XMM_SAVE_AREA32;

/* 2 */
struct __declspec(align(16)) _CONTEXT
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union
    {
        XMM_SAVE_AREA32 FltSave;
        struct
        {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

/* 16 */
typedef struct _UNWIND_HISTORY_TABLE* PUNWIND_HISTORY_TABLE;

/* 20 */
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY* PRUNTIME_FUNCTION;

/* 19 */
struct _UNWIND_HISTORY_TABLE_ENTRY
{
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

/* 18 */
typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

/* 17 */
struct _UNWIND_HISTORY_TABLE
{
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

/* 21 */
#pragma pack(push, 4)
struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
#pragma pack(push, 4)
    union
    {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    };
#pragma pack(pop)
};
#pragma pack(pop)

/* 23 */
typedef unsigned __int64* PULONG64;

/* 24 */
typedef struct _KNONVOLATILE_CONTEXT_POINTERS* PKNONVOLATILE_CONTEXT_POINTERS;

/* 27 */
typedef struct _M128A* PM128A;


/* 30 */
typedef unsigned __int64* PDWORD64;

/* 25 */
struct _KNONVOLATILE_CONTEXT_POINTERS
{
    union
    {
        PM128A FloatingContext[16];
        struct
        {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };
    union
    {
        PDWORD64 IntegerContext[16];
        struct
        {
            PDWORD64 Rax;
            PDWORD64 Rcx;
            PDWORD64 Rdx;
            PDWORD64 Rbx;
            PDWORD64 Rsp;
            PDWORD64 Rbp;
            PDWORD64 Rsi;
            PDWORD64 Rdi;
            PDWORD64 R8;
            PDWORD64 R9;
            PDWORD64 R10;
            PDWORD64 R11;
            PDWORD64 R12;
            PDWORD64 R13;
            PDWORD64 R14;
            PDWORD64 R15;
        };
    };
};

/* 33 */
typedef unsigned int ULONG;

/* 32 */
typedef ULONG* PULONG;

/* 34 */
typedef void* PVOID;

/* 36 */
typedef wchar_t WCHAR;

/* 35 */
typedef const WCHAR* PCWSTR;

/* 38 */
typedef DWORD* PDWORD;

/* 39 */
typedef int(__cdecl* _CoreCrtNonSecureSearchSortCompareFunction)(const void*, const void*);

/* 40 */
typedef int(__cdecl* _CoreCrtSecureSearchSortCompareFunction)(void*, const void*, const void*);

/* 41 */
typedef char* va_list;

/* 42 */
typedef unsigned __int64 size_t;
typedef int NTSTATUS;
typedef WCHAR* PWSTR;

/* 43 */
enum SE_WS_APPX_SIGNATURE_ORIGIN : __int32
{
    SE_WS_APPX_SIGNATURE_ORIGIN_NOT_VALIDATED = 0x0,
    SE_WS_APPX_SIGNATURE_ORIGIN_UNKNOWN = 0x1,
    SE_WS_APPX_SIGNATURE_ORIGIN_APPSTORE = 0x2,
    SE_WS_APPX_SIGNATURE_ORIGIN_WINDOWS = 0x3,
    SE_WS_APPX_SIGNATURE_ORIGIN_ENTERPRISE = 0x4,
};

/* 44 */
enum _PS_MITIGATION_OPTION : __int32
{
    PS_MITIGATION_OPTION_NX = 0x0,
    PS_MITIGATION_OPTION_SEHOP = 0x1,
    PS_MITIGATION_OPTION_FORCE_RELOCATE_IMAGES = 0x2,
    PS_MITIGATION_OPTION_HEAP_TERMINATE = 0x3,
    PS_MITIGATION_OPTION_BOTTOM_UP_ASLR = 0x4,
    PS_MITIGATION_OPTION_HIGH_ENTROPY_ASLR = 0x5,
    PS_MITIGATION_OPTION_STRICT_HANDLE_CHECKS = 0x6,
    PS_MITIGATION_OPTION_WIN32K_SYSTEM_CALL_DISABLE = 0x7,
    PS_MITIGATION_OPTION_EXTENSION_POINT_DISABLE = 0x8,
    PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE = 0x9,
    PS_MITIGATION_OPTION_CONTROL_FLOW_GUARD = 0xA,
    PS_MITIGATION_OPTION_BLOCK_NON_MICROSOFT_BINARIES = 0xB,
    PS_MITIGATION_OPTION_FONT_DISABLE = 0xC,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_REMOTE = 0xD,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_LOW_LABEL = 0xE,
    PS_MITIGATION_OPTION_IMAGE_LOAD_PREFER_SYSTEM32 = 0xF,
    PS_MITIGATION_OPTION_RETURN_FLOW_GUARD = 0x10,
    PS_MITIGATION_OPTION_LOADER_INTEGRITY_CONTINUITY = 0x11,
    PS_MITIGATION_OPTION_STRICT_CONTROL_FLOW_GUARD = 0x12,
    PS_MITIGATION_OPTION_RESTRICT_SET_THREAD_CONTEXT = 0x13,
    PS_MITIGATION_OPTION_ROP_STACKPIVOT = 0x14,
    PS_MITIGATION_OPTION_ROP_CALLER_CHECK = 0x15,
    PS_MITIGATION_OPTION_ROP_SIMEXEC = 0x16,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER = 0x17,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER_PLUS = 0x18,
    PS_MITIGATION_OPTION_RESTRICT_CHILD_PROCESS_CREATION = 0x19,
    PS_MITIGATION_OPTION_IMPORT_ADDRESS_FILTER = 0x1A,
    PS_MITIGATION_OPTION_MODULE_TAMPERING_PROTECTION = 0x1B,
    PS_MITIGATION_OPTION_RESTRICT_INDIRECT_BRANCH_PREDICTION = 0x1C,
    PS_MITIGATION_OPTION_SPECULATIVE_STORE_BYPASS_DISABLE = 0x1D,
    PS_MITIGATION_OPTION_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY = 0x1E,
    PS_MITIGATION_OPTION_CET_USER_SHADOW_STACKS = 0x1F,
    PS_MITIGATION_OPTION_USER_CET_SET_CONTEXT_IP_VALIDATION = 0x20,
    PS_MITIGATION_OPTION_BLOCK_NON_CET_BINARIES = 0x21,
    PS_MITIGATION_OPTION_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY = 0x24,
    PS_MITIGATION_OPTION_REDIRECTION_TRUST = 0x25,
    PS_MITIGATION_OPTION_FSCTL_SYSTEM_CALL_DISABLE = 0x26,
};

/* 45 */
enum _NT_PRODUCT_TYPE : __int32
{
    NtProductWinNt = 0x1,
    NtProductLanManNt = 0x2,
    NtProductServer = 0x3,
};

/* 46 */
enum _ALTERNATIVE_ARCHITECTURE_TYPE : __int32
{
    StandardDesign = 0x0,
    NEC98x86 = 0x1,
    EndAlternatives = 0x2,
};

/* 47 */
enum _TP_CALLBACK_PRIORITY : __int32
{
    TP_CALLBACK_PRIORITY_HIGH = 0x0,
    TP_CALLBACK_PRIORITY_NORMAL = 0x1,
    TP_CALLBACK_PRIORITY_LOW = 0x2,
    TP_CALLBACK_PRIORITY_INVALID = 0x3,
    TP_CALLBACK_PRIORITY_COUNT = 0x3,
};

/* 48 */
enum _MODE : __int32
{
    KernelMode = 0x0,
    UserMode = 0x1,
    MaximumMode = 0x2,
};

/* 49 */
enum _POOL_TYPE : __int32
{
    NonPagedPool = 0x0,
    NonPagedPoolExecute = 0x0,
    PagedPool = 0x1,
    NonPagedPoolMustSucceed = 0x2,
    DontUseThisType = 0x3,
    NonPagedPoolCacheAligned = 0x4,
    PagedPoolCacheAligned = 0x5,
    NonPagedPoolCacheAlignedMustS = 0x6,
    MaxPoolType = 0x7,
    NonPagedPoolBase = 0x0,
    NonPagedPoolBaseMustSucceed = 0x2,
    NonPagedPoolBaseCacheAligned = 0x4,
    NonPagedPoolBaseCacheAlignedMustS = 0x6,
    NonPagedPoolSession = 0x20,
    PagedPoolSession = 0x21,
    NonPagedPoolMustSucceedSession = 0x22,
    DontUseThisTypeSession = 0x23,
    NonPagedPoolCacheAlignedSession = 0x24,
    PagedPoolCacheAlignedSession = 0x25,
    NonPagedPoolCacheAlignedMustSSession = 0x26,
    NonPagedPoolNx = 0x200,
    NonPagedPoolNxCacheAligned = 0x204,
    NonPagedPoolSessionNx = 0x220,
};

/* 50 */
enum _EX_POOL_PRIORITY : __int32
{
    LowPoolPriority = 0x0,
    LowPoolPrioritySpecialPoolOverrun = 0x8,
    LowPoolPrioritySpecialPoolUnderrun = 0x9,
    NormalPoolPriority = 0x10,
    NormalPoolPrioritySpecialPoolOverrun = 0x18,
    NormalPoolPrioritySpecialPoolUnderrun = 0x19,
    HighPoolPriority = 0x20,
    HighPoolPrioritySpecialPoolOverrun = 0x28,
    HighPoolPrioritySpecialPoolUnderrun = 0x29,
};

/* 51 */
enum _EVENT_TYPE : __int32
{
    NotificationEvent = 0x0,
    SynchronizationEvent = 0x1,
};

/* 52 */
enum _PP_NPAGED_LOOKASIDE_NUMBER : __int32
{
    LookasideSmallIrpList = 0x0,
    LookasideMediumIrpList = 0x1,
    LookasideLargeIrpList = 0x2,
    LookasideMdlList = 0x3,
    LookasideCreateInfoList = 0x4,
    LookasideNameBufferList = 0x5,
    LookasideTwilightList = 0x6,
    LookasideCompletionList = 0x7,
    LookasideScratchBufferList = 0x8,
    LookasideMaximumList = 0x9,
};

/* 53 */
enum _EX_GEN_RANDOM_DOMAIN : __int32
{
    ExGenRandomDomainKernel = 0x0,
    ExGenRandomDomainFirst = 0x0,
    ExGenRandomDomainUserVisible = 0x1,
    ExGenRandomDomainMax = 0x2,
};

/* 54 */
enum _SYSTEM_DLL_TYPE : __int32
{
    PsNativeSystemDll = 0x0,
    PsWowX86SystemDll = 0x1,
    PsWowArm32SystemDll = 0x2,
    PsWowAmd64SystemDll = 0x3,
    PsWowChpeX86SystemDll = 0x4,
    PsVsmEnclaveRuntimeDll = 0x5,
    PsSystemDllTotalTypes = 0x6,
};

/* 55 */
enum _FILE_INFORMATION_CLASS : __int32
{
    FileDirectoryInformation = 0x1,
    FileFullDirectoryInformation = 0x2,
    FileBothDirectoryInformation = 0x3,
    FileBasicInformation = 0x4,
    FileStandardInformation = 0x5,
    FileInternalInformation = 0x6,
    FileEaInformation = 0x7,
    FileAccessInformation = 0x8,
    FileNameInformation = 0x9,
    FileRenameInformation = 0xA,
    FileLinkInformation = 0xB,
    FileNamesInformation = 0xC,
    FileDispositionInformation = 0xD,
    FilePositionInformation = 0xE,
    FileFullEaInformation = 0xF,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13,
    FileEndOfFileInformation = 0x14,
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FilePipeInformation = 0x17,
    FilePipeLocalInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileMailslotQueryInformation = 0x1A,
    FileMailslotSetInformation = 0x1B,
    FileCompressionInformation = 0x1C,
    FileObjectIdInformation = 0x1D,
    FileCompletionInformation = 0x1E,
    FileMoveClusterInformation = 0x1F,
    FileQuotaInformation = 0x20,
    FileReparsePointInformation = 0x21,
    FileNetworkOpenInformation = 0x22,
    FileAttributeTagInformation = 0x23,
    FileTrackingInformation = 0x24,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileValidDataLengthInformation = 0x27,
    FileShortNameInformation = 0x28,
    FileIoCompletionNotificationInformation = 0x29,
    FileIoStatusBlockRangeInformation = 0x2A,
    FileIoPriorityHintInformation = 0x2B,
    FileSfioReserveInformation = 0x2C,
    FileSfioVolumeInformation = 0x2D,
    FileHardLinkInformation = 0x2E,
    FileProcessIdsUsingFileInformation = 0x2F,
    FileNormalizedNameInformation = 0x30,
    FileNetworkPhysicalNameInformation = 0x31,
    FileIdGlobalTxDirectoryInformation = 0x32,
    FileIsRemoteDeviceInformation = 0x33,
    FileUnusedInformation = 0x34,
    FileNumaNodeInformation = 0x35,
    FileStandardLinkInformation = 0x36,
    FileRemoteProtocolInformation = 0x37,
    FileRenameInformationBypassAccessCheck = 0x38,
    FileLinkInformationBypassAccessCheck = 0x39,
    FileVolumeNameInformation = 0x3A,
    FileIdInformation = 0x3B,
    FileIdExtdDirectoryInformation = 0x3C,
    FileReplaceCompletionInformation = 0x3D,
    FileHardLinkFullIdInformation = 0x3E,
    FileIdExtdBothDirectoryInformation = 0x3F,
    FileDispositionInformationEx = 0x40,
    FileRenameInformationEx = 0x41,
    FileRenameInformationExBypassAccessCheck = 0x42,
    FileDesiredStorageClassInformation = 0x43,
    FileStatInformation = 0x44,
    FileMemoryPartitionInformation = 0x45,
    FileStatLxInformation = 0x46,
    FileCaseSensitiveInformation = 0x47,
    FileLinkInformationEx = 0x48,
    FileLinkInformationExBypassAccessCheck = 0x49,
    FileStorageReserveIdInformation = 0x4A,
    FileCaseSensitiveInformationForceAccessCheck = 0x4B,
    FileMaximumInformation = 0x4C,
};

/* 56 */
enum _DIRECTORY_NOTIFY_INFORMATION_CLASS : __int32
{
    DirectoryNotifyInformation = 0x1,
    DirectoryNotifyExtendedInformation = 0x2,
};

/* 57 */
enum _FSINFOCLASS : __int32
{
    FileFsVolumeInformation = 0x1,
    FileFsLabelInformation = 0x2,
    FileFsSizeInformation = 0x3,
    FileFsDeviceInformation = 0x4,
    FileFsAttributeInformation = 0x5,
    FileFsControlInformation = 0x6,
    FileFsFullSizeInformation = 0x7,
    FileFsObjectIdInformation = 0x8,
    FileFsDriverPathInformation = 0x9,
    FileFsVolumeFlagsInformation = 0xA,
    FileFsSectorSizeInformation = 0xB,
    FileFsDataCopyInformation = 0xC,
    FileFsMetadataSizeInformation = 0xD,
    FileFsFullSizeInformationEx = 0xE,
    FileFsMaximumInformation = 0xF,
};

/* 58 */
enum _DEVICE_RELATION_TYPE : __int32
{
    BusRelations = 0x0,
    EjectionRelations = 0x1,
    PowerRelations = 0x2,
    RemovalRelations = 0x3,
    TargetDeviceRelation = 0x4,
    SingleBusRelations = 0x5,
    TransportRelations = 0x6,
};

/* 59 */
enum BUS_QUERY_ID_TYPE : __int32
{
    BusQueryDeviceID = 0x0,
    BusQueryHardwareIDs = 0x1,
    BusQueryCompatibleIDs = 0x2,
    BusQueryInstanceID = 0x3,
    BusQueryDeviceSerialNumber = 0x4,
    BusQueryContainerID = 0x5,
};

/* 60 */
enum DEVICE_TEXT_TYPE : __int32
{
    DeviceTextDescription = 0x0,
    DeviceTextLocationInformation = 0x1,
};

/* 61 */
enum _DEVICE_USAGE_NOTIFICATION_TYPE : __int32
{
    DeviceUsageTypeUndefined = 0x0,
    DeviceUsageTypePaging = 0x1,
    DeviceUsageTypeHibernation = 0x2,
    DeviceUsageTypeDumpFile = 0x3,
    DeviceUsageTypeBoot = 0x4,
    DeviceUsageTypePostDisplay = 0x5,
    DeviceUsageTypeGuestAssigned = 0x6,
};

/* 62 */
enum _SYSTEM_POWER_STATE : __int32
{
    PowerSystemUnspecified = 0x0,
    PowerSystemWorking = 0x1,
    PowerSystemSleeping1 = 0x2,
    PowerSystemSleeping2 = 0x3,
    PowerSystemSleeping3 = 0x4,
    PowerSystemHibernate = 0x5,
    PowerSystemShutdown = 0x6,
    PowerSystemMaximum = 0x7,
};

/* 63 */
enum _POWER_STATE_TYPE : __int32
{
    SystemPowerState = 0x0,
    DevicePowerState = 0x1,
};

/* 64 */
enum POWER_ACTION : __int32
{
    PowerActionNone = 0x0,
    PowerActionReserved = 0x1,
    PowerActionSleep = 0x2,
    PowerActionHibernate = 0x3,
    PowerActionShutdown = 0x4,
    PowerActionShutdownReset = 0x5,
    PowerActionShutdownOff = 0x6,
    PowerActionWarmEject = 0x7,
    PowerActionDisplayOff = 0x8,
};

/* 65 */
enum _IO_PRIORITY_HINT : __int32
{
    IoPriorityVeryLow = 0x0,
    IoPriorityLow = 0x1,
    IoPriorityNormal = 0x2,
    IoPriorityHigh = 0x3,
    IoPriorityCritical = 0x4,
    MaxIoPriorityTypes = 0x5,
};

/* 66 */
enum _MEMORY_CACHING_TYPE : __int32
{
    MmNonCached = 0x0,
    MmCached = 0x1,
    MmWriteCombined = 0x2,
    MmHardwareCoherentCached = 0x3,
    MmNonCachedUnordered = 0x4,
    MmUSWCCached = 0x5,
    MmMaximumCacheType = 0x6,
    MmNotMapped = 0xFFFFFFFF,
};

/* 67 */
enum _MM_PAGE_ACCESS_TYPE : __int32
{
    MmPteAccessType = 0x0,
    MmCcReadAheadType = 0x1,
    MmPfnRepurposeType = 0x2,
    MmMaximumPageAccessType = 0x3,
};

/* 68 */
enum _PF_FILE_ACCESS_TYPE : __int32
{
    PfFileAccessTypeRead = 0x0,
    PfFileAccessTypeWrite = 0x1,
    PfFileAccessTypeMax = 0x2,
};

/* 69 */
enum _DEVICE_POWER_STATE : __int32
{
    PowerDeviceUnspecified = 0x0,
    PowerDeviceD0 = 0x1,
    PowerDeviceD1 = 0x2,
    PowerDeviceD2 = 0x3,
    PowerDeviceD3 = 0x4,
    PowerDeviceMaximum = 0x5,
};

/* 70 */
enum _DEVICE_WAKE_DEPTH : __int32
{
    DeviceWakeDepthNotWakeable = 0x0,
    DeviceWakeDepthD0 = 0x1,
    DeviceWakeDepthD1 = 0x2,
    DeviceWakeDepthD2 = 0x3,
    DeviceWakeDepthD3hot = 0x4,
    DeviceWakeDepthD3cold = 0x5,
    DeviceWakeDepthMaximum = 0x6,
};

/* 71 */
enum _WHEA_ERROR_SOURCE_TYPE : __int32
{
    WheaErrSrcTypeMCE = 0x0,
    WheaErrSrcTypeCMC = 0x1,
    WheaErrSrcTypeCPE = 0x2,
    WheaErrSrcTypeNMI = 0x3,
    WheaErrSrcTypePCIe = 0x4,
    WheaErrSrcTypeGeneric = 0x5,
    WheaErrSrcTypeINIT = 0x6,
    WheaErrSrcTypeBOOT = 0x7,
    WheaErrSrcTypeSCIGeneric = 0x8,
    WheaErrSrcTypeIPFMCA = 0x9,
    WheaErrSrcTypeIPFCMC = 0xA,
    WheaErrSrcTypeIPFCPE = 0xB,
    WheaErrSrcTypeGenericV2 = 0xC,
    WheaErrSrcTypeSCIGenericV2 = 0xD,
    WheaErrSrcTypeBMC = 0xE,
    WheaErrSrcTypePMEM = 0xF,
    WheaErrSrcTypeDeviceDriver = 0x10,
    WheaErrSrcTypeMax = 0x11,
};

/* 72 */
enum _WHEA_ERROR_SOURCE_STATE : __int32
{
    WheaErrSrcStateStopped = 0x1,
    WheaErrSrcStateStarted = 0x2,
    WheaErrSrcStateRemoved = 0x3,
    WheaErrSrcStateRemovePending = 0x4,
};

/* 73 */
enum _WHEA_EVENT_LOG_ENTRY_TYPE : __int32
{
    WheaEventLogEntryTypeInformational = 0x0,
    WheaEventLogEntryTypeWarning = 0x1,
    WheaEventLogEntryTypeError = 0x2,
};

/* 74 */
enum _WHEA_EVENT_LOG_ENTRY_ID : __int32
{
    WheaEventLogEntryIdCmcPollingTimeout = 0x80000001,
    WheaEventLogEntryIdWheaInit = 0x80000002,
    WheaEventLogEntryIdCmcSwitchToPolling = 0x80000003,
    WheaEventLogEntryIdDroppedCorrectedError = 0x80000004,
    WheaEventLogEntryIdStartedReportHwError = 0x80000005,
    WheaEventLogEntryIdPFAMemoryOfflined = 0x80000006,
    WheaEventLogEntryIdPFAMemoryRemoveMonitor = 0x80000007,
    WheaEventLogEntryIdPFAMemoryPolicy = 0x80000008,
    WheaEventLogEntryIdPshedInjectError = 0x80000009,
    WheaEventLogEntryIdOscCapabilities = 0x8000000A,
    WheaEventLogEntryIdPshedPluginRegister = 0x8000000B,
    WheaEventLogEntryIdAddRemoveErrorSource = 0x8000000C,
    WheaEventLogEntryIdWorkQueueItem = 0x8000000D,
    WheaEventLogEntryIdAttemptErrorRecovery = 0x8000000E,
    WheaEventLogEntryIdMcaFoundErrorInBank = 0x8000000F,
    WheaEventLogEntryIdMcaStuckErrorCheck = 0x80000010,
    WheaEventLogEntryIdMcaErrorCleared = 0x80000011,
    WheaEventLogEntryIdClearedPoison = 0x80000012,
    WheaEventLogEntryIdProcessEINJ = 0x80000013,
    WheaEventLogEntryIdProcessHEST = 0x80000014,
    WheaEventLogEntryIdCreateGenericRecord = 0x80000015,
    WheaEventLogEntryIdErrorRecord = 0x80000016,
    WheaEventLogEntryIdErrorRecordLimit = 0x80000017,
    WheaEventLogEntryIdErrSrcArrayInvalid = 0x80000019,
    WheaEventLogEntryIdAcpiTimeOut = 0x8000001A,
    WheaEventLogCmciRestart = 0x8000001B,
    WheaEventLogCmciFinalRestart = 0x8000001C,
    WheaEventLogEntryEtwOverFlow = 0x8000001D,
    WheaEventLogAzccRootBusSearchErr = 0x8000001E,
    WheaEventLogAzccRootBusList = 0x8000001F,
    WheaEventLogEntryIdErrSrcInvalid = 0x80000020,
    WheaEventLogEntryIdGenericErrMemMap = 0x80000021,
    WheaEventLogEntryIdPshedCallbackCollision = 0x80000022,
    WheaEventLogEntryIdSELBugCheckProgress = 0x80000023,
    WheaEventLogEntryIdPshedPluginLoad = 0x80000024,
    WheaEventLogEntryIdPshedPluginUnload = 0x80000025,
    WheaEventLogEntryIdPshedPluginSupported = 0x80000026,
    WheaEventLogEntryIdDeviceDriver = 0x80000027,
    WheaEventLogEntryIdCmciImplPresent = 0x80000028,
    WheaEventLogEntryIdCmciInitError = 0x80000029,
    WheaEventLogEntryIdSELBugCheckRecovery = 0x8000002A,
    WheaEventLogEntryIdDrvErrSrcInvalid = 0x8000002B,
    WheaEventLogEntryIdDrvHandleBusy = 0x8000002C,
    WheaEventLogEntryIdWheaHeartbeat = 0x8000002D,
    WheaEventLogAzccRootBusPoisonSet = 0x8000002E,
    WheaEventLogEntryIdSELBugCheckInfo = 0x8000002F,
    WheaEventLogEntryIdErrDimmInfoMismatch = 0x80000030,
    WheaEventLogEntryIdeDpcEnabled = 0x80000031,
};

/* 75 */
enum _WHEA_ERROR_TYPE : __int32
{
    WheaErrTypeProcessor = 0x0,
    WheaErrTypeMemory = 0x1,
    WheaErrTypePCIExpress = 0x2,
    WheaErrTypeNMI = 0x3,
    WheaErrTypePCIXBus = 0x4,
    WheaErrTypePCIXDevice = 0x5,
    WheaErrTypeGeneric = 0x6,
    WheaErrTypePmem = 0x7,
};

/* 76 */
enum _WHEA_ERROR_SEVERITY : __int32
{
    WheaErrSevRecoverable = 0x0,
    WheaErrSevFatal = 0x1,
    WheaErrSevCorrected = 0x2,
    WheaErrSevInformational = 0x3,
};

/* 77 */
enum _WHEA_ERROR_PACKET_DATA_FORMAT : __int32
{
    WheaDataFormatIPFSalRecord = 0x0,
    WheaDataFormatXPFMCA = 0x1,
    WheaDataFormatMemory = 0x2,
    WheaDataFormatPCIExpress = 0x3,
    WheaDataFormatNMIPort = 0x4,
    WheaDataFormatPCIXBus = 0x5,
    WheaDataFormatPCIXDevice = 0x6,
    WheaDataFormatGeneric = 0x7,
    WheaDataFormatMax = 0x8,
};

/* 78 */
enum RTLP_CSPARSE_BITMAP_STATE : __int32
{
    CommitBitmapInvalid = 0x0,
    UserBitmapInvalid = 0x1,
    UserBitmapValid = 0x2,
};

/* 79 */
enum _RTLP_HP_ADDRESS_SPACE_TYPE : __int32
{
    HeapAddressUser = 0x0,
    HeapAddressKernel = 0x1,
    HeapAddressSession = 0x2,
    HeapAddressSecureKernel = 0x3,
    HeapAddressTypeMax = 0x4,
};

/* 80 */
enum _RTLP_HP_LOCK_TYPE : __int32
{
    HeapLockPaged = 0x0,
    HeapLockNonPaged = 0x1,
    HeapLockTypeMax = 0x2,
};

/* 81 */
enum _HEAP_FAILURE_TYPE : __int32
{
    heap_failure_internal = 0x0,
    heap_failure_unknown = 0x1,
    heap_failure_generic = 0x2,
    heap_failure_entry_corruption = 0x3,
    heap_failure_multiple_entries_corruption = 0x4,
    heap_failure_virtual_block_corruption = 0x5,
    heap_failure_buffer_overrun = 0x6,
    heap_failure_buffer_underrun = 0x7,
    heap_failure_block_not_busy = 0x8,
    heap_failure_invalid_argument = 0x9,
    heap_failure_invalid_allocation_type = 0xA,
    heap_failure_usage_after_free = 0xB,
    heap_failure_cross_heap_operation = 0xC,
    heap_failure_freelists_corruption = 0xD,
    heap_failure_listentry_corruption = 0xE,
    heap_failure_lfh_bitmap_mismatch = 0xF,
    heap_failure_segment_lfh_bitmap_corruption = 0x10,
    heap_failure_segment_lfh_double_free = 0x11,
    heap_failure_vs_subsegment_corruption = 0x12,
    heap_failure_null_heap = 0x13,
    heap_failure_allocation_limit = 0x14,
    heap_failure_commit_limit = 0x15,
    heap_failure_invalid_va_mgr_query = 0x16,
};

/* 82 */
enum _LDR_DLL_LOAD_REASON : __int32
{
    LoadReasonStaticDependency = 0x0,
    LoadReasonStaticForwarderDependency = 0x1,
    LoadReasonDynamicForwarderDependency = 0x2,
    LoadReasonDelayloadDependency = 0x3,
    LoadReasonDynamicLoad = 0x4,
    LoadReasonAsImageLoad = 0x5,
    LoadReasonAsDataLoad = 0x6,
    LoadReasonEnclavePrimary = 0x7,
    LoadReasonEnclaveDependency = 0x8,
    LoadReasonUnknown = 0xFFFFFFFF,
};

/* 83 */
enum _HEAP_LFH_LOCKMODE : __int32
{
    HeapLockNotHeld = 0x0,
    HeapLockShared = 0x1,
    HeapLockExclusive = 0x2,
};

/* 84 */
enum _HEAP_SEG_RANGE_TYPE : __int32
{
    HeapSegRangeUser = 0x0,
    HeapSegRangeInternal = 0x1,
    HeapSegRangeLFH = 0x2,
    HeapSegRangeVS = 0x3,
    HeapSegRangeTypeMax = 0x3,
};

/* 85 */
enum _RTLP_HP_ALLOCATOR : __int32
{
    RtlpHpSegmentSm = 0x0,
    RtlpHpSegmentLg = 0x1,
    RtlpHpSegmentTypes = 0x2,
    RtlpHpHugeAllocator = 0x2,
    RtlpHpAllocatorMax = 0x3,
};

/* 86 */
enum _IO_RATE_CONTROL_TYPE : __int32
{
    IoRateControlTypeCapMin = 0x0,
    IoRateControlTypeIopsCap = 0x0,
    IoRateControlTypeBandwidthCap = 0x1,
    IoRateControlTypeTimePercentCap = 0x2,
    IoRateControlTypeCapMax = 0x2,
    IoRateControlTypeReservationMin = 0x3,
    IoRateControlTypeIopsReservation = 0x3,
    IoRateControlTypeBandwidthReservation = 0x4,
    IoRateControlTypeTimePercentReservation = 0x5,
    IoRateControlTypeReservationMax = 0x5,
    IoRateControlTypeCriticalReservationMin = 0x6,
    IoRateControlTypeIopsCriticalReservation = 0x6,
    IoRateControlTypeBandwidthCriticalReservation = 0x7,
    IoRateControlTypeTimePercentCriticalReservation = 0x8,
    IoRateControlTypeCriticalReservationMax = 0x8,
    IoRateControlTypeSoftCapMin = 0x9,
    IoRateControlTypeIopsSoftCap = 0x9,
    IoRateControlTypeBandwidthSoftCap = 0xA,
    IoRateControlTypeTimePercentSoftCap = 0xB,
    IoRateControlTypeSoftCapMax = 0xB,
    IoRateControlTypeLimitExcessNotifyMin = 0xC,
    IoRateControlTypeIopsLimitExcessNotify = 0xC,
    IoRateControlTypeBandwidthLimitExcessNotify = 0xD,
    IoRateControlTypeTimePercentLimitExcessNotify = 0xE,
    IoRateControlTypeLimitExcessNotifyMax = 0xE,
    IoRateControlTypeMax = 0xF,
};

/* 87 */
enum _KINTERRUPT_POLARITY : __int32
{
    InterruptPolarityUnknown = 0x0,
    InterruptActiveHigh = 0x1,
    InterruptRisingEdge = 0x1,
    InterruptActiveLow = 0x2,
    InterruptFallingEdge = 0x2,
    InterruptActiveBoth = 0x3,
    InterruptActiveBothTriggerLow = 0x3,
    InterruptActiveBothTriggerHigh = 0x4,
};

/* 88 */
enum _JOBOBJECTINFOCLASS : __int32
{
    JobObjectBasicAccountingInformation = 0x1,
    JobObjectBasicLimitInformation = 0x2,
    JobObjectBasicProcessIdList = 0x3,
    JobObjectBasicUIRestrictions = 0x4,
    JobObjectSecurityLimitInformation = 0x5,
    JobObjectEndOfJobTimeInformation = 0x6,
    JobObjectAssociateCompletionPortInformation = 0x7,
    JobObjectBasicAndIoAccountingInformation = 0x8,
    JobObjectExtendedLimitInformation = 0x9,
    JobObjectJobSetInformation = 0xA,
    JobObjectGroupInformation = 0xB,
    JobObjectNotificationLimitInformation = 0xC,
    JobObjectLimitViolationInformation = 0xD,
    JobObjectGroupInformationEx = 0xE,
    JobObjectCpuRateControlInformation = 0xF,
    JobObjectCompletionFilter = 0x10,
    JobObjectCompletionCounter = 0x11,
    JobObjectFreezeInformation = 0x12,
    JobObjectExtendedAccountingInformation = 0x13,
    JobObjectWakeInformation = 0x14,
    JobObjectBackgroundInformation = 0x15,
    JobObjectSchedulingRankBiasInformation = 0x16,
    JobObjectTimerVirtualizationInformation = 0x17,
    JobObjectCycleTimeNotification = 0x18,
    JobObjectClearEvent = 0x19,
    JobObjectInterferenceInformation = 0x1A,
    JobObjectClearPeakJobMemoryUsed = 0x1B,
    JobObjectMemoryUsageInformation = 0x1C,
    JobObjectSharedCommit = 0x1D,
    JobObjectContainerId = 0x1E,
    JobObjectIoRateControlInformation = 0x1F,
    JobObjectSiloRootDirectory = 0x25,
    JobObjectServerSiloBasicInformation = 0x26,
    JobObjectServerSiloUserSharedData = 0x27,
    JobObjectServerSiloInitialize = 0x28,
    JobObjectServerSiloRunningState = 0x29,
    JobObjectIoAttribution = 0x2A,
    JobObjectMemoryPartitionInformation = 0x2B,
    JobObjectContainerTelemetryId = 0x2C,
    JobObjectSiloSystemRoot = 0x2D,
    JobObjectEnergyTrackingState = 0x2E,
    JobObjectThreadImpersonationInformation = 0x2F,
    JobObjectReserved1Information = 0x12,
    JobObjectReserved2Information = 0x13,
    JobObjectReserved3Information = 0x14,
    JobObjectReserved4Information = 0x15,
    JobObjectReserved5Information = 0x16,
    JobObjectReserved6Information = 0x17,
    JobObjectReserved7Information = 0x18,
    JobObjectReserved8Information = 0x19,
    JobObjectReserved9Information = 0x1A,
    JobObjectReserved10Information = 0x1B,
    JobObjectReserved11Information = 0x1C,
    JobObjectReserved12Information = 0x1D,
    JobObjectReserved13Information = 0x1E,
    JobObjectReserved14Information = 0x1F,
    JobObjectNetRateControlInformation = 0x20,
    JobObjectNotificationLimitInformation2 = 0x21,
    JobObjectLimitViolationInformation2 = 0x22,
    JobObjectCreateSilo = 0x23,
    JobObjectSiloBasicInformation = 0x24,
    JobObjectReserved15Information = 0x25,
    JobObjectReserved16Information = 0x26,
    JobObjectReserved17Information = 0x27,
    JobObjectReserved18Information = 0x28,
    JobObjectReserved19Information = 0x29,
    JobObjectReserved20Information = 0x2A,
    JobObjectReserved21Information = 0x2B,
    JobObjectReserved22Information = 0x2C,
    JobObjectReserved23Information = 0x2D,
    JobObjectReserved24Information = 0x2E,
    JobObjectReserved25Information = 0x2F,
    MaxJobObjectInfoClass = 0x30,
};

/* 89 */
enum _PROCESS_SECTION_TYPE : __int32
{
    ProcessSectionData = 0x0,
    ProcessSectionImage = 0x1,
    ProcessSectionImageNx = 0x2,
    ProcessSectionPagefileBacked = 0x3,
    ProcessSectionMax = 0x4,
};

/* 90 */
enum _RTLP_HP_MEMORY_TYPE : __int32
{
    HeapMemoryPaged = 0x0,
    HeapMemoryNonPaged = 0x1,
    HeapMemoryLargePage = 0x2,
    HeapMemoryHugePage = 0x3,
    HeapMemoryTypeMax = 0x4,
};

/* 91 */
enum _KWAIT_BLOCK_STATE : __int32
{
    WaitBlockBypassStart = 0x0,
    WaitBlockBypassComplete = 0x1,
    WaitBlockSuspendBypassStart = 0x2,
    WaitBlockSuspendBypassComplete = 0x3,
    WaitBlockActive = 0x4,
    WaitBlockInactive = 0x5,
    WaitBlockSuspended = 0x6,
    WaitBlockAllStates = 0x7,
};

/* 92 */
enum _RTL_FEATURE_CONFIGURATION_PRIORITY : __int32
{
    FeatureConfigurationPriorityImageDefault = 0x0,
    FeatureConfigurationPriorityEKB = 0x1,
    FeatureConfigurationPrioritySafeguard = 0x2,
    FeatureConfigurationPriorityPersistent = 0x2,
    FeatureConfigurationPriorityReserved3 = 0x3,
    FeatureConfigurationPriorityService = 0x4,
    FeatureConfigurationPriorityReserved5 = 0x5,
    FeatureConfigurationPriorityDynamic = 0x6,
    FeatureConfigurationPriorityReserved7 = 0x7,
    FeatureConfigurationPriorityUser = 0x8,
    FeatureConfigurationPrioritySecurity = 0x9,
    FeatureConfigurationPriorityUserPolicy = 0xA,
    FeatureConfigurationPriorityReserved11 = 0xB,
    FeatureConfigurationPriorityTest = 0xC,
    FeatureConfigurationPriorityReserved13 = 0xD,
    FeatureConfigurationPriorityReserved14 = 0xE,
    FeatureConfigurationPriorityImageOverride = 0xF,
    FeatureConfigurationPriorityMax = 0xF,
};

/* 93 */
enum _KHETERO_CPU_POLICY : __int32
{
    KHeteroCpuPolicyAll = 0x0,
    KHeteroCpuPolicyLarge = 0x1,
    KHeteroCpuPolicyLargeOrIdle = 0x2,
    KHeteroCpuPolicySmall = 0x3,
    KHeteroCpuPolicySmallOrIdle = 0x4,
    KHeteroCpuPolicyDynamic = 0x5,
    KHeteroCpuPolicyStaticMax = 0x5,
    KHeteroCpuPolicyBiasedSmall = 0x6,
    KHeteroCpuPolicyBiasedLarge = 0x7,
    KHeteroCpuPolicyDefault = 0x8,
    KHeteroCpuPolicyMax = 0x9,
};

/* 94 */
enum JOB_OBJECT_IO_RATE_CONTROL_FLAGS : __int32
{
    JOB_OBJECT_IO_RATE_CONTROL_ENABLE = 0x1,
    JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME = 0x2,
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL = 0x4,
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP = 0x8,
    JOB_OBJECT_IO_RATE_CONTROL_VALID_FLAGS = 0xF,
};

/* 95 */
enum _LDR_DDAG_STATE : __int32
{
    LdrModulesMerged = 0xFFFFFFFB,
    LdrModulesInitError = 0xFFFFFFFC,
    LdrModulesSnapError = 0xFFFFFFFD,
    LdrModulesUnloaded = 0xFFFFFFFE,
    LdrModulesUnloading = 0xFFFFFFFF,
    LdrModulesPlaceHolder = 0x0,
    LdrModulesMapping = 0x1,
    LdrModulesMapped = 0x2,
    LdrModulesWaitingForDependencies = 0x3,
    LdrModulesSnapping = 0x4,
    LdrModulesSnapped = 0x5,
    LdrModulesCondensed = 0x6,
    LdrModulesReadyToInit = 0x7,
    LdrModulesInitializing = 0x8,
    LdrModulesReadyToRun = 0x9,
};

/* 96 */
enum _KOBJECTS : __int32
{
    EventNotificationObject = 0x0,
    EventSynchronizationObject = 0x1,
    MutantObject = 0x2,
    ProcessObject = 0x3,
    QueueObject = 0x4,
    SemaphoreObject = 0x5,
    ThreadObject = 0x6,
    GateObject = 0x7,
    TimerNotificationObject = 0x8,
    TimerSynchronizationObject = 0x9,
    Spare2Object = 0xA,
    Spare3Object = 0xB,
    Spare4Object = 0xC,
    Spare5Object = 0xD,
    Spare6Object = 0xE,
    Spare7Object = 0xF,
    Spare8Object = 0x10,
    ProfileCallbackObject = 0x11,
    ApcObject = 0x12,
    DpcObject = 0x13,
    DeviceQueueObject = 0x14,
    PriQueueObject = 0x15,
    InterruptObject = 0x16,
    ProfileObject = 0x17,
    Timer2NotificationObject = 0x18,
    Timer2SynchronizationObject = 0x19,
    ThreadedDpcObject = 0x1A,
    MaximumKernelObject = 0x1B,
};

/* 97 */
enum _PS_STD_HANDLE_STATE : __int32
{
    PsNeverDuplicate = 0x0,
    PsRequestDuplicate = 0x1,
    PsAlwaysDuplicate = 0x2,
    PsMaxStdHandleStates = 0x3,
};

/* 98 */
enum _MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE : __int32
{
    MemoryNotContiguous = 0x0,
    MemoryAlignedAndContiguous = 0x1,
    MemoryNotResident = 0x2,
    MemoryNotEligibleToMakeContiguous = 0x3,
    MemoryContiguityStateMax = 0x4,
};

/* 99 */
enum _PS_WAKE_REASON : __int32
{
    PsWakeReasonUser = 0x0,
    PsWakeReasonExecutionRequired = 0x1,
    PsWakeReasonKernel = 0x2,
    PsWakeReasonInstrumentation = 0x3,
    PsWakeReasonPreserveProcess = 0x4,
    PsWakeReasonActivityReference = 0x5,
    PsWakeReasonWorkOnBehalf = 0x6,
    PsMaxWakeReasons = 0x7,
};

/* 100 */
enum _RTL_MEMORY_TYPE : __int32
{
    MemoryTypePaged = 0x0,
    MemoryTypeNonPaged = 0x1,
    MemoryTypeLargePage = 0x2,
    MemoryTypeHugePage = 0x3,
    MemoryTypeMax = 0x4,
};

/* 101 */
enum _KHETERO_RUNNING_TYPE : __int32
{
    KHeteroShortRunning = 0x0,
    KHeteroLongRunning = 0x1,
    KHeteroRunningTypeMax = 0x2,
};

/* 102 */
enum _HARDWARE_COUNTER_TYPE : __int32
{
    PMCCounter = 0x0,
    MaxHardwareCounterType = 0x1,
};

/* 103 */
enum _REG_NOTIFY_CLASS : __int32
{
    RegNtDeleteKey = 0x0,
    RegNtPreDeleteKey = 0x0,
    RegNtSetValueKey = 0x1,
    RegNtPreSetValueKey = 0x1,
    RegNtDeleteValueKey = 0x2,
    RegNtPreDeleteValueKey = 0x2,
    RegNtSetInformationKey = 0x3,
    RegNtPreSetInformationKey = 0x3,
    RegNtRenameKey = 0x4,
    RegNtPreRenameKey = 0x4,
    RegNtEnumerateKey = 0x5,
    RegNtPreEnumerateKey = 0x5,
    RegNtEnumerateValueKey = 0x6,
    RegNtPreEnumerateValueKey = 0x6,
    RegNtQueryKey = 0x7,
    RegNtPreQueryKey = 0x7,
    RegNtQueryValueKey = 0x8,
    RegNtPreQueryValueKey = 0x8,
    RegNtQueryMultipleValueKey = 0x9,
    RegNtPreQueryMultipleValueKey = 0x9,
    RegNtPreCreateKey = 0xA,
    RegNtPostCreateKey = 0xB,
    RegNtPreOpenKey = 0xC,
    RegNtPostOpenKey = 0xD,
    RegNtKeyHandleClose = 0xE,
    RegNtPreKeyHandleClose = 0xE,
    RegNtPostDeleteKey = 0xF,
    RegNtPostSetValueKey = 0x10,
    RegNtPostDeleteValueKey = 0x11,
    RegNtPostSetInformationKey = 0x12,
    RegNtPostRenameKey = 0x13,
    RegNtPostEnumerateKey = 0x14,
    RegNtPostEnumerateValueKey = 0x15,
    RegNtPostQueryKey = 0x16,
    RegNtPostQueryValueKey = 0x17,
    RegNtPostQueryMultipleValueKey = 0x18,
    RegNtPostKeyHandleClose = 0x19,
    RegNtPreCreateKeyEx = 0x1A,
    RegNtPostCreateKeyEx = 0x1B,
    RegNtPreOpenKeyEx = 0x1C,
    RegNtPostOpenKeyEx = 0x1D,
    RegNtPreFlushKey = 0x1E,
    RegNtPostFlushKey = 0x1F,
    RegNtPreLoadKey = 0x20,
    RegNtPostLoadKey = 0x21,
    RegNtPreUnLoadKey = 0x22,
    RegNtPostUnLoadKey = 0x23,
    RegNtPreQueryKeySecurity = 0x24,
    RegNtPostQueryKeySecurity = 0x25,
    RegNtPreSetKeySecurity = 0x26,
    RegNtPostSetKeySecurity = 0x27,
    RegNtCallbackObjectContextCleanup = 0x28,
    RegNtPreRestoreKey = 0x29,
    RegNtPostRestoreKey = 0x2A,
    RegNtPreSaveKey = 0x2B,
    RegNtPostSaveKey = 0x2C,
    RegNtPreReplaceKey = 0x2D,
    RegNtPostReplaceKey = 0x2E,
    RegNtPreQueryKeyName = 0x2F,
    RegNtPostQueryKeyName = 0x30,
    MaxRegNtNotifyClass = 0x31,
};

/* 104 */
enum _KTHREAD_TAG : __int32
{
    KThreadTagNone = 0x0,
    KThreadTagMediaBuffering = 0x1,
    KThreadTagDeadline = 0x2,
    KThreadTagMax = 0x3,
};

/* 105 */
enum _KE_WAKE_SOURCE_TYPE : __int32
{
    KeWakeSourceTypeSpuriousWake = 0x0,
    KeWakeSourceTypeSpuriousClock = 0x1,
    KeWakeSourceTypeSpuriousInterrupt = 0x2,
    KeWakeSourceTypeQueryFailure = 0x3,
    KeWakeSourceTypeAccountingFailure = 0x4,
    KeWakeSourceTypeStaticSourceMax = 0x4,
    KeWakeSourceTypeInterrupt = 0x5,
    KeWakeSourceTypeIRTimer = 0x6,
    KeWakeSourceTypeMax = 0x7,
};

/* 106 */
enum _PS_PROTECTED_TYPE : __int32
{
    PsProtectedTypeNone = 0x0,
    PsProtectedTypeProtectedLight = 0x1,
    PsProtectedTypeProtected = 0x2,
    PsProtectedTypeMax = 0x3,
};

/* 107 */
enum _PROCESS_VA_TYPE : __int32
{
    ProcessVAImage = 0x0,
    ProcessVASection = 0x1,
    ProcessVAPrivate = 0x2,
    ProcessVAMax = 0x3,
};

/* 108 */
enum _PS_RESOURCE_TYPE : __int32
{
    PsResourceNonPagedPool = 0x0,
    PsResourcePagedPool = 0x1,
    PsResourcePageFile = 0x2,
    PsResourceWorkingSet = 0x3,
    PsResourceMax = 0x4,
};

/* 109 */
enum _HEAP_SEGMGR_LARGE_PAGE_POLICY : __int32
{
    HeapSegMgrNoLargePages = 0x0,
    HeapSegMgrEnableLargePages = 0x1,
    HeapSegMgrNormalPolicy = 0x1,
    HeapSegMgrForceSmall = 0x2,
    HeapSegMgrForceLarge = 0x3,
    HeapSegMgrForceRandom = 0x4,
    HeapSegMgrLargePagePolicyMax = 0x5,
};

/* 110 */
enum _PERFINFO_KERNELMEMORY_USAGE_TYPE : __int32
{
    PerfInfoMemUsagePfnMetadata = 0x0,
    PerfInfoMemUsageMax = 0x1,
};

/* 111 */
enum _IO_ALLOCATION_ACTION : __int32
{
    KeepObject = 0x1,
    DeallocateObject = 0x2,
    DeallocateObjectKeepRegisters = 0x3,
};

/* 112 */
enum _PS_PROTECTED_SIGNER : __int32
{
    PsProtectedSignerNone = 0x0,
    PsProtectedSignerAuthenticode = 0x1,
    PsProtectedSignerCodeGen = 0x2,
    PsProtectedSignerAntimalware = 0x3,
    PsProtectedSignerLsa = 0x4,
    PsProtectedSignerWindows = 0x5,
    PsProtectedSignerWinTcb = 0x6,
    PsProtectedSignerWinSystem = 0x7,
    PsProtectedSignerApp = 0x8,
    PsProtectedSignerMax = 0x9,
};

/* 113 */
enum _WORKING_SET_TYPE : __int32
{
    WorkingSetTypeUser = 0x0,
    WorkingSetTypeSession = 0x1,
    WorkingSetTypeSystemTypes = 0x2,
    WorkingSetTypeSystemCache = 0x2,
    WorkingSetTypePagedPool = 0x3,
    WorkingSetTypeSystemViews = 0x4,
    WorkingSetTypePagableMaximum = 0x4,
    WorkingSetTypeSystemPtes = 0x5,
    WorkingSetTypeKernelStacks = 0x6,
    WorkingSetTypeNonPagedPool = 0x7,
    WorkingSetTypeMaximum = 0x8,
};

/* 114 */
enum DISPLAYCONFIG_SCANLINE_ORDERING : __int32
{
    DISPLAYCONFIG_SCANLINE_ORDERING_UNSPECIFIED = 0x0,
    DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE = 0x1,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED = 0x2,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED_UPPERFIELDFIRST = 0x2,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED_LOWERFIELDFIRST = 0x3,
    DISPLAYCONFIG_SCANLINE_ORDERING_FORCE_UINT32 = 0xFFFFFFFF,
};

/* 115 */
enum PS_CREATE_STATE : __int32
{
    PsCreateInitialState = 0x0,
    PsCreateFailOnFileOpen = 0x1,
    PsCreateFailOnSectionCreate = 0x2,
    PsCreateFailExeFormat = 0x3,
    PsCreateFailMachineMismatch = 0x4,
    PsCreateFailExeName = 0x5,
    PsCreateSuccess = 0x6,
    PsCreateMaximumStates = 0x7,
};

/* 116 */
enum _KTHREAD_PPM_POLICY : __int32
{
    ThreadPpmDefault = 0x0,
    ThreadPpmThrottle = 0x1,
    ThreadPpmSemiThrottle = 0x2,
    ThreadPpmNoThrottle = 0x3,
    MaxThreadPpmPolicy = 0x4,
};

/* 117 */
enum _VRF_RULE_CLASS_ID : __int32
{
    VrfSpecialPoolRuleClass = 0x0,
    VrfForceIrqlRuleClass = 0x1,
    VrfAllocationFailuresRuleClass = 0x2,
    VrfTrackingPoolAllocationsRuleClass = 0x3,
    VrfIORuleClass = 0x4,
    VrfDeadlockPreventionRuleClass = 0x5,
    VrfEnhancedIORuleClass = 0x6,
    VrfDMARuleClass = 0x7,
    VrfSecurityRuleClass = 0x8,
    VrfForcePendingIORequestRuleClass = 0x9,
    VrfIRPTrackingRuleClass = 0xA,
    VrfMiscellaneousRuleClass = 0xB,
    VrfMoreDebuggingRuleClass = 0xC,
    VrfMDLInvariantStackRuleClass = 0xD,
    VrfMDLInvariantDriverRuleClass = 0xE,
    VrfPowerDelayFuzzingRuleClass = 0xF,
    VrfPortMiniportRuleClass = 0x10,
    VrfStandardDDIRuleClass = 0x11,
    VrfAutoFailRuleClass = 0x12,
    VrfAdditionalDDIRuleClass = 0x13,
    VrfRuleClassBase = 0x14,
    VrfNdisWifiRuleClass = 0x15,
    VrfDriverLoggingRuleClass = 0x16,
    VrfSyncDelayFuzzingRuleClass = 0x17,
    VrfVMSwitchingRuleClass = 0x18,
    VrfCodeIntegrityRuleClass = 0x19,
    VrfBelow4GBAllocationRuleClass = 0x1A,
    VrfProcessorBranchTraceRuleClass = 0x1B,
    VrfAdvancedMMRuleClass = 0x1C,
    VrfExtendingXDVTimeLimit = 0x1D,
    VrfSystemBIOSRuleClass = 0x1E,
    VrfHardwareRuleClass = 0x1F,
    VrfStateSepRuleClass = 0x20,
    VrfWDFRuleClass = 0x21,
    VrfMoreIrqlRuleClass = 0x22,
    VrfXDVPlatformMode = 0x23,
    VrfStandalonePlatformMode = 0x24,
    VrfPlatformModeTest = 0x25,
    VrfInfoDisclosureIRPRule = 0x26,
    VrfLwSpecialPool = 0x27,
    VrfAVXCorruption = 0x28,
    VrfAccessModeMismatch = 0x29,
    ReservedForDVRF42 = 0x2A,
    ReservedForDVRF43 = 0x2B,
    ReservedForDVRF44 = 0x2C,
    ReservedForDVRF45 = 0x2D,
    ReservedForDVRF46 = 0x2E,
    ReservedForDVRF47 = 0x2F,
    ReservedForDVRF48 = 0x30,
    ReservedForDVRF49 = 0x31,
    ReservedForDVRF50 = 0x32,
    ReservedForDVRF51 = 0x33,
    ReservedForDVRF52 = 0x34,
    ReservedForDVRF53 = 0x35,
    ReservedForDVRF54 = 0x36,
    ReservedForDVRF55 = 0x37,
    ReservedForDVRF56 = 0x38,
    ReservedForDVRF57 = 0x39,
    ReservedForDVRF58 = 0x3A,
    ReservedForDVRF59 = 0x3B,
    ReservedForDVRF60 = 0x3C,
    ReservedForDVRF61 = 0x3D,
    ReservedForDVRF62 = 0x3E,
    ReservedForDVRF63 = 0x3F,
    VrfRuleClassSizeMax = 0x40,
};

/* 118 */
enum _KPROCESS_PPM_POLICY : __int32
{
    ProcessPpmDefault = 0x0,
    ProcessPpmThrottle = 0x1,
    ProcessPpmSemiThrottle = 0x2,
    ProcessPpmNoThrottle = 0x3,
    ProcessPpmWindowMinimized = 0x4,
    ProcessPpmWindowOccluded = 0x5,
    ProcessPpmWindowVisible = 0x6,
    ProcessPpmWindowInFocus = 0x7,
    MaxProcessPpmPolicy = 0x8,
};

/* 119 */
enum _MEMORY_CACHING_TYPE_ORIG : __int32
{
    MmFrameBufferCached = 0x2,
};

/* 120 */
enum _INTERLOCKED_RESULT : __int32
{
    ResultNegative = 0x1,
    ResultZero = 0x0,
    ResultPositive = 0x2,
};

/* 121 */
enum _SYSTEM_PROCESS_CLASSIFICATION : __int32
{
    SystemProcessClassificationNormal = 0x0,
    SystemProcessClassificationSystem = 0x1,
    SystemProcessClassificationSecureSystem = 0x2,
    SystemProcessClassificationMemCompression = 0x3,
    SystemProcessClassificationRegistry = 0x4,
    SystemProcessClassificationMaximum = 0x5,
};

/* 122 */
enum _WOW64_SHARED_INFORMATION : __int32
{
    SharedNtdll32LdrInitializeThunk = 0x0,
    SharedNtdll32KiUserExceptionDispatcher = 0x1,
    SharedNtdll32KiUserApcDispatcher = 0x2,
    SharedNtdll32KiUserCallbackDispatcher = 0x3,
    SharedNtdll32RtlUserThreadStart = 0x4,
    SharedNtdll32pQueryProcessDebugInformationRemote = 0x5,
    SharedNtdll32BaseAddress = 0x6,
    SharedNtdll32LdrSystemDllInitBlock = 0x7,
    SharedNtdll32RtlpFreezeTimeBias = 0x8,
    Wow64SharedPageEntriesCount = 0x9,
};

/* 123 */
enum _PROCESSOR_CACHE_TYPE : __int32
{
    CacheUnified = 0x0,
    CacheInstruction = 0x1,
    CacheData = 0x2,
    CacheTrace = 0x3,
};

/* 124 */
enum _KWAIT_STATE : __int32
{
    WaitInProgress = 0x0,
    WaitCommitted = 0x1,
    WaitAborted = 0x2,
    WaitSuspendInProgress = 0x3,
    WaitSuspended = 0x4,
    WaitResumeInProgress = 0x5,
    WaitResumeAborted = 0x6,
    WaitFirstSuspendState = 0x3,
    WaitLastSuspendState = 0x6,
    MaximumWaitState = 0x7,
};

/* 125 */
enum _USER_ACTIVITY_PRESENCE : __int32
{
    PowerUserPresent = 0x0,
    PowerUserNotPresent = 0x1,
    PowerUserInactive = 0x2,
    PowerUserMaximum = 0x3,
    PowerUserInvalid = 0x3,
};

/* 126 */
enum _INTERFACE_TYPE : __int32
{
    InterfaceTypeUndefined = 0xFFFFFFFF,
    Internal = 0x0,
    Isa = 0x1,
    Eisa = 0x2,
    MicroChannel = 0x3,
    TurboChannel = 0x4,
    PCIBus = 0x5,
    VMEBus = 0x6,
    NuBus = 0x7,
    PCMCIABus = 0x8,
    CBus = 0x9,
    MPIBus = 0xA,
    MPSABus = 0xB,
    ProcessorInternal = 0xC,
    InternalPowerBus = 0xD,
    PNPISABus = 0xE,
    PNPBus = 0xF,
    Vmcs = 0x10,
    ACPIBus = 0x11,
    MaximumInterfaceType = 0x12,
};

/* 127 */
enum _KPROCESS_STATE : __int32
{
    ProcessInMemory = 0x0,
    ProcessOutOfMemory = 0x1,
    ProcessInTransition = 0x2,
    ProcessOutTransition = 0x3,
    ProcessInSwap = 0x4,
    ProcessOutSwap = 0x5,
    ProcessRetryOutSwap = 0x6,
    ProcessAllSwapStates = 0x7,
};

/* 128 */
enum _INVPCID_TYPE : __int32
{
    InvpcidIndividualAddress = 0x0,
    InvpcidSingleContext = 0x1,
    InvpcidAllContextAndGlobals = 0x2,
    InvpcidAllContext = 0x3,
};

/* 129 */
enum _TRACE_INFORMATION_CLASS : __int32
{
    TraceIdClass = 0x0,
    TraceHandleClass = 0x1,
    TraceEnableFlagsClass = 0x2,
    TraceEnableLevelClass = 0x3,
    GlobalLoggerHandleClass = 0x4,
    EventLoggerHandleClass = 0x5,
    AllLoggerHandlesClass = 0x6,
    TraceHandleByNameClass = 0x7,
    LoggerEventsLostClass = 0x8,
    TraceSessionSettingsClass = 0x9,
    LoggerEventsLoggedClass = 0xA,
    DiskIoNotifyRoutinesClass = 0xB,
    TraceInformationClassReserved1 = 0xC,
    AllPossibleNotifyRoutinesClass = 0xC,
    FltIoNotifyRoutinesClass = 0xD,
    TraceInformationClassReserved2 = 0xE,
    WdfNotifyRoutinesClass = 0xF,
    MaxTraceInformationClass = 0x10,
};

/* 130 */
enum _EXCEPTION_DISPOSITION : __int32
{
    ExceptionContinueExecution = 0x0,
    ExceptionContinueSearch = 0x1,
    ExceptionNestedException = 0x2,
    ExceptionCollidedUnwind = 0x3,
};

/* 131 */
enum _SECURITY_IMPERSONATION_LEVEL : __int32
{
    SecurityAnonymous = 0x0,
    SecurityIdentification = 0x1,
    SecurityImpersonation = 0x2,
    SecurityDelegation = 0x3,
};

/* 132 */
enum _PERFINFO_MM_STAT : __int32
{
    PerfInfoMMStatNotUsed = 0x0,
    PerfInfoMMStatAggregatePageCombine = 0x1,
    PerfInfoMMStatIterationPageCombine = 0x2,
    PerfInfoMMStatMax = 0x3,
};

/* 133 */
enum LSA_FOREST_TRUST_RECORD_TYPE : __int32
{
    ForestTrustTopLevelName = 0x0,
    ForestTrustTopLevelNameEx = 0x1,
    ForestTrustDomainInfo = 0x2,
    ForestTrustBinaryInfo = 0x3,
    ForestTrustScannerInfo = 0x4,
    ForestTrustRecordTypeLast = 0x4,
};

/* 134 */
enum _PROC_HYPERVISOR_STATE : __int32
{
    ProcHypervisorNone = 0x0,
    ProcHypervisorPresent = 0x1,
    ProcHypervisorPower = 0x2,
    ProcHypervisorHvCounters = 0x3,
};

/* 135 */
enum _KHETERO_CPU_QOS : __int32
{
    KHeteroCpuQosDefault = 0x0,
    KHeteroCpuQosHigh = 0x0,
    KHeteroCpuQosMedium = 0x1,
    KHeteroCpuQosLow = 0x2,
    KHeteroCpuQosMultimedia = 0x3,
    KHeteroCpuQosDeadline = 0x4,
    KHeteroCpuQosDynamic = 0x5,
    KHeteroCpuQosMax = 0x5,
};

/* 136 */
enum _THREAD_WORKLOAD_CLASS : __int32
{
    ThreadWorkloadClassDefault = 0x0,
    ThreadWorkloadClassGraphics = 0x1,
    MaxThreadWorkloadClass = 0x2,
};

/* 137 */
enum _SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE : __int32
{
    SystemFeatureConfigurationSectionTypeBoot = 0x0,
    SystemFeatureConfigurationSectionTypeRuntime = 0x1,
    SystemFeatureConfigurationSectionTypeUsageTriggers = 0x2,
    SystemFeatureConfigurationSectionTypeCount = 0x3,
};

/* 138 */
enum _PS_ATTRIBUTE_NUM : __int32
{
    PsAttributeParentProcess = 0x0,
    PsAttributeDebugObject = 0x1,
    PsAttributeToken = 0x2,
    PsAttributeClientId = 0x3,
    PsAttributeTebAddress = 0x4,
    PsAttributeImageName = 0x5,
    PsAttributeImageInfo = 0x6,
    PsAttributeMemoryReserve = 0x7,
    PsAttributePriorityClass = 0x8,
    PsAttributeErrorMode = 0x9,
    PsAttributeStdHandleInfo = 0xA,
    PsAttributeHandleList = 0xB,
    PsAttributeGroupAffinity = 0xC,
    PsAttributePreferredNode = 0xD,
    PsAttributeIdealProcessor = 0xE,
    PsAttributeUmsThread = 0xF,
    PsAttributeMitigationOptions = 0x10,
    PsAttributeProtectionLevel = 0x11,
    PsAttributeSecureProcess = 0x12,
    PsAttributeJobList = 0x13,
    PsAttributeChildProcessPolicy = 0x14,
    PsAttributeAllApplicationPackagesPolicy = 0x15,
    PsAttributeWin32kFilter = 0x16,
    PsAttributeSafeOpenPromptOriginClaim = 0x17,
    PsAttributeBnoIsolation = 0x18,
    PsAttributeDesktopAppPolicy = 0x19,
    PsAttributeChpe = 0x1A,
    PsAttributeMitigationAuditOptions = 0x1B,
    PsAttributeMachineType = 0x1C,
    PsAttributeComponentFilter = 0x1D,
    PsAttributeMax = 0x1E,
};

/* 139 */
enum _SYSTEM_INFORMATION_CLASS : __int32
{
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xA,
    SystemModuleInformation = 0xB,
    SystemLocksInformation = 0xC,
    SystemStackTraceInformation = 0xD,
    SystemPagedPoolInformation = 0xE,
    SystemNonPagedPoolInformation = 0xF,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1A,
    SystemUnloadGdiDriverInformation = 0x1B,
    SystemTimeAdjustmentInformation = 0x1C,
    SystemSummaryMemoryInformation = 0x1D,
    SystemMirrorMemoryInformation = 0x1E,
    SystemPerformanceTraceInformation = 0x1F,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2A,
    SystemLegacyDriverInformation = 0x2B,
    SystemCurrentTimeZoneInformation = 0x2C,
    SystemLookasideInformation = 0x2D,
    SystemTimeSlipNotification = 0x2E,
    SystemSessionCreate = 0x2F,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3A,
    SystemComPlusPackage = 0x3B,
    SystemNumaAvailableMemory = 0x3C,
    SystemProcessorPowerInformation = 0x3D,
    SystemEmulationBasicInformation = 0x3E,
    SystemEmulationProcessorInformation = 0x3F,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4A,
    SystemRegisterFirmwareTableInformationHandler = 0x4B,
    SystemFirmwareTableInformation = 0x4C,
    SystemModuleInformationEx = 0x4D,
    SystemVerifierTriageInformation = 0x4E,
    SystemSuperfetchInformation = 0x4F,
    SystemMemoryListInformation = 0x50,
    SystemFileCacheInformationEx = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation = 0x56,
    SystemSpecialPoolInformation = 0x57,
    SystemProcessIdInformation = 0x58,
    SystemErrorPortInformation = 0x59,
    SystemBootEnvironmentInformation = 0x5A,
    SystemHypervisorInformation = 0x5B,
    SystemVerifierInformationEx = 0x5C,
    SystemTimeZoneInformation = 0x5D,
    SystemImageFileExecutionOptionsInformation = 0x5E,
    SystemCoverageInformation = 0x5F,
    SystemPrefetchPatchInformation = 0x60,
    SystemVerifierFaultsInformation = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString = 0x69,
    SystemVirtualAddressInformation = 0x6A,
    SystemLogicalProcessorAndGroupInformation = 0x6B,
    SystemProcessorCycleTimeInformation = 0x6C,
    SystemStoreInformation = 0x6D,
    SystemRegistryAppendString = 0x6E,
    SystemAitSamplingValue = 0x6F,
    SystemVhdBootInformation = 0x70,
    SystemCpuQuotaInformation = 0x71,
    SystemNativeBasicInformation = 0x72,
    SystemErrorPortTimeouts = 0x73,
    SystemLowPriorityIoInformation = 0x74,
    SystemBootEntropyInformation = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemPagedPoolInformationEx = 0x77,
    SystemSystemPtesInformationEx = 0x78,
    SystemNodeDistanceInformation = 0x79,
    SystemAcpiAuditInformation = 0x7A,
    SystemBasicPerformanceInformation = 0x7B,
    SystemQueryPerformanceCounterInformation = 0x7C,
    SystemSessionBigPoolInformation = 0x7D,
    SystemBootGraphicsInformation = 0x7E,
    SystemScrubPhysicalMemoryInformation = 0x7F,
    SystemBadPageInformation = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation = 0x84,
    SystemPlatformBinaryInformation = 0x85,
    SystemPolicyInformation = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation = 0x8A,
    SystemMemoryChannelInformation = 0x8B,
    SystemBootLogoInformation = 0x8C,
    SystemProcessorPerformanceInformationEx = 0x8D,
    SystemCriticalProcessErrorLogInformation = 0x8E,
    SystemSecureBootPolicyInformation = 0x8F,
    SystemPageFileInformationEx = 0x90,
    SystemSecureBootInformation = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation = 0x96,
    SystemSoftRebootInformation = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9A,
    SystemRegistryReconciliationInformation = 0x9B,
    SystemEdidInformation = 0x9C,
    SystemManufacturingInformation = 0x9D,
    SystemEnergyEstimationConfigInformation = 0x9E,
    SystemHypervisorDetailInformation = 0x9F,
    SystemProcessorCycleStatsInformation = 0xA0,
    SystemVmGenerationCountInformation = 0xA1,
    SystemTrustedPlatformModuleInformation = 0xA2,
    SystemKernelDebuggerFlags = 0xA3,
    SystemCodeIntegrityPolicyInformation = 0xA4,
    SystemIsolatedUserModeInformation = 0xA5,
    SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
    SystemSingleModuleInformation = 0xA7,
    SystemAllowedCpuSetsInformation = 0xA8,
    SystemVsmProtectionInformation = 0xA9,
    SystemInterruptCpuSetsInformation = 0xAA,
    SystemSecureBootPolicyFullInformation = 0xAB,
    SystemCodeIntegrityPolicyFullInformation = 0xAC,
    SystemAffinitizedInterruptProcessorInformation = 0xAD,
    SystemRootSiloInformation = 0xAE,
    SystemCpuSetInformation = 0xAF,
    SystemCpuSetTagInformation = 0xB0,
    SystemWin32WerStartCallout = 0xB1,
    SystemSecureKernelProfileInformation = 0xB2,
    SystemCodeIntegrityPlatformManifestInformation = 0xB3,
    SystemInterruptSteeringInformation = 0xB4,
    SystemSupportedProcessorArchitectures = 0xB5,
    SystemMemoryUsageInformation = 0xB6,
    SystemCodeIntegrityCertificateInformation = 0xB7,
    SystemPhysicalMemoryInformation = 0xB8,
    SystemControlFlowTransition = 0xB9,
    SystemKernelDebuggingAllowed = 0xBA,
    SystemActivityModerationExeState = 0xBB,
    SystemActivityModerationUserSettings = 0xBC,
    SystemCodeIntegrityPoliciesFullInformation = 0xBD,
    SystemCodeIntegrityUnlockInformation = 0xBE,
    SystemIntegrityQuotaInformation = 0xBF,
    SystemFlushInformation = 0xC0,
    SystemProcessorIdleMaskInformation = 0xC1,
    SystemSecureDumpEncryptionInformation = 0xC2,
    SystemWriteConstraintInformation = 0xC3,
    SystemKernelVaShadowInformation = 0xC4,
    SystemHypervisorSharedPageInformation = 0xC5,
    SystemFirmwareBootPerformanceInformation = 0xC6,
    SystemCodeIntegrityVerificationInformation = 0xC7,
    SystemFirmwarePartitionInformation = 0xC8,
    SystemSpeculationControlInformation = 0xC9,
    SystemDmaGuardPolicyInformation = 0xCA,
    SystemEnclaveLaunchControlInformation = 0xCB,
    SystemWorkloadAllowedCpuSetsInformation = 0xCC,
    SystemCodeIntegrityUnlockModeInformation = 0xCD,
    SystemLeapSecondInformation = 0xCE,
    SystemFlags2Information = 0xCF,
    SystemSecurityModelInformation = 0xD0,
    SystemCodeIntegritySyntheticCacheInformation = 0xD1,
    SystemFeatureConfigurationInformation = 0xD2,
    SystemFeatureConfigurationSectionInformation = 0xD3,
    SystemFeatureUsageSubscriptionInformation = 0xD4,
    SystemSecureSpeculationControlInformation = 0xD5,
    SystemSpacesBootInformation = 0xD6,
    SystemFwRamdiskInformation = 0xD7,
    SystemWheaIpmiHardwareInformation = 0xD8,
    SystemDifSetRuleClassInformation = 0xD9,
    SystemDifClearRuleClassInformation = 0xDA,
    SystemDifApplyPluginVerificationOnDriver = 0xDB,
    SystemDifRemovePluginVerificationOnDriver = 0xDC,
    SystemShadowStackInformation = 0xDD,
    SystemBuildVersionInformation = 0xDE,
    SystemPoolLimitInformation = 0xDF,
    SystemCodeIntegrityAddDynamicStore = 0xE0,
    SystemCodeIntegrityClearDynamicStores = 0xE1,
    SystemPoolZeroingInformation = 0xE3,
    MaxSystemInfoClass = 0xE4,
};

/* 140 */
enum _PROCESS_TERMINATE_REQUEST_REASON : __int32
{
    ProcessTerminateRequestReasonNone = 0x0,
    ProcessTerminateCommitFail = 0x1,
    ProcessTerminateWriteToExecuteMemory = 0x2,
    ProcessTerminateAttachedWriteToExecuteMemory = 0x3,
    ProcessTerminateRequestReasonMax = 0x4,
};

/* 141 */
enum _VRF_TRIAGE_CONTEXT : __int32
{
    VRF_TRIAGE_CONTEXT_NONE = 0x0,
    VRF_TRIAGE_CONTEXT_DEFAULT = 0x1,
    VRF_TRIAGE_CONTEXT_DEVELOPMENT = 0x1,
    VRF_TRIAGE_CONTEXT_CERTIFICATION = 0x2,
    VRF_TRIAGE_CONTEXT_FLIGHT_TARGETED = 0x3,
    VRF_TRIAGE_CONTEXT_FLIGHT_DIAGNOSTICS = 0x4,
    VRF_TRIAGE_CONTEXT_FLIGHT_MONITORING = 0x5,
    NUM_VRF_TRIAGE_CONTEXTS = 0x6,
};

/* 142 */
enum _EXQUEUEINDEX : __int32
{
    ExPoolUntrusted = 0x0,
    IoPoolUntrusted = 0x1,
    ExPoolMax = 0x8,
};

/* 143 */
enum ReplacesCorHdrNumericDefines : __int32
{
    COMIMAGE_FLAGS_ILONLY = 0x1,
    COMIMAGE_FLAGS_32BITREQUIRED = 0x2,
    COMIMAGE_FLAGS_IL_LIBRARY = 0x4,
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x8,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x10,
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x10000,
    COMIMAGE_FLAGS_32BITPREFERRED = 0x20000,
    COR_VERSION_MAJOR_V2 = 0x2,
    COR_VERSION_MAJOR = 0x2,
    COR_VERSION_MINOR = 0x5,
    COR_DELETED_NAME_LENGTH = 0x8,
    COR_VTABLEGAP_NAME_LENGTH = 0x8,
    NATIVE_TYPE_MAX_CB = 0x1,
    COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE = 0xFF,
    IMAGE_COR_MIH_METHODRVA = 0x1,
    IMAGE_COR_MIH_EHRVA = 0x2,
    IMAGE_COR_MIH_BASICBLOCK = 0x8,
    COR_VTABLE_32BIT = 0x1,
    COR_VTABLE_64BIT = 0x2,
    COR_VTABLE_FROM_UNMANAGED = 0x4,
    COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 0x8,
    COR_VTABLE_CALL_MOST_DERIVED = 0x10,
    IMAGE_COR_EATJ_THUNK_SIZE = 0x20,
    MAX_CLASS_NAME = 0x400,
    MAX_PACKAGE_NAME = 0x400,
};

/* 144 */
enum JOB_OBJECT_NET_RATE_CONTROL_FLAGS : __int32
{
    JOB_OBJECT_NET_RATE_CONTROL_ENABLE = 0x1,
    JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 0x2,
    JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG = 0x4,
    JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS = 0x7,
};

/* 145 */
enum PPM_IDLE_BUCKET_TIME_TYPE : __int32
{
    PpmIdleBucketTimeInQpc = 0x0,
    PpmIdleBucketTimeIn100ns = 0x1,
    PpmIdleBucketTimeMaximum = 0x2,
};

/* 146 */
enum _OB_OPEN_REASON : __int32
{
    ObCreateHandle = 0x0,
    ObOpenHandle = 0x1,
    ObDuplicateHandle = 0x2,
    ObInheritHandle = 0x3,
    ObMaxOpenReason = 0x4,
};

/* 147 */
enum _SECURITY_OPERATION_CODE : __int32
{
    SetSecurityDescriptor = 0x0,
    QuerySecurityDescriptor = 0x1,
    DeleteSecurityDescriptor = 0x2,
    AssignSecurityDescriptor = 0x3,
};

/* 148 */
enum _SERVERSILO_STATE : __int32
{
    SERVERSILO_INITING = 0x0,
    SERVERSILO_STARTED = 0x1,
    SERVERSILO_SHUTTING_DOWN = 0x2,
    SERVERSILO_TERMINATING = 0x3,
    SERVERSILO_TERMINATED = 0x4,
};

/* 149 */
enum _KCONTINUE_TYPE : __int32
{
    KCONTINUE_UNWIND = 0x0,
    KCONTINUE_RESUME = 0x1,
    KCONTINUE_LONGJUMP = 0x2,
    KCONTINUE_SET = 0x3,
    KCONTINUE_LAST = 0x4,
};

/* 150 */
enum _RTL_GENERIC_COMPARE_RESULTS : __int32
{
    GenericLessThan = 0x0,
    GenericGreaterThan = 0x1,
    GenericEqual = 0x2,
};

/* 151 */
enum MCA_EXCEPTION_TYPE : __int32
{
    HAL_MCE_RECORD = 0x0,
    HAL_MCA_RECORD = 0x1,
};

/* 152 */
enum _FUNCTION_TABLE_TYPE : __int32
{
    RF_SORTED = 0x0,
    RF_UNSORTED = 0x1,
    RF_CALLBACK = 0x2,
    RF_KERNEL_DYNAMIC = 0x3,
};

/* 153 */
enum _PROCESSOR_PRESENCE : __int32
{
    ProcessorPresenceNt = 0x0,
    ProcessorPresenceHv = 0x1,
    ProcessorPresenceHidden = 0x2,
};

/* 154 */
enum _MACHINE_CHECK_NESTING_LEVEL : __int32
{
    McheckNormal = 0x0,
    McheckNmi = 0x1,
    McheckNestingLevels = 0x2,
};

/* 155 */
enum _IRQ_PRIORITY : __int32
{
    IrqPriorityUndefined = 0x0,
    IrqPriorityLow = 0x1,
    IrqPriorityNormal = 0x2,
    IrqPriorityHigh = 0x3,
};

/* 156 */
enum _FS_FILTER_SECTION_SYNC_TYPE : __int32
{
    SyncTypeOther = 0x0,
    SyncTypeCreateSection = 0x1,
};

/* 157 */
struct LIST_ENTRY64
{
    unsigned __int64 Flink;
    unsigned __int64 Blink;
};

/* 158 */
struct LIST_ENTRY32
{
    unsigned int Flink;
    unsigned int Blink;
};

/* 159 */
struct _PS_MITIGATION_OPTIONS_MAP
{
    unsigned __int64 Map[3];
};

/* 160 */
struct _PS_MITIGATION_AUDIT_OPTIONS_MAP
{
    unsigned __int64 Map[3];
};

/* 161 */
volatile struct _KSYSTEM_TIME
{
    unsigned int LowPart;
    int High1Time;
    int High2Time;
};

/* 162 */
struct $FAF74743FBE1C8632047CFB668F7028A
{
    unsigned int LowPart;
    int HighPart;
};

/* 163 */
union _LARGE_INTEGER
{
    $FAF74743FBE1C8632047CFB668F7028A __s0;
    $FAF74743FBE1C8632047CFB668F7028A u;
    __int64 QuadPart;
};

/* 165 */
struct _XSTATE_FEATURE
{
    unsigned int Offset;
    unsigned int Size;
};

/* 166 */
struct $62654262369868C0312B20411168132E
{
    unsigned __int32 OptimizedSave : 1;
    unsigned __int32 CompactionEnabled : 1;
};

/* 167 */
union $47EFFA9D97A5D47BA61ABB3125BDF244
{
    unsigned int ControlFlags;
    $62654262369868C0312B20411168132E __s1;
};

/* 168 */
struct _XSTATE_CONFIGURATION
{
    unsigned __int64 EnabledFeatures;
    unsigned __int64 EnabledVolatileFeatures;
    unsigned int Size;
    $47EFFA9D97A5D47BA61ABB3125BDF244 ___u3;
    _XSTATE_FEATURE Features[64];
    unsigned __int64 EnabledSupervisorFeatures;
    unsigned __int64 AlignedFeatures;
    unsigned int AllFeatureSize;
    unsigned int AllFeatures[64];
    unsigned __int64 EnabledUserVisibleSupervisorFeatures;
};

/* 169 */
struct $3D940D5D03EF7F98CEE6737EDE752E57
{
    unsigned __int8 NXSupportPolicy : 2;
    unsigned __int8 SEHValidationPolicy : 2;
    unsigned __int8 CurDirDevicesSkippedForDlls : 2;
    unsigned __int8 Reserved : 2;
};

/* 170 */
union $FF4F1E40A1ECF948960A00F942B8A2EB
{
    unsigned __int8 MitigationPolicies;
    $3D940D5D03EF7F98CEE6737EDE752E57 __s1;
};

/* 171 */
struct $4BF4056B39611650D41923F164DAFA52
{
    unsigned __int32 DbgErrorPortPresent : 1;
    unsigned __int32 DbgElevationEnabled : 1;
    unsigned __int32 DbgVirtEnabled : 1;
    unsigned __int32 DbgInstallerDetectEnabled : 1;
    unsigned __int32 DbgLkgEnabled : 1;
    unsigned __int32 DbgDynProcessorEnabled : 1;
    unsigned __int32 DbgConsoleBrokerEnabled : 1;
    unsigned __int32 DbgSecureBootEnabled : 1;
    unsigned __int32 DbgMultiSessionSku : 1;
    unsigned __int32 DbgMultiUsersInSessionSku : 1;
    unsigned __int32 DbgStateSeparationEnabled : 1;
    unsigned __int32 SpareBits : 21;
};

/* 172 */
union $8BEB0B222A1F3A48F7A62CAD275BA982
{
    unsigned int SharedDataFlags;
    $4BF4056B39611650D41923F164DAFA52 __s1;
};

/* 173 */
#pragma pack(push, 1)
union $9525396884BCBFFCC1BF61AE9A4F7D4F
{
    volatile _KSYSTEM_TIME TickCount;
    volatile unsigned __int64 TickCountQuad;
    unsigned int ReservedTickCountOverlay[3];
};
#pragma pack(pop)

/* 174 */
struct $F91ACE6F13277DFC9425B9B8BBCB30F7
{
    volatile unsigned __int8 QpcBypassEnabled;
    unsigned __int8 QpcShift;
};

/* 175 */
union $D00C9A3CCDBF29EEA55CD2F19EE2E79F
{
    unsigned __int16 QpcData;
    $F91ACE6F13277DFC9425B9B8BBCB30F7 __s1;
};

/* 176 */
struct _KUSER_SHARED_DATA
{
    unsigned int TickCountLowDeprecated;
    unsigned int TickCountMultiplier;
    volatile _KSYSTEM_TIME InterruptTime;
    volatile _KSYSTEM_TIME SystemTime;
    volatile _KSYSTEM_TIME TimeZoneBias;
    unsigned __int16 ImageNumberLow;
    unsigned __int16 ImageNumberHigh;
    wchar_t NtSystemRoot[260];
    unsigned int MaxStackTraceDepth;
    unsigned int CryptoExponent;
    unsigned int TimeZoneId;
    unsigned int LargePageMinimum;
    unsigned int AitSamplingValue;
    unsigned int AppCompatFlag;
    unsigned __int64 RNGSeedVersion;
    unsigned int GlobalValidationRunlevel;
    volatile int TimeZoneBiasStamp;
    unsigned int NtBuildNumber;
    _NT_PRODUCT_TYPE NtProductType;
    unsigned __int8 ProductTypeIsValid;
    unsigned __int8 Reserved0[1];
    unsigned __int16 NativeProcessorArchitecture;
    unsigned int NtMajorVersion;
    unsigned int NtMinorVersion;
    unsigned __int8 ProcessorFeatures[64];
    unsigned int Reserved1;
    unsigned int Reserved3;
    volatile unsigned int TimeSlip;
    _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    unsigned int BootId;
    _LARGE_INTEGER SystemExpirationDate;
    unsigned int SuiteMask;
    unsigned __int8 KdDebuggerEnabled;
    $FF4F1E40A1ECF948960A00F942B8A2EB ___u33;
    unsigned __int16 CyclesPerYield;
    volatile unsigned int ActiveConsoleId;
    volatile unsigned int DismountCount;
    unsigned int ComPlusPackage;
    unsigned int LastSystemRITEventTickCount;
    unsigned int NumberOfPhysicalPages;
    unsigned __int8 SafeBootMode;
    unsigned __int8 VirtualizationFlags;
    unsigned __int8 Reserved12[2];
    $8BEB0B222A1F3A48F7A62CAD275BA982 ___u43;
    unsigned int DataFlagsPad[1];
    unsigned __int64 TestRetInstruction;
    __int64 QpcFrequency;
    unsigned int SystemCall;
    unsigned int Reserved2;
    unsigned __int64 SystemCallPad[2];
    $9525396884BCBFFCC1BF61AE9A4F7D4F ___u50;
    unsigned int TickCountPad[1];
    unsigned int Cookie;
    unsigned int CookiePad[1];
    __int64 ConsoleSessionForegroundProcessId;
    unsigned __int64 TimeUpdateLock;
    unsigned __int64 BaselineSystemTimeQpc;
    unsigned __int64 BaselineInterruptTimeQpc;
    unsigned __int64 QpcSystemTimeIncrement;
    unsigned __int64 QpcInterruptTimeIncrement;
    unsigned __int8 QpcSystemTimeIncrementShift;
    unsigned __int8 QpcInterruptTimeIncrementShift;
    unsigned __int16 UnparkedProcessorCount;
    unsigned int EnclaveFeatureMask[4];
    unsigned int TelemetryCoverageRound;
    unsigned __int16 UserModeGlobalLogger[16];
    unsigned int ImageFileExecutionOptions;
    unsigned int LangGenerationCount;
    unsigned __int64 Reserved4;
    volatile unsigned __int64 InterruptTimeBias;
    volatile unsigned __int64 QpcBias;
    unsigned int ActiveProcessorCount;
    volatile unsigned __int8 ActiveGroupCount;
    unsigned __int8 Reserved9;
    $D00C9A3CCDBF29EEA55CD2F19EE2E79F ___u74;
    _LARGE_INTEGER TimeZoneBiasEffectiveStart;
    _LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    _XSTATE_CONFIGURATION XState;
    _KSYSTEM_TIME FeatureConfigurationChangeStamp;
    unsigned int Spare;
};

/* 177 */
struct $B950AFB169DC87688B328897744C612F
{
    unsigned int LowPart;
    unsigned int HighPart;
};

/* 178 */
union _ULARGE_INTEGER
{
    $B950AFB169DC87688B328897744C612F __s0;
    $B950AFB169DC87688B328897744C612F u;
    unsigned __int64 QuadPart;
};

/* 181 */
struct $8C32E5D3ED1763EA38B94549972C5F20
{
    unsigned __int32 LongFunction : 1;
    unsigned __int32 Persistent : 1;
    unsigned __int32 Private : 30;
};

/* 182 */
union $18EC96EF2B8090D4B30ED63819DFD800
{
    unsigned int Flags;
    $8C32E5D3ED1763EA38B94549972C5F20 s;
};

/* 180 */
struct __declspec(align(8)) _TP_CALLBACK_ENVIRON_V3
{
    unsigned int Version;
    struct _TP_POOL* Pool;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void(__fastcall* CleanupGroupCancelCallback)(void*, void*);
    void* RaceDll;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void(__fastcall* FinalizationCallback)(struct _TP_CALLBACK_INSTANCE*, void*);
    $18EC96EF2B8090D4B30ED63819DFD800 u;
    _TP_CALLBACK_PRIORITY CallbackPriority;
    unsigned int Size;
};

/* 183 */
struct _EXCEPTION_REGISTRATION_RECORD
{
    _EXCEPTION_REGISTRATION_RECORD* Next;
    _EXCEPTION_DISPOSITION(__fastcall* Handler)(_EXCEPTION_RECORD*, void*, _CONTEXT*, void*);
};

/* 184 */
struct _EXCEPTION_RECORD
{
    int ExceptionCode;
    unsigned int ExceptionFlags;
    _EXCEPTION_RECORD* ExceptionRecord;
    void* ExceptionAddress;
    unsigned int NumberParameters;
    unsigned __int64 ExceptionInformation[15];
};

/* 186 */
union $7A727655067EA29DD1B3C3F7D79CBFD1
{
    void* FiberData;
    unsigned int Version;
};

/* 185 */
struct _NT_TIB
{
    _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    void* StackBase;
    void* StackLimit;
    void* SubSystemTib;
    $7A727655067EA29DD1B3C3F7D79CBFD1 ___u4;
    void* ArbitraryUserPointer;
    _NT_TIB* Self;
};

/* 187 */
struct _CLIENT_ID
{
    void* UniqueProcess;
    void* UniqueThread;
};

/* 188 */
struct _LIST_ENTRY
{
    _LIST_ENTRY* Flink;
    _LIST_ENTRY* Blink;
};

/* 189 */
struct _PEB_LDR_DATA
{
    unsigned int Length;
    unsigned __int8 Initialized;
    void* SsHandle;
    _LIST_ENTRY InLoadOrderModuleList;
    _LIST_ENTRY InMemoryOrderModuleList;
    _LIST_ENTRY InInitializationOrderModuleList;
    void* EntryInProgress;
    unsigned __int8 ShutdownInProgress;
    void* ShutdownThreadId;
};

/* 190 */
struct _UNICODE_STRING
{
    unsigned __int16 Length;
    unsigned __int16 MaximumLength;
    wchar_t* Buffer;
};

/* 191 */
struct _CURDIR
{
    _UNICODE_STRING DosPath;
    void* Handle;
};

/* 192 */
struct _STRING
{
    unsigned __int16 Length;
    unsigned __int16 MaximumLength;
    char* Buffer;
};

/* 193 */
struct _RTL_DRIVE_LETTER_CURDIR
{
    unsigned __int16 Flags;
    unsigned __int16 Length;
    unsigned int TimeStamp;
    _STRING DosPath;
};

/* 194 */
struct _RTL_USER_PROCESS_PARAMETERS
{
    unsigned int MaximumLength;
    unsigned int Length;
    unsigned int Flags;
    unsigned int DebugFlags;
    void* ConsoleHandle;
    unsigned int ConsoleFlags;
    void* StandardInput;
    void* StandardOutput;
    void* StandardError;
    _CURDIR CurrentDirectory;
    _UNICODE_STRING DllPath;
    _UNICODE_STRING ImagePathName;
    _UNICODE_STRING CommandLine;
    void* Environment;
    unsigned int StartingX;
    unsigned int StartingY;
    unsigned int CountX;
    unsigned int CountY;
    unsigned int CountCharsX;
    unsigned int CountCharsY;
    unsigned int FillAttribute;
    unsigned int WindowFlags;
    unsigned int ShowWindowFlags;
    _UNICODE_STRING WindowTitle;
    _UNICODE_STRING DesktopInfo;
    _UNICODE_STRING ShellInfo;
    _UNICODE_STRING RuntimeData;
    _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    unsigned __int64 EnvironmentSize;
    unsigned __int64 EnvironmentVersion;
    void* PackageDependencyData;
    unsigned int ProcessGroupId;
    unsigned int LoaderThreads;
    _UNICODE_STRING RedirectionDllName;
    _UNICODE_STRING HeapPartitionName;
    unsigned __int64* DefaultThreadpoolCpuSetMasks;
    unsigned int DefaultThreadpoolCpuSetMaskCount;
    unsigned int DefaultThreadpoolThreadMaximum;
};

/* 195 */
struct _RTL_CRITICAL_SECTION
{
    _RTL_CRITICAL_SECTION_DEBUG* DebugInfo;
    int LockCount;
    int RecursionCount;
    void* OwningThread;
    void* LockSemaphore;
    unsigned __int64 SpinCount;
};

/* 196 */
struct _RTL_CRITICAL_SECTION_DEBUG
{
    unsigned __int16 Type;
    unsigned __int16 CreatorBackTraceIndex;
    _RTL_CRITICAL_SECTION* CriticalSection;
    _LIST_ENTRY ProcessLocksList;
    unsigned int EntryCount;
    unsigned int ContentionCount;
    unsigned int Flags;
    unsigned __int16 CreatorBackTraceIndexHigh;
    unsigned __int16 SpareUSHORT;
};

/* 197 */
struct $37C35E5C8CCF236A60767E3040AC49D0
{
    unsigned __int64 Alignment;
    unsigned __int64 Region;
};

/* 199 */
struct $F9F9EB832D628D73E611400623F67F2B
{
    unsigned __int64 Depth : 16;
    unsigned __int64 Sequence : 48;
    unsigned __int64 Reserved : 4;
    unsigned __int64 NextEntry : 60;
};

/* 198 */
union _SLIST_HEADER
{
    $37C35E5C8CCF236A60767E3040AC49D0 __s0;
    $F9F9EB832D628D73E611400623F67F2B HeaderX64;
};

/* 200 */
struct _LEAP_SECOND_DATA
{
    unsigned __int8 Enabled;
    unsigned int Count;
    _LARGE_INTEGER Data[1];
};

/* 201 */
struct $26C534863E3B2F3363253F7AC0ACA204
{
    unsigned __int8 ImageUsesLargePages : 1;
    unsigned __int8 IsProtectedProcess : 1;
    unsigned __int8 IsImageDynamicallyRelocated : 1;
    unsigned __int8 SkipPatchingUser32Forwarders : 1;
    unsigned __int8 IsPackagedProcess : 1;
    unsigned __int8 IsAppContainer : 1;
    unsigned __int8 IsProtectedProcessLight : 1;
    unsigned __int8 IsLongPathAwareProcess : 1;
};

/* 202 */
union $51D2FE860E3D24CBB5D18A66F92CBB3C
{
    unsigned __int8 BitField;
    $26C534863E3B2F3363253F7AC0ACA204 __s1;
};

/* 203 */
struct $4FCFD4C7BDD47E55BF02313DBB2A825D
{
    unsigned __int32 ProcessInJob : 1;
    unsigned __int32 ProcessInitializing : 1;
    unsigned __int32 ProcessUsingVEH : 1;
    unsigned __int32 ProcessUsingVCH : 1;
    unsigned __int32 ProcessUsingFTH : 1;
    unsigned __int32 ProcessPreviouslyThrottled : 1;
    unsigned __int32 ProcessCurrentlyThrottled : 1;
    unsigned __int32 ProcessImagesHotPatched : 1;
    unsigned __int32 ReservedBits0 : 24;
};

/* 204 */
union $EBE42E673971247D518EE0952A24D91C
{
    unsigned int CrossProcessFlags;
    $4FCFD4C7BDD47E55BF02313DBB2A825D __s1;
};

/* 205 */
union $6F1CA9A36B21C857AE5467E073440320
{
    void* KernelCallbackTable;
    void* UserSharedInfoPtr;
};

/* 206 */
struct $B9EB1F4F9D70F693049DD1A0DA8FBDA7
{
    unsigned __int32 HeapTracingEnabled : 1;
    unsigned __int32 CritSecTracingEnabled : 1;
    unsigned __int32 LibLoaderTracingEnabled : 1;
    unsigned __int32 SpareTracingBits : 29;
};

/* 207 */
union $98BE1D9D1AB68706920100E8ED516A55
{
    unsigned int TracingFlags;
    $B9EB1F4F9D70F693049DD1A0DA8FBDA7 __s1;
};

/* 208 */
struct $9AED812D9AFCFBDB9DE58272C10BD98C
{
    unsigned __int32 SixtySecondEnabled : 1;
    unsigned __int32 Reserved : 31;
};

/* 209 */
union $4A45994A7603896D317AA01724198593
{
    unsigned int LeapSecondFlags;
    $9AED812D9AFCFBDB9DE58272C10BD98C __s1;
};

/* 210 */
struct _PEB
{
    unsigned __int8 InheritedAddressSpace;
    unsigned __int8 ReadImageFileExecOptions;
    unsigned __int8 BeingDebugged;
    $51D2FE860E3D24CBB5D18A66F92CBB3C ___u3;
    unsigned __int8 Padding0[4];
    void* Mutant;
    void* ImageBaseAddress;
    _PEB_LDR_DATA* Ldr;
    _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    void* SubSystemData;
    void* ProcessHeap;
    _RTL_CRITICAL_SECTION* FastPebLock;
    _SLIST_HEADER* volatile AtlThunkSListPtr;
    void* IFEOKey;
    $EBE42E673971247D518EE0952A24D91C ___u14;
    unsigned __int8 Padding1[4];
    $6F1CA9A36B21C857AE5467E073440320 ___u16;
    unsigned int SystemReserved;
    unsigned int AtlThunkSListPtr32;
    void* ApiSetMap;
    unsigned int TlsExpansionCounter;
    unsigned __int8 Padding2[4];
    void* TlsBitmap;
    unsigned int TlsBitmapBits[2];
    void* ReadOnlySharedMemoryBase;
    void* SharedData;
    void** ReadOnlyStaticServerData;
    void* AnsiCodePageData;
    void* OemCodePageData;
    void* UnicodeCaseTableData;
    unsigned int NumberOfProcessors;
    unsigned int NtGlobalFlag;
    _LARGE_INTEGER CriticalSectionTimeout;
    unsigned __int64 HeapSegmentReserve;
    unsigned __int64 HeapSegmentCommit;
    unsigned __int64 HeapDeCommitTotalFreeThreshold;
    unsigned __int64 HeapDeCommitFreeBlockThreshold;
    unsigned int NumberOfHeaps;
    unsigned int MaximumNumberOfHeaps;
    void** ProcessHeaps;
    void* GdiSharedHandleTable;
    void* ProcessStarterHelper;
    unsigned int GdiDCAttributeList;
    unsigned __int8 Padding3[4];
    _RTL_CRITICAL_SECTION* LoaderLock;
    unsigned int OSMajorVersion;
    unsigned int OSMinorVersion;
    unsigned __int16 OSBuildNumber;
    unsigned __int16 OSCSDVersion;
    unsigned int OSPlatformId;
    unsigned int ImageSubsystem;
    unsigned int ImageSubsystemMajorVersion;
    unsigned int ImageSubsystemMinorVersion;
    unsigned __int8 Padding4[4];
    unsigned __int64 ActiveProcessAffinityMask;
    unsigned int GdiHandleBuffer[60];
    void(__fastcall* PostProcessInitRoutine)();
    void* TlsExpansionBitmap;
    unsigned int TlsExpansionBitmapBits[32];
    unsigned int SessionId;
    unsigned __int8 Padding5[4];
    _ULARGE_INTEGER AppCompatFlags;
    _ULARGE_INTEGER AppCompatFlagsUser;
    void* pShimData;
    void* AppCompatInfo;
    _UNICODE_STRING CSDVersion;
    const struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    const struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    unsigned __int64 MinimumStackCommit;
    void* SparePointers[4];
    unsigned int SpareUlongs[5];
    void* WerRegistrationData;
    void* WerShipAssertPtr;
    void* pUnused;
    void* pImageHeaderHash;
    $98BE1D9D1AB68706920100E8ED516A55 ___u77;
    unsigned __int8 Padding6[4];
    unsigned __int64 CsrServerReadOnlySharedMemoryBase;
    unsigned __int64 TppWorkerpListLock;
    _LIST_ENTRY TppWorkerpList;
    void* WaitOnAddressHashTable[128];
    void* TelemetryCoverageHeader;
    unsigned int CloudFileFlags;
    unsigned int CloudFileDiagFlags;
    char PlaceholderCompatibilityMode;
    char PlaceholderCompatibilityModeReserved[7];
    _LEAP_SECOND_DATA* LeapSecondData;
    $4A45994A7603896D317AA01724198593 ___u89;
    unsigned int NtGlobalFlag2;
};

/* 211 */
struct __declspec(align(8)) _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    unsigned int Flags;
};

/* 212 */
struct __declspec(align(8)) _ACTIVATION_CONTEXT_STACK
{
    _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    _LIST_ENTRY FrameListCache;
    unsigned int Flags;
    unsigned int NextCookieSequenceNumber;
    unsigned int StackId;
};

/* 213 */
struct _GDI_TEB_BATCH
{
    unsigned __int32 Offset : 31;
    unsigned __int32 HasRenderingCommand : 1;
    unsigned __int64 HDC;
    unsigned int Buffer[310];
};

/* 214 */
struct _GUID
{
    unsigned int Data1;
    unsigned __int16 Data2;
    unsigned __int16 Data3;
    unsigned __int8 Data4[8];
};

/* 215 */
struct _PROCESSOR_NUMBER
{
    unsigned __int16 Group;
    unsigned __int8 Number;
    unsigned __int8 Reserved;
};

/* 216 */
struct _TEB_ACTIVE_FRAME
{
    unsigned int Flags;
    _TEB_ACTIVE_FRAME* Previous;
    const _TEB_ACTIVE_FRAME_CONTEXT* Context;
};

/* 217 */
const struct _TEB_ACTIVE_FRAME_CONTEXT
{
    unsigned int Flags;
    const char* FrameName;
};

/* 218 */
struct $6BCCBD9B7EADC6FB619C96ACD0967B24
{
    unsigned __int8 ReservedPad0;
    unsigned __int8 ReservedPad1;
    unsigned __int8 ReservedPad2;
    unsigned __int8 IdealProcessor;
};

/* 219 */
union $D9EBF87819411078EEC96304C6F97E47
{
    _PROCESSOR_NUMBER CurrentIdealProcessor;
    unsigned int IdealProcessorValue;
    $6BCCBD9B7EADC6FB619C96ACD0967B24 __s2;
};

/* 220 */
struct $88D35C6E749BA8930BA8A8A22D5F60D0
{
    unsigned __int16 SpareCrossTebBits : 16;
};

/* 221 */
union $8ABCD40CDBD167328241B217BDB144A7
{
    volatile unsigned __int16 CrossTebFlags;
    $88D35C6E749BA8930BA8A8A22D5F60D0 __s1;
};

/* 222 */
struct $67FCF779A2D496C4674D201A175A29C8
{
    unsigned __int16 SafeThunkCall : 1;
    unsigned __int16 InDebugPrint : 1;
    unsigned __int16 HasFiberData : 1;
    unsigned __int16 SkipThreadAttach : 1;
    unsigned __int16 WerInShipAssertCode : 1;
    unsigned __int16 RanProcessInit : 1;
    unsigned __int16 ClonedThread : 1;
    unsigned __int16 SuppressDebugMsg : 1;
    unsigned __int16 DisableUserStackWalk : 1;
    unsigned __int16 RtlExceptionAttached : 1;
    unsigned __int16 InitialThread : 1;
    unsigned __int16 SessionAware : 1;
    unsigned __int16 LoadOwner : 1;
    unsigned __int16 LoaderWorker : 1;
    unsigned __int16 SkipLoaderInit : 1;
    unsigned __int16 SpareSameTebBits : 1;
};

/* 223 */
union $3FCCE8508B160B5CC5A7BB6A6352584C
{
    unsigned __int16 SameTebFlags;
    $67FCF779A2D496C4674D201A175A29C8 __s1;
};

/* 224 */
struct _TEB
{
    _NT_TIB NtTib;
    void* EnvironmentPointer;
    _CLIENT_ID ClientId;
    void* ActiveRpcHandle;
    void* ThreadLocalStoragePointer;
    _PEB* ProcessEnvironmentBlock;
    unsigned int LastErrorValue;
    unsigned int CountOfOwnedCriticalSections;
    void* CsrClientThread;
    void* Win32ThreadInfo;
    unsigned int User32Reserved[26];
    unsigned int UserReserved[5];
    void* WOW32Reserved;
    unsigned int CurrentLocale;
    unsigned int FpSoftwareStatusRegister;
    void* ReservedForDebuggerInstrumentation[16];
    void* SystemReserved1[30];
    char PlaceholderCompatibilityMode;
    unsigned __int8 PlaceholderHydrationAlwaysExplicit;
    char PlaceholderReserved[10];
    unsigned int ProxiedProcessId;
    _ACTIVATION_CONTEXT_STACK _ActivationStack;
    unsigned __int8 WorkingOnBehalfTicket[8];
    int ExceptionCode;
    unsigned __int8 Padding0[4];
    _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    unsigned __int64 InstrumentationCallbackSp;
    unsigned __int64 InstrumentationCallbackPreviousPc;
    unsigned __int64 InstrumentationCallbackPreviousSp;
    unsigned int TxFsContext;
    unsigned __int8 InstrumentationCallbackDisabled;
    unsigned __int8 UnalignedLoadStoreExceptions;
    unsigned __int8 Padding1[2];
    _GDI_TEB_BATCH GdiTebBatch;
    _CLIENT_ID RealClientId;
    void* GdiCachedProcessHandle;
    unsigned int GdiClientPID;
    unsigned int GdiClientTID;
    void* GdiThreadLocalInfo;
    unsigned __int64 Win32ClientInfo[62];
    void* glDispatchTable[233];
    unsigned __int64 glReserved1[29];
    void* glReserved2;
    void* glSectionInfo;
    void* glSection;
    void* glTable;
    void* glCurrentRC;
    void* glContext;
    unsigned int LastStatusValue;
    unsigned __int8 Padding2[4];
    _UNICODE_STRING StaticUnicodeString;
    wchar_t StaticUnicodeBuffer[261];
    unsigned __int8 Padding3[6];
    void* DeallocationStack;
    void* TlsSlots[64];
    _LIST_ENTRY TlsLinks;
    void* Vdm;
    void* ReservedForNtRpc;
    void* DbgSsReserved[2];
    unsigned int HardErrorMode;
    unsigned __int8 Padding4[4];
    void* Instrumentation[11];
    _GUID ActivityId;
    void* SubProcessTag;
    void* PerflibData;
    void* EtwTraceData;
    void* WinSockData;
    unsigned int GdiBatchCount;
    $D9EBF87819411078EEC96304C6F97E47 ___u68;
    unsigned int GuaranteedStackBytes;
    unsigned __int8 Padding5[4];
    void* ReservedForPerf;
    void* ReservedForOle;
    unsigned int WaitingOnLoaderLock;
    unsigned __int8 Padding6[4];
    void* SavedPriorityState;
    unsigned __int64 ReservedForCodeCoverage;
    void* ThreadPoolData;
    void** TlsExpansionSlots;
    void* DeallocationBStore;
    void* BStoreLimit;
    unsigned int MuiGeneration;
    unsigned int IsImpersonating;
    void* NlsCache;
    void* pShimData;
    unsigned int HeapData;
    unsigned __int8 Padding7[4];
    void* CurrentTransactionHandle;
    _TEB_ACTIVE_FRAME* ActiveFrame;
    void* FlsData;
    void* PreferredLanguages;
    void* UserPrefLanguages;
    void* MergedPrefLanguages;
    unsigned int MuiImpersonation;
    $8ABCD40CDBD167328241B217BDB144A7 ___u94;
    $3FCCE8508B160B5CC5A7BB6A6352584C ___u95;
    void* TxnScopeEnterCallback;
    void* TxnScopeExitCallback;
    void* TxnScopeContext;
    unsigned int LockCount;
    int WowTebOffset;
    void* ResourceRetValue;
    void* ReservedForWdf;
    unsigned __int64 ReservedForCrt;
    _GUID EffectiveContainerId;
};

/* 225 */
struct _SINGLE_LIST_ENTRY
{
    _SINGLE_LIST_ENTRY* Next;
};

/* 226 */
struct _RTL_SPLAY_LINKS
{
    _RTL_SPLAY_LINKS* Parent;
    _RTL_SPLAY_LINKS* LeftChild;
    _RTL_SPLAY_LINKS* RightChild;
};

/* 227 */
struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT
{
    _LIST_ENTRY* ChainHead;
    _LIST_ENTRY* PrevLinkage;
    unsigned __int64 Signature;
};

/* 228 */
struct _RTL_DYNAMIC_HASH_TABLE_ENTRY
{
    _LIST_ENTRY Linkage;
    unsigned __int64 Signature;
};

/* 229 */
union $C19F8505DAD441D00B8145FA530CCFC0
{
    _RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry;
    _LIST_ENTRY* CurEntry;
};

/* 230 */
struct __declspec(align(8)) _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR
{
    $C19F8505DAD441D00B8145FA530CCFC0 ___u0;
    _LIST_ENTRY* ChainHead;
    unsigned int BucketIndex;
};

/* 231 */
struct _RTL_DYNAMIC_HASH_TABLE
{
    unsigned int Flags;
    unsigned int Shift;
    unsigned int TableSize;
    unsigned int Pivot;
    unsigned int DivisorMask;
    unsigned int NumEntries;
    unsigned int NonEmptyBuckets;
    unsigned int NumEnumerators;
    void* Directory;
};

/* 232 */
struct _RTL_BITMAP
{
    unsigned int SizeOfBitMap;
    unsigned int* Buffer;
};

/* 233 */
struct _LUID
{
    unsigned int LowPart;
    int HighPart;
};

/* 234 */
struct _CUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG
{
    unsigned int Size;
    const wchar_t* TriggerId;
};

/* 235 */
struct _IMAGE_FILE_HEADER
{
    unsigned __int16 Machine;
    unsigned __int16 NumberOfSections;
    unsigned int TimeDateStamp;
    unsigned int PointerToSymbolTable;
    unsigned int NumberOfSymbols;
    unsigned __int16 SizeOfOptionalHeader;
    unsigned __int16 Characteristics;
};

/* 236 */
struct _IMAGE_DATA_DIRECTORY
{
    unsigned int VirtualAddress;
    unsigned int Size;
};

/* 237 */
struct _IMAGE_OPTIONAL_HEADER64
{
    unsigned __int16 Magic;
    unsigned __int8 MajorLinkerVersion;
    unsigned __int8 MinorLinkerVersion;
    unsigned int SizeOfCode;
    unsigned int SizeOfInitializedData;
    unsigned int SizeOfUninitializedData;
    unsigned int AddressOfEntryPoint;
    unsigned int BaseOfCode;
    unsigned __int64 ImageBase;
    unsigned int SectionAlignment;
    unsigned int FileAlignment;
    unsigned __int16 MajorOperatingSystemVersion;
    unsigned __int16 MinorOperatingSystemVersion;
    unsigned __int16 MajorImageVersion;
    unsigned __int16 MinorImageVersion;
    unsigned __int16 MajorSubsystemVersion;
    unsigned __int16 MinorSubsystemVersion;
    unsigned int Win32VersionValue;
    unsigned int SizeOfImage;
    unsigned int SizeOfHeaders;
    unsigned int CheckSum;
    unsigned __int16 Subsystem;
    unsigned __int16 DllCharacteristics;
    unsigned __int64 SizeOfStackReserve;
    unsigned __int64 SizeOfStackCommit;
    unsigned __int64 SizeOfHeapReserve;
    unsigned __int64 SizeOfHeapCommit;
    unsigned int LoaderFlags;
    unsigned int NumberOfRvaAndSizes;
    _IMAGE_DATA_DIRECTORY DataDirectory[16];
};

/* 238 */
struct _IMAGE_NT_HEADERS64
{
    unsigned int Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

/* 239 */
struct _IMAGE_DOS_HEADER
{
    unsigned __int16 e_magic;
    unsigned __int16 e_cblp;
    unsigned __int16 e_cp;
    unsigned __int16 e_crlc;
    unsigned __int16 e_cparhdr;
    unsigned __int16 e_minalloc;
    unsigned __int16 e_maxalloc;
    unsigned __int16 e_ss;
    unsigned __int16 e_sp;
    unsigned __int16 e_csum;
    unsigned __int16 e_ip;
    unsigned __int16 e_cs;
    unsigned __int16 e_lfarlc;
    unsigned __int16 e_ovno;
    unsigned __int16 e_res[4];
    unsigned __int16 e_oemid;
    unsigned __int16 e_oeminfo;
    unsigned __int16 e_res2[10];
    int e_lfanew;
};

/* 241 */
struct $11CDBA684CEB7DB775078FD069C3AE71
{
    _RTL_BALANCED_NODE* Left;
    _RTL_BALANCED_NODE* Right;
};

/* 242 */
union $2FC0ACC38DFBCDBC97F9A16F2176FBF3
{
    _RTL_BALANCED_NODE* Children[2];
    $11CDBA684CEB7DB775078FD069C3AE71 __s1;
};

/* 243 */
struct $424C8BBEF8F6C852886B4C6E806B5DB0
{
    unsigned __int8 Red : 1;
};

/* 244 */
struct $D962A830273E2DCC2CD9A73DF8740260
{
    unsigned __int8 Balance : 2;
};

/* 245 */
union $FBE9DFC73C710CED4CE990514FEA3AEC
{
    $424C8BBEF8F6C852886B4C6E806B5DB0 __s0;
    $D962A830273E2DCC2CD9A73DF8740260 __s1;
    unsigned __int64 ParentValue;
};

/* 240 */
struct _RTL_BALANCED_NODE
{
    $2FC0ACC38DFBCDBC97F9A16F2176FBF3 ___u0;
    $FBE9DFC73C710CED4CE990514FEA3AEC ___u1;
};

/* 246 */
struct $7D93978C745EB1C2D28075BAF55422B4
{
    unsigned __int8 Encoded : 1;
};

/* 247 */
union $1F377A3CF2ED3C411307FC2748017117
{
    $7D93978C745EB1C2D28075BAF55422B4 __s0;
    _RTL_BALANCED_NODE* Min;
};

/* 248 */
struct _RTL_RB_TREE
{
    _RTL_BALANCED_NODE* Root;
    $1F377A3CF2ED3C411307FC2748017117 ___u1;
};

/* 249 */
struct _RTL_AVL_TREE
{
    _RTL_BALANCED_NODE* Root;
};

/* 251 */
struct $AE5011AAEC6C076BF662A410B5C9D999
{
    unsigned __int8 BaseMiddle;
    unsigned __int8 Flags1;
    unsigned __int8 Flags2;
    unsigned __int8 BaseHigh;
};

/* 250 */
struct $3AF973CD41D86FE815C4B32B4036FCC9
{
    unsigned __int16 LimitLow;
    unsigned __int16 BaseLow;
    $AE5011AAEC6C076BF662A410B5C9D999 Bytes;
    unsigned int BaseUpper;
    unsigned int MustBeZero;
};

/* 252 */
struct $DE019BF23F645DE18A8E2A817E597FE0
{
    __int64 DataLow;
    __int64 DataHigh;
};

/* 254 */
struct $C844E967038F1AF417EC2DF28AA016C9
{
    unsigned __int32 BaseMiddle : 8;
    unsigned __int32 Type : 5;
    unsigned __int32 Dpl : 2;
    unsigned __int32 Present : 1;
    unsigned __int32 LimitHigh : 4;
    unsigned __int32 System : 1;
    unsigned __int32 LongMode : 1;
    unsigned __int32 DefaultBig : 1;
    unsigned __int32 Granularity : 1;
    unsigned __int32 BaseHigh : 8;
};

/* 253 */
struct $5543AE040A0C011A568F8C20964DE0A6
{
    _BYTE gap0[4];
    $C844E967038F1AF417EC2DF28AA016C9 Bits;
};

/* 255 */
union _KGDTENTRY64
{
    $3AF973CD41D86FE815C4B32B4036FCC9 __s0;
    $DE019BF23F645DE18A8E2A817E597FE0 __s1;
    $5543AE040A0C011A568F8C20964DE0A6 __s2;
};

/* 256 */
struct _KTSS64
{
    unsigned int Reserved0;
    __unaligned __declspec(align(1)) unsigned __int64 Rsp0;
    __unaligned __declspec(align(1)) unsigned __int64 Rsp1;
    __unaligned __declspec(align(1)) unsigned __int64 Rsp2;
    __unaligned __declspec(align(1)) unsigned __int64 Ist[8];
    __unaligned __declspec(align(1)) unsigned __int64 Reserved1;
    unsigned __int16 Reserved2;
    unsigned __int16 IoMapBase;
};

/* 502 */
struct $3DFF1F384874590E4001BBFD09FD0991
{
    _KGDTENTRY64* GdtBase;
    _KTSS64* TssBase;
    unsigned __int64 UserRsp;
    _KPCR* Self;
    _KPRCB* CurrentPrcb;
    _KSPIN_LOCK_QUEUE* LockArray;
    void* Used_Self;
};

/* 503 */
union $6D2BD277AAF6D9FAEE9DE564884AEDF4
{
    _NT_TIB NtTib;
    $3DFF1F384874590E4001BBFD09FD0991 __s1;
};

/* 484 */
struct $77895C0986AC25977C4D7841AB2A3C85
{
    unsigned __int8 PendingTick : 1;
    unsigned __int8 PendingBackupTick : 1;
};

/* 485 */
union $ED34874246E5ECE3CAF1B6B6E76DEE42
{
    unsigned __int8 PendingTickFlags;
    $77895C0986AC25977C4D7841AB2A3C85 __s1;
};

/* 486 */
struct $765B7FFCC4FB01A5AB0EE4EE9D978908
{
    unsigned __int8 CpuStepping;
    unsigned __int8 CpuModel;
};

/* 487 */
union $25350A9DA83C31B1294F7FCF870CEEB1
{
    unsigned __int16 CpuStep;
    $765B7FFCC4FB01A5AB0EE4EE9D978908 __s1;
};

/* 400 */
struct $FA7086906B11B84E19C202CDD64679A5
{
    unsigned __int32 BamQosLevel : 8;
    unsigned __int32 PendingQosUpdate : 2;
    unsigned __int32 CacheIsolationEnabled : 1;
    unsigned __int32 TracepointActive : 1;
    unsigned __int32 PrcbFlagsReserved : 20;
};

/* 401 */
union _KPRCBFLAG
{
    volatile int PrcbFlags;
    $FA7086906B11B84E19C202CDD64679A5 __s1;
};

/* 402 */
struct _KDESCRIPTOR
{
    unsigned __int16 Pad[3];
    unsigned __int16 Limit;
    void* Base;
};

/* 403 */
struct _KSPECIAL_REGISTERS
{
    unsigned __int64 Cr0;
    unsigned __int64 Cr2;
    unsigned __int64 Cr3;
    unsigned __int64 Cr4;
    unsigned __int64 KernelDr0;
    unsigned __int64 KernelDr1;
    unsigned __int64 KernelDr2;
    unsigned __int64 KernelDr3;
    unsigned __int64 KernelDr6;
    unsigned __int64 KernelDr7;
    _KDESCRIPTOR Gdtr;
    _KDESCRIPTOR Idtr;
    unsigned __int16 Tr;
    unsigned __int16 Ldtr;
    unsigned int MxCsr;
    unsigned __int64 DebugControl;
    unsigned __int64 LastBranchToRip;
    unsigned __int64 LastBranchFromRip;
    unsigned __int64 LastExceptionToRip;
    unsigned __int64 LastExceptionFromRip;
    unsigned __int64 Cr8;
    unsigned __int64 MsrGsBase;
    unsigned __int64 MsrGsSwap;
    unsigned __int64 MsrStar;
    unsigned __int64 MsrLStar;
    unsigned __int64 MsrCStar;
    unsigned __int64 MsrSyscallMask;
    unsigned __int64 Xcr0;
    unsigned __int64 MsrFsBase;
    unsigned __int64 SpecialPadding0;
};

/* 404 */
struct _KPROCESSOR_STATE
{
    _KSPECIAL_REGISTERS SpecialRegisters;
    _CONTEXT ContextFrame;
};

/* 488 */
struct $34248A84B98EBB2D47BB9FC41093285E
{
    unsigned __int16 BpbRetpolineExitSpecCtrl;
    unsigned __int16 BpbTrappedRetpolineExitSpecCtrl;
    unsigned __int16 BpbTrappedBpbState;
    unsigned __int8 BpbRetpolineState;
    unsigned __int8 PrcbPad12b;
};

/* 489 */
#pragma pack(push, 1)
struct $586BEB158A9527E20025803546797F02
{
    _BYTE gap0[4];
    unsigned __int16 BpbTrappedCpuIdle : 1;
    unsigned __int16 BpbTrappedFlushRsbOnTrap : 1;
    unsigned __int16 BpbTrappedIbpbOnReturn : 1;
    unsigned __int16 BpbTrappedIbpbOnTrap : 1;
    unsigned __int16 BpbTrappedIbpbOnRetpolineExit : 1;
    unsigned __int16 BpbTrappedBpbStateReserved : 3;
    unsigned __int16 BpbTrappedBpbStateReserved2 : 8;
    unsigned __int8 BpbRunningNonRetpolineCode : 1;
    unsigned __int8 BpbIndirectCallsSafe : 1;
    unsigned __int8 BpbRetpolineEnabled : 1;
    unsigned __int8 BpbRetpolineStateReserved : 5;
};
#pragma pack(pop)

/* 490 */
union $71E45612887303BC023F3CB9C13769F5
{
    $34248A84B98EBB2D47BB9FC41093285E __s0;
    unsigned __int64 PrcbPad12a;
    $586BEB158A9527E20025803546797F02 __s2;
};

/* 491 */
struct $74A749D08003D8EA6488D13162AFD0DD
{
    unsigned __int64 TrappedSecurityDomain;
    unsigned __int16 BpbState;
    unsigned __int8 BpbFeatures;
    unsigned __int8 PrcbPad12e[1];
    unsigned __int16 BpbCurrentSpecCtrl;
    unsigned __int16 BpbKernelSpecCtrl;
    unsigned __int16 BpbNmiSpecCtrl;
    unsigned __int16 BpbUserSpecCtrl;
    volatile __int16 PairRegister;
    unsigned __int8 PrcbPad12d[2];
};

/* 492 */
#pragma pack(push, 1)
struct $256D534C91A68E88DC1DB6C565859C51
{
    _BYTE gap0[8];
    unsigned __int16 BpbCpuIdle : 1;
    unsigned __int16 BpbFlushRsbOnTrap : 1;
    unsigned __int16 BpbIbpbOnReturn : 1;
    unsigned __int16 BpbIbpbOnTrap : 1;
    unsigned __int16 BpbIbpbOnRetpolineExit : 1;
    unsigned __int16 BpbFlushRsbOnReturn : 1;
    unsigned __int16 BpbFlushRsbOnRetpolineExit : 1;
    unsigned __int16 BpbDivideOnReturn : 1;
    unsigned __int16 VerwOnNonKvaReturn : 1;
    unsigned __int16 FlushBhbOnTrap : 1;
    unsigned __int16 Spare : 6;
    unsigned __int8 BpbClearOnIdle : 1;
    unsigned __int8 BpbEnabled : 1;
    unsigned __int8 BpbSmep : 1;
    unsigned __int8 BpbKCet : 1;
    unsigned __int8 BhbFlushSequence : 2;
    unsigned __int8 BpbFeaturesReserved : 2;
};
#pragma pack(pop)

/* 493 */
union $83BFE9ED6FF150C93B2F88E6A5C27C2B
{
    $74A749D08003D8EA6488D13162AFD0DD __s0;
    unsigned __int64 PrcbPad12c[3];
    $256D534C91A68E88DC1DB6C565859C51 __s2;
};

/* 405 */
struct _KSPIN_LOCK_QUEUE
{
    _KSPIN_LOCK_QUEUE* volatile Next;
    unsigned __int64* volatile Lock;
};

/* 415 */
struct _PP_LOOKASIDE_LIST
{
    _GENERAL_LOOKASIDE* P;
    _GENERAL_LOOKASIDE* L;
};

/* 407 */
union $8A813D4E776EFDE239FDBDB1317DE833
{
    _SLIST_HEADER ListHead;
    _SINGLE_LIST_ENTRY SingleListHead;
};

/* 408 */
union $9D02AA4AC86E49CEAF084B97B97744B1
{
    unsigned int AllocateMisses;
    unsigned int AllocateHits;
};

/* 409 */
union $4290DA71080BA5C562B380EC38D3C295
{
    unsigned int FreeMisses;
    unsigned int FreeHits;
};

/* 410 */
union $3ECDF33E7806C0DE2F6C4C70AFFAAD33
{
    void* (__fastcall* AllocateEx)(_POOL_TYPE, unsigned __int64, unsigned int, _LOOKASIDE_LIST_EX*);
    void* (__fastcall* Allocate)(_POOL_TYPE, unsigned __int64, unsigned int);
};

/* 411 */
union $71CB7496F5B7FB86694EF1216DE71F14
{
    void(__fastcall* FreeEx)(void*, _LOOKASIDE_LIST_EX*);
    void(__fastcall* Free)(void*);
};

/* 412 */
union $BA67176EA55FA2D963EA02A98A2C99D2
{
    unsigned int LastAllocateMisses;
    unsigned int LastAllocateHits;
};

/* 413 */
struct _GENERAL_LOOKASIDE_POOL
{
    $8A813D4E776EFDE239FDBDB1317DE833 ___u0;
    unsigned __int16 Depth;
    unsigned __int16 MaximumDepth;
    unsigned int TotalAllocates;
    $9D02AA4AC86E49CEAF084B97B97744B1 ___u4;
    unsigned int TotalFrees;
    $4290DA71080BA5C562B380EC38D3C295 ___u6;
    _POOL_TYPE Type;
    unsigned int Tag;
    unsigned int Size;
    $3ECDF33E7806C0DE2F6C4C70AFFAAD33 ___u10;
    $71CB7496F5B7FB86694EF1216DE71F14 ___u11;
    _LIST_ENTRY ListEntry;
    unsigned int LastTotalAllocates;
    $BA67176EA55FA2D963EA02A98A2C99D2 ___u14;
    unsigned int Future[2];
};

/* 419 */
struct _KDPC_LIST
{
    _SINGLE_LIST_ENTRY ListHead;
    _SINGLE_LIST_ENTRY* LastEntry;
};

/* 420 */
struct _KDPC_DATA
{
    _KDPC_LIST DpcList;
    unsigned __int64 DpcLock;
    volatile int DpcQueueDepth;
    unsigned int DpcCount;
    _KDPC* volatile ActiveDpc;
};

/* 494 */
struct $A14E8C9598FEC320F05702613B784A64
{
    __int16 NormalDpcState;
    __int16 ThreadDpcState;
};

/* 495 */
struct $62DA18D6A05C474F028C1781FA2A668F
{
    unsigned __int32 DpcNormalProcessingActive : 1;
    unsigned __int32 DpcNormalProcessingRequested : 1;
    unsigned __int32 DpcNormalThreadSignal : 1;
    unsigned __int32 DpcNormalTimerExpiration : 1;
    unsigned __int32 DpcNormalDpcPresent : 1;
    unsigned __int32 DpcNormalLocalInterrupt : 1;
    unsigned __int32 DpcNormalSpare : 10;
    unsigned __int32 DpcThreadActive : 1;
    unsigned __int32 DpcThreadRequested : 1;
    unsigned __int32 DpcThreadSpare : 14;
};

/* 496 */
union $EDE6DD1DB226BBFFCBDEE777881653F4
{
    volatile int DpcRequestSummary;
    __int16 DpcRequestSlot[2];
    $A14E8C9598FEC320F05702613B784A64 __s2;
    $62DA18D6A05C474F028C1781FA2A668F __s3;
};

/* 421 */
struct _KTIMER_TABLE_ENTRY
{
    unsigned __int64 Lock;
    _LIST_ENTRY Entry;
    _ULARGE_INTEGER Time;
};

/* 422 */
struct _KTIMER_TABLE_STATE
{
    unsigned __int64 LastTimerExpiration[2];
    unsigned int LastTimerHand[2];
};

/* 423 */
struct _KTIMER_TABLE
{
    _KTIMER* TimerExpiry[64];
    _KTIMER_TABLE_ENTRY TimerEntries[2][256];
    _KTIMER_TABLE_STATE TableState;
};

/* 258 */
struct $08481D05807C14C022C64127DBCB0DC5
{
    unsigned __int8 Type;
    unsigned __int8 Signalling;
    unsigned __int8 Size;
    unsigned __int8 Reserved1;
};

/* 259 */
struct $BDD1DEEA9085FB2031C94E38C028AF9F
{
    unsigned __int8 TimerType;
    unsigned __int8 TimerControlFlags;
    unsigned __int8 Hand;
    unsigned __int8 TimerMiscFlags;
};

/* 260 */
struct $02F1E2651E9D26351CD44793F2F78E1F
{
    unsigned __int8 Timer2Type;
    unsigned __int8 Absolute : 1;
    unsigned __int8 Wake : 1;
    unsigned __int8 EncodedTolerableDelay : 6;
    unsigned __int8 Timer2ComponentId;
    unsigned __int8 Index : 6;
    unsigned __int8 Inserted : 1;
    unsigned __int8 Expired : 1;
};

/* 261 */
struct $E9B6E411B508381891F0374539EA7718
{
    unsigned __int8 QueueType;
    unsigned __int8 Timer2Flags;
    unsigned __int8 QueueSize;
    unsigned __int8 Timer2RelativeId;
};

/* 262 */
struct $82359CCE575330AAB08AF0894BC28AE0
{
    unsigned __int8 ThreadType;
    unsigned __int8 Timer2Inserted : 1;
    unsigned __int8 Timer2Expiring : 1;
    unsigned __int8 Timer2CancelPending : 1;
    unsigned __int8 Timer2SetPending : 1;
    unsigned __int8 Timer2Running : 1;
    unsigned __int8 Timer2Disabled : 1;
    unsigned __int8 Timer2ReservedFlags : 2;
    unsigned __int8 ThreadControlFlags;
    unsigned __int8 QueueReserved;
};

/* 263 */
struct $15D1686C1B6B91F828FF4FDCD9195D5F
{
    unsigned __int8 MutantType;
    unsigned __int8 QueueControlFlags;
    unsigned __int8 CycleProfiling : 1;
    unsigned __int8 CounterProfiling : 1;
    unsigned __int8 GroupScheduling : 1;
    unsigned __int8 AffinitySet : 1;
    unsigned __int8 Tagged : 1;
    unsigned __int8 EnergyProfiling : 1;
    unsigned __int8 SchedulerAssist : 1;
    unsigned __int8 ThreadReservedControlFlags : 1;
    unsigned __int8 DebugActive;
};

/* 264 */
struct $D79AAC5C8887A555B51B5D23AA59DF12
{
    _BYTE gap0;
    unsigned __int8 Abandoned : 1;
    unsigned __int8 DisableIncrement : 1;
    unsigned __int8 QueueReservedControlFlags : 6;
    unsigned __int8 DpcActive;
    unsigned __int8 ActiveDR7 : 1;
    unsigned __int8 Instrumented : 1;
    unsigned __int8 Minimal : 1;
    unsigned __int8 Reserved4 : 2;
    unsigned __int8 AltSyscall : 1;
    unsigned __int8 UmsScheduled : 1;
    unsigned __int8 UmsPrimary : 1;
};

/* 265 */
struct $083564EDBD3AB37FEF5E1E996A18DE87
{
    _BYTE gap0;
    unsigned __int8 ThreadReserved;
    _BYTE gap2;
    unsigned __int8 MutantReserved;
};

/* 266 */
struct $C2211613BBEF869A31F7F48D9F786AC7
{
    _BYTE gap0;
    unsigned __int8 MutantSize;
};

/* 267 */
union $237CC490DF443354F65B5A76B8490859
{
    volatile int Lock;
    int LockNV;
    $08481D05807C14C022C64127DBCB0DC5 __s2;
    $BDD1DEEA9085FB2031C94E38C028AF9F __s3;
    $02F1E2651E9D26351CD44793F2F78E1F __s4;
    $E9B6E411B508381891F0374539EA7718 __s5;
    $82359CCE575330AAB08AF0894BC28AE0 __s6;
    $15D1686C1B6B91F828FF4FDCD9195D5F __s7;
    $D79AAC5C8887A555B51B5D23AA59DF12 __s8;
    $083564EDBD3AB37FEF5E1E996A18DE87 __s9;
    $C2211613BBEF869A31F7F48D9F786AC7 __s10;
};

/* 268 */
struct _DISPATCHER_HEADER
{
    $237CC490DF443354F65B5A76B8490859 ___u0;
    int SignalState;
    _LIST_ENTRY WaitListHead;
};

/* 424 */
struct _KGATE
{
    _DISPATCHER_HEADER Header;
};

/* 275 */
struct $82623AFB470F8517B6D8F9E43441C7E1
{
    unsigned __int8 Type;
    unsigned __int8 Importance;
    volatile unsigned __int16 Number;
};

/* 276 */
union $D18E84BEB9E7CD87A2B907E75D4EFF0A
{
    unsigned int TargetInfoAsUlong;
    $82623AFB470F8517B6D8F9E43441C7E1 __s1;
};

/* 274 */
struct _KDPC
{
    $D18E84BEB9E7CD87A2B907E75D4EFF0A ___u0;
    _SINGLE_LIST_ENTRY DpcListEntry;
    unsigned __int64 ProcessorHistory;
    void(__fastcall* DeferredRoutine)(_KDPC*, void*, void*, void*);
    void* DeferredContext;
    void* SystemArgument1;
    void* SystemArgument2;
    void* DpcData;
};

/* 497 */
struct $587E166413A0BC9D4B6487D1ABA99C2F
{
    unsigned __int8 NmiActive;
    unsigned __int8 MceActive;
};

/* 498 */
union $6C78CA605BC64D4FCD792FE841F45F4B
{
    $587E166413A0BC9D4B6487D1ABA99C2F __s0;
    unsigned __int16 CombinedNmiMceActive;
};

/* 441 */
struct _PROC_IDLE_POLICY
{
    unsigned __int8 PromotePercent;
    unsigned __int8 DemotePercent;
    unsigned __int8 PromotePercentBase;
    unsigned __int8 DemotePercentBase;
    unsigned __int8 AllowScaling;
    unsigned __int8 ForceLightIdle;
};

/* 442 */
struct $4C54FEED1D206CF6DD53948246B9325F
{
    __int32 RefCount : 24;
    unsigned __int32 State : 8;
};

/* 443 */
volatile union _PPM_IDLE_SYNCHRONIZATION_STATE
{
    int AsLong;
    $4C54FEED1D206CF6DD53948246B9325F __s1;
};

/* 446 */
struct __declspec(align(8)) _PROC_FEEDBACK
{
    unsigned __int64 Lock;
    unsigned __int64 CyclesLast;
    unsigned __int64 CyclesActive;
    _PROC_FEEDBACK_COUNTER* Counters[2];
    unsigned __int64 LastUpdateTime;
    unsigned __int64 UnscaledTime;
    volatile __int64 UnaccountedTime;
    unsigned __int64 ScaledTime[2];
    unsigned __int64 UnaccountedKernelTime;
    unsigned __int64 PerformanceScaledKernelTime;
    unsigned int UserTimeLast;
    unsigned int KernelTimeLast;
    unsigned __int64 IdleGenerationNumberLast;
    unsigned __int64 HvActiveTimeLast;
    unsigned __int64 StallCyclesLast;
    unsigned __int64 StallTime;
    unsigned __int8 KernelTimesIndex;
    unsigned __int8 CounterDiscardsIdleTime;
};

/* 447 */
struct _PPM_FFH_THROTTLE_STATE_INFO
{
    unsigned __int8 EnableLogging;
    unsigned int MismatchCount;
    unsigned __int8 Initialized;
    unsigned __int64 LastValue;
    _LARGE_INTEGER LastLogTickCount;
};

/* 448 */
struct _PROC_IDLE_SNAP
{
    unsigned __int64 Time;
    unsigned __int64 Idle;
};

/* 449 */
struct __declspec(align(4)) _PROC_PERF_CHECK_CONTEXT
{
    _PROC_PERF_DOMAIN* Domain;
    _PROC_PERF_CONSTRAINT* Constraint;
    _PROC_PERF_CHECK* PerfCheck;
    _PROC_PERF_LOAD* Load;
    _PROC_PERF_HISTORY* PerfHistory;
    unsigned int Utility;
    unsigned int AffinitizedUtility;
    unsigned int MediaUtility;
    unsigned __int16 LatestAffinitizedPercent;
    unsigned __int16 AveragePerformancePercent;
    unsigned int RelativePerformance;
    unsigned __int8 NtProcessor;
};

/* 460 */
union $1295C7652040702D9335A0311A3EC089
{
    unsigned __int64 SnapTimeLast;
    unsigned __int64 EnergyConsumed;
};

/* 461 */
struct _PROCESSOR_POWER_STATE
{
    _PPM_IDLE_STATES* IdleStates;
    _PROC_IDLE_ACCOUNTING* IdleAccounting;
    unsigned __int64 IdleTimeLast;
    unsigned __int64 IdleTimeTotal;
    volatile unsigned __int64 IdleTimeEntry;
    unsigned __int64 IdleTimeExpiration;
    unsigned __int8 NonInterruptibleTransition;
    unsigned __int8 PepWokenTransition;
    unsigned __int8 HvTargetState;
    unsigned __int8 SoftParked;
    unsigned int TargetIdleState;
    _PROC_IDLE_POLICY IdlePolicy;
    volatile _PPM_IDLE_SYNCHRONIZATION_STATE Synchronization;
    _PROC_FEEDBACK PerfFeedback;
    _PROC_HYPERVISOR_STATE Hypervisor;
    unsigned int LastSysTime;
    unsigned __int64 WmiDispatchPtr;
    int WmiInterfaceEnabled;
    _PPM_FFH_THROTTLE_STATE_INFO FFHThrottleStateInfo;
    _KDPC PerfActionDpc;
    volatile int PerfActionMask;
    _PROC_IDLE_SNAP HvIdleCheck;
    _PROC_PERF_CHECK_CONTEXT CheckContext;
    _PPM_CONCURRENCY_ACCOUNTING* Concurrency;
    _PPM_CONCURRENCY_ACCOUNTING* ClassConcurrency;
    unsigned __int8 ArchitecturalEfficiencyClass;
    unsigned __int8 PerformanceSchedulingClass;
    unsigned __int8 EfficiencySchedulingClass;
    unsigned __int8 Unused;
    unsigned __int8 Parked;
    unsigned __int8 LongPriorQosPeriod;
    $1295C7652040702D9335A0311A3EC089 ___u31;
    unsigned __int64 ActiveTime;
    unsigned __int64 TotalTime;
    struct _POP_FX_DEVICE* FxDevice;
    unsigned __int64 LastQosTranstionTsc;
    unsigned __int64 QosTransitionHysteresis;
    _KHETERO_CPU_QOS RequestedQosClass;
    _KHETERO_CPU_QOS ResolvedQosClass;
    unsigned __int16 QosEquivalencyMask;
    unsigned __int16 HwFeedbackTableIndex;
    unsigned __int8 HwFeedbackParkHint;
    unsigned __int8 HwFeedbackPerformanceClass;
    unsigned __int8 HwFeedbackEfficiencyClass;
    unsigned __int8 HeteroCoreType;
};

/* 309 */
struct _KTIMER
{
    _DISPATCHER_HEADER Header;
    _ULARGE_INTEGER DueTime;
    _LIST_ENTRY TimerListEntry;
    _KDPC* Dpc;
    unsigned __int16 Processor;
    unsigned __int16 TimerType;
    unsigned int Period;
};

/* 462 */
struct _CACHE_DESCRIPTOR
{
    unsigned __int8 Level;
    unsigned __int8 Associativity;
    unsigned __int16 LineSize;
    unsigned int Size;
    _PROCESSOR_CACHE_TYPE Type;
};

/* 290 */
struct _KAFFINITY_EX
{
    unsigned __int16 Count;
    unsigned __int16 Size;
    unsigned int Reserved;
    unsigned __int64 Bitmap[20];
};

/* 469 */
struct _SYNCH_COUNTERS
{
    unsigned int SpinLockAcquireCount;
    unsigned int SpinLockContentionCount;
    unsigned int SpinLockSpinCount;
    unsigned int IpiSendRequestBroadcastCount;
    unsigned int IpiSendRequestRoutineCount;
    unsigned int IpiSendSoftwareInterruptCount;
    unsigned int ExInitializeResourceCount;
    unsigned int ExReInitializeResourceCount;
    unsigned int ExDeleteResourceCount;
    unsigned int ExecutiveResourceAcquiresCount;
    unsigned int ExecutiveResourceContentionsCount;
    unsigned int ExecutiveResourceReleaseExclusiveCount;
    unsigned int ExecutiveResourceReleaseSharedCount;
    unsigned int ExecutiveResourceConvertsCount;
    unsigned int ExAcqResExclusiveAttempts;
    unsigned int ExAcqResExclusiveAcquiresExclusive;
    unsigned int ExAcqResExclusiveAcquiresExclusiveRecursive;
    unsigned int ExAcqResExclusiveWaits;
    unsigned int ExAcqResExclusiveNotAcquires;
    unsigned int ExAcqResSharedAttempts;
    unsigned int ExAcqResSharedAcquiresExclusive;
    unsigned int ExAcqResSharedAcquiresShared;
    unsigned int ExAcqResSharedAcquiresSharedRecursive;
    unsigned int ExAcqResSharedWaits;
    unsigned int ExAcqResSharedNotAcquires;
    unsigned int ExAcqResSharedStarveExclusiveAttempts;
    unsigned int ExAcqResSharedStarveExclusiveAcquiresExclusive;
    unsigned int ExAcqResSharedStarveExclusiveAcquiresShared;
    unsigned int ExAcqResSharedStarveExclusiveAcquiresSharedRecursive;
    unsigned int ExAcqResSharedStarveExclusiveWaits;
    unsigned int ExAcqResSharedStarveExclusiveNotAcquires;
    unsigned int ExAcqResSharedWaitForExclusiveAttempts;
    unsigned int ExAcqResSharedWaitForExclusiveAcquiresExclusive;
    unsigned int ExAcqResSharedWaitForExclusiveAcquiresShared;
    unsigned int ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive;
    unsigned int ExAcqResSharedWaitForExclusiveWaits;
    unsigned int ExAcqResSharedWaitForExclusiveNotAcquires;
    unsigned int ExSetResOwnerPointerExclusive;
    unsigned int ExSetResOwnerPointerSharedNew;
    unsigned int ExSetResOwnerPointerSharedOld;
    unsigned int ExTryToAcqExclusiveAttempts;
    unsigned int ExTryToAcqExclusiveAcquires;
    unsigned int ExBoostExclusiveOwner;
    unsigned int ExBoostSharedOwners;
    unsigned int ExEtwSynchTrackingNotificationsCount;
    unsigned int ExEtwSynchTrackingNotificationsAccountedCount;
};

/* 470 */
struct _FILESYSTEM_DISK_COUNTERS
{
    unsigned __int64 FsBytesRead;
    unsigned __int64 FsBytesWritten;
};

/* 471 */
struct __declspec(align(8)) _KENTROPY_TIMING_STATE
{
    unsigned int EntropyCount;
    unsigned int Buffer[64];
    _KDPC Dpc;
    unsigned int LastDeliveredBuffer;
};

/* 472 */
struct $437EDEAFE33DAFED4793B8A3A762EFC4
{
    unsigned __int8 PairLocalLow;
    unsigned __int8 PairLocalForceStibp : 1;
    unsigned __int8 Reserved : 4;
    unsigned __int8 Frozen : 1;
    unsigned __int8 ForceUntrusted : 1;
    unsigned __int8 SynchIpi : 1;
};

/* 473 */
union $ED2DC9081457D565203355DB81D7680C
{
    __int16 PairLocal;
    $437EDEAFE33DAFED4793B8A3A762EFC4 __s1;
};

/* 474 */
struct $65F3014B83CBA7D0B98DA1788953A33A
{
    unsigned __int8 PairRemoteLow;
    unsigned __int8 Reserved2;
};

/* 475 */
union $52C737777222223B24864384646C84A0
{
    __int16 PairRemote;
    $65F3014B83CBA7D0B98DA1788953A33A __s1;
};

/* 499 */
struct $1EA2F041BCB2C8FF5956360917820830
{
    unsigned int UpdateCycle;
    $ED2DC9081457D565203355DB81D7680C ___u1;
    $52C737777222223B24864384646C84A0 ___u2;
    unsigned __int8 Trace[24];
    unsigned __int64 LocalDomain;
    unsigned __int64 RemoteDomain;
    _KTHREAD* Thread;
};

/* 476 */
struct _IOP_IRP_STACK_PROFILER
{
    unsigned int Profile[20];
    unsigned int TotalIrps;
};

/* 477 */
struct _KSECURE_FAULT_INFORMATION
{
    unsigned __int64 FaultCode;
    unsigned __int64 FaultVa;
};

/* 463 */
struct _KSHARED_READY_QUEUE
{
    unsigned __int64 Lock;
    unsigned int ReadySummary;
    _LIST_ENTRY ReadyListHead[32];
    char RunningSummary[64];
    unsigned __int8 Span;
    unsigned __int8 LowProcIndex;
    unsigned __int8 QueueIndex;
    unsigned __int8 ProcCount;
    unsigned __int8 ScanOwner;
    unsigned __int8 Spare[3];
    unsigned __int64 Affinity;
    unsigned int ReadyThreadCount;
    unsigned __int64 ReadyQueueExpectedRunTime;
};

/* 478 */
struct _KTIMER_EXPIRATION_TRACE
{
    unsigned __int64 InterruptTime;
    _LARGE_INTEGER PerformanceCounter;
};

/* 481 */
struct _MACHINE_FRAME
{
    unsigned __int64 Rip;
    unsigned __int16 SegCs;
    unsigned __int16 Fill1[3];
    unsigned int EFlags;
    unsigned int Fill2;
    unsigned __int64 Rsp;
    unsigned __int16 SegSs;
    unsigned __int16 Fill3[3];
};

/* 482 */
struct _MACHINE_CHECK_CONTEXT
{
    _MACHINE_FRAME MachineFrame;
    unsigned __int64 Rax;
    unsigned __int64 Rcx;
    unsigned __int64 Rdx;
    unsigned __int64 GsBase;
    unsigned __int64 Cr3;
};

/* 483 */
struct __declspec(align(8)) _KLOCK_QUEUE_HANDLE
{
    _KSPIN_LOCK_QUEUE LockQueue;
    unsigned __int8 OldIrql;
};

/* 480 */
struct _KREQUEST_PACKET
{
    void* CurrentPacket[3];
    void(__fastcall* WorkerRoutine)(void*, void*, void*, void*);
};

/* 479 */
struct __declspec(align(8)) _REQUEST_MAILBOX
{
    _REQUEST_MAILBOX* Next;
    unsigned __int64 RequestSummary;
    _KREQUEST_PACKET RequestPacket;
    volatile int* NodeTargetCountAddr;
    volatile int NodeTargetCount;
};

/* 416 */
union $F0B7633D12AB9253AAF20DBC06B17433
{
    _KAFFINITY_EX KeFlushTbAffinity;
    _KAFFINITY_EX KeFlushWbAffinity;
    _KAFFINITY_EX KeSyncContextAffinity;
};

/* 417 */
struct _KSTATIC_AFFINITY_BLOCK
{
    $F0B7633D12AB9253AAF20DBC06B17433 ___u0;
    _KAFFINITY_EX KeFlushTbDeepIdleAffinity;
    _KAFFINITY_EX KeIpiSendAffinity;
    _KAFFINITY_EX KeIpiSendIpiSet;
};

/* 337 */
struct _KPRCB
{
    unsigned int MxCsr;
    unsigned __int8 LegacyNumber;
    unsigned __int8 ReservedMustBeZero;
    unsigned __int8 InterruptRequest;
    unsigned __int8 IdleHalt;
    _KTHREAD* CurrentThread;
    _KTHREAD* NextThread;
    _KTHREAD* IdleThread;
    unsigned __int8 NestingLevel;
    unsigned __int8 ClockOwner;
    $ED34874246E5ECE3CAF1B6B6E76DEE42 ___u10;
    unsigned __int8 IdleState;
    unsigned int Number;
    unsigned __int64 RspBase;
    unsigned __int64 PrcbLock;
    char* PriorityState;
    char CpuType;
    char CpuID;
    $25350A9DA83C31B1294F7FCF870CEEB1 ___u18;
    unsigned int MHz;
    unsigned __int64 HalReserved[8];
    unsigned __int16 MinorVersion;
    unsigned __int16 MajorVersion;
    unsigned __int8 BuildType;
    unsigned __int8 CpuVendor;
    unsigned __int8 LegacyCoresPerPhysicalProcessor;
    unsigned __int8 LegacyLogicalProcessorsPerCore;
    unsigned __int64 TscFrequency;
    unsigned int CoresPerPhysicalProcessor;
    unsigned int LogicalProcessorsPerCore;
    unsigned __int64 PrcbPad04[4];
    _KNODE* ParentNode;
    unsigned __int64 GroupSetMember;
    unsigned __int8 Group;
    unsigned __int8 GroupIndex;
    unsigned __int8 PrcbPad05[2];
    unsigned int InitialApicId;
    unsigned int ScbOffset;
    unsigned int ApicMask;
    void* AcpiReserved;
    unsigned int CFlushSize;
    _KPRCBFLAG PrcbFlags;
    unsigned __int64 PrcbPad11[2];
    _KPROCESSOR_STATE ProcessorState;
    _XSAVE_AREA_HEADER* ExtendedSupervisorState;
    unsigned int ProcessorSignature;
    unsigned int ProcessorFlags;
    $71E45612887303BC023F3CB9C13769F5 ___u47;
    $83BFE9ED6FF150C93B2F88E6A5C27C2B ___u48;
    _KSPIN_LOCK_QUEUE LockQueue[17];
    _PP_LOOKASIDE_LIST PPLookasideList[16];
    _GENERAL_LOOKASIDE_POOL PPNxPagedLookasideList[32];
    _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
    _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
    unsigned __int64 PrcbPad20;
    _SINGLE_LIST_ENTRY DeferredReadyListHead;
    volatile int MmPageFaultCount;
    volatile int MmCopyOnWriteCount;
    volatile int MmTransitionCount;
    volatile int MmDemandZeroCount;
    volatile int MmPageReadCount;
    volatile int MmPageReadIoCount;
    volatile int MmDirtyPagesWriteCount;
    volatile int MmDirtyWriteIoCount;
    volatile int MmMappedPagesWriteCount;
    volatile int MmMappedWriteIoCount;
    unsigned int KeSystemCalls;
    unsigned int KeContextSwitches;
    unsigned int PrcbPad40;
    unsigned int CcFastReadNoWait;
    unsigned int CcFastReadWait;
    unsigned int CcFastReadNotPossible;
    unsigned int CcCopyReadNoWait;
    unsigned int CcCopyReadWait;
    unsigned int CcCopyReadNoWaitMiss;
    volatile int IoReadOperationCount;
    volatile int IoWriteOperationCount;
    volatile int IoOtherOperationCount;
    _LARGE_INTEGER IoReadTransferCount;
    _LARGE_INTEGER IoWriteTransferCount;
    _LARGE_INTEGER IoOtherTransferCount;
    volatile int PacketBarrier;
    volatile int TargetCount;
    volatile unsigned int IpiFrozen;
    unsigned int PrcbPad30;
    void* IsrDpcStats;
    unsigned int DeviceInterrupts;
    int LookasideIrpFloat;
    unsigned int InterruptLastCount;
    unsigned int InterruptRate;
    unsigned __int64 PrcbPad31;
    _KPRCB* PairPrcb;
    _KSTATIC_AFFINITY_BLOCK StaticAffinity;
    unsigned __int64 PrcbPad35[5];
    _SLIST_HEADER InterruptObjectPool;
    _RTL_HASH_TABLE* DpcRuntimeHistoryHashTable;
    _KDPC* DpcRuntimeHistoryHashTableCleanupDpc;
    void(__fastcall* CurrentDpcRoutine)(_KDPC*, void*, void*, void*);
    unsigned __int64 CurrentDpcRuntimeHistoryCached;
    unsigned __int64 CurrentDpcStartTime;
    unsigned __int64 PrcbPad41[1];
    _KDPC_DATA DpcData[2];
    void* DpcStack;
    int MaximumDpcQueueDepth;
    unsigned int DpcRequestRate;
    unsigned int MinimumDpcRate;
    unsigned int DpcLastCount;
    unsigned __int8 ThreadDpcEnable;
    volatile unsigned __int8 QuantumEnd;
    volatile unsigned __int8 DpcRoutineActive;
    volatile unsigned __int8 IdleSchedule;
    $EDE6DD1DB226BBFFCBDEE777881653F4 ___u111;
    unsigned int PrcbPad93;
    unsigned int LastTick;
    unsigned int ClockInterrupts;
    unsigned int ReadyScanTick;
    void* InterruptObject[256];
    _KTIMER_TABLE TimerTable;
    unsigned int PrcbPad92[10];
    _KGATE DpcGate;
    void* PrcbPad52;
    _KDPC CallDpc;
    int ClockKeepAlive;
    unsigned __int8 PrcbPad60[2];
    $6C78CA605BC64D4FCD792FE841F45F4B ___u124;
    int DpcWatchdogPeriod;
    int DpcWatchdogCount;
    volatile int KeSpinLockOrdering;
    unsigned int DpcWatchdogProfileCumulativeDpcThreshold;
    void* CachedPtes;
    _LIST_ENTRY WaitListHead;
    unsigned __int64 WaitLock;
    unsigned int ReadySummary;
    int AffinitizedSelectionMask;
    unsigned int QueueIndex;
    unsigned int PrcbPad75[2];
    unsigned int DpcWatchdogSequenceNumber;
    _KDPC TimerExpirationDpc;
    _RTL_RB_TREE ScbQueue;
    _LIST_ENTRY DispatcherReadyListHead[32];
    unsigned int InterruptCount;
    unsigned int KernelTime;
    unsigned int UserTime;
    unsigned int DpcTime;
    unsigned int InterruptTime;
    unsigned int AdjustDpcThreshold;
    unsigned __int8 DebuggerSavedIRQL;
    unsigned __int8 GroupSchedulingOverQuota;
    volatile unsigned __int8 DeepSleep;
    unsigned __int8 PrcbPad80;
    unsigned int DpcTimeCount;
    unsigned int DpcTimeLimit;
    unsigned int PeriodicCount;
    unsigned int PeriodicBias;
    unsigned int AvailableTime;
    unsigned int KeExceptionDispatchCount;
    unsigned int ReadyThreadCount;
    unsigned __int64 ReadyQueueExpectedRunTime;
    unsigned __int64 StartCycles;
    unsigned __int64 TaggedCyclesStart;
    unsigned __int64 TaggedCycles[3];
    unsigned __int64 AffinitizedCycles;
    unsigned __int64 ImportantCycles;
    unsigned __int64 UnimportantCycles;
    unsigned int DpcWatchdogProfileSingleDpcThreshold;
    volatile int MmSpinLockOrdering;
    void* volatile CachedStack;
    unsigned int PageColor;
    unsigned int NodeColor;
    unsigned int NodeShiftedColor;
    unsigned int SecondaryColorMask;
    unsigned __int8 PrcbPad81[6];
    unsigned __int8 ExceptionStackActive;
    unsigned __int8 TbFlushListActive;
    void* ExceptionStack;
    unsigned __int64 PrcbPad82[1];
    unsigned __int64 CycleTime;
    unsigned __int64 Cycles[4][2];
    unsigned int CcFastMdlReadNoWait;
    unsigned int CcFastMdlReadWait;
    unsigned int CcFastMdlReadNotPossible;
    unsigned int CcMapDataNoWait;
    unsigned int CcMapDataWait;
    unsigned int CcPinMappedDataCount;
    unsigned int CcPinReadNoWait;
    unsigned int CcPinReadWait;
    unsigned int CcMdlReadNoWait;
    unsigned int CcMdlReadWait;
    unsigned int CcLazyWriteHotSpots;
    unsigned int CcLazyWriteIos;
    unsigned int CcLazyWritePages;
    unsigned int CcDataFlushes;
    unsigned int CcDataPages;
    unsigned int CcLostDelayedWrites;
    unsigned int CcFastReadResourceMiss;
    unsigned int CcCopyReadWaitMiss;
    unsigned int CcFastMdlReadResourceMiss;
    unsigned int CcMapDataNoWaitMiss;
    unsigned int CcMapDataWaitMiss;
    unsigned int CcPinReadNoWaitMiss;
    unsigned int CcPinReadWaitMiss;
    unsigned int CcMdlReadNoWaitMiss;
    unsigned int CcMdlReadWaitMiss;
    unsigned int CcReadAheadIos;
    volatile int MmCacheTransitionCount;
    volatile int MmCacheReadCount;
    volatile int MmCacheIoCount;
    unsigned int PrcbPad91;
    void* MmInternal;
    _PROCESSOR_POWER_STATE PowerState;
    void* HyperPte;
    _LIST_ENTRY ScbList;
    _KDPC ForceIdleDpc;
    _KDPC DpcWatchdogDpc;
    _KTIMER DpcWatchdogTimer;
    _CACHE_DESCRIPTOR Cache[5];
    unsigned int CacheCount;
    volatile unsigned int CachedCommit;
    volatile unsigned int CachedResidentAvailable;
    void* WheaInfo;
    void* EtwSupport;
    void* ExSaPageArray;
    unsigned int KeAlignmentFixupCount;
    unsigned int PrcbPad95;
    _SLIST_HEADER HypercallPageList;
    unsigned __int64* StatisticsPage;
    unsigned __int64 GenerationTarget;
    unsigned __int64 PrcbPad85[4];
    void* HypercallCachedPages;
    void* VirtualApicAssist;
    _KAFFINITY_EX PackageProcessorSet;
    unsigned int PackageId;
    unsigned int PrcbPad86;
    unsigned __int64 SharedReadyQueueMask;
    _KSHARED_READY_QUEUE* SharedReadyQueue;
    unsigned int SharedQueueScanOwner;
    unsigned int ScanSiblingIndex;
    unsigned __int64 CoreProcessorSet;
    unsigned __int64 ScanSiblingMask;
    unsigned __int64 LLCMask;
    unsigned __int64 CacheProcessorMask[5];
    _PROCESSOR_PROFILE_CONTROL_AREA* ProcessorProfileControlArea;
    void* ProfileEventIndexAddress;
    void** DpcWatchdogProfile;
    void** DpcWatchdogProfileCurrentEmptyCapture;
    void* SchedulerAssist;
    _SYNCH_COUNTERS SynchCounters;
    unsigned __int64 PrcbPad94;
    _FILESYSTEM_DISK_COUNTERS FsCounters;
    unsigned __int8 VendorString[13];
    unsigned __int8 PrcbPad100[3];
    unsigned __int64 FeatureBits;
    _LARGE_INTEGER UpdateSignature;
    unsigned __int64 PteBitCache;
    unsigned int PteBitOffset;
    unsigned int PrcbPad105;
    _CONTEXT* Context;
    unsigned int ContextFlagsInit;
    unsigned int PrcbPad115;
    _XSAVE_AREA* ExtendedState;
    void* IsrStack;
    _KENTROPY_TIMING_STATE EntropyTimingState;
    unsigned __int64 PrcbPad110;
    $1EA2F041BCB2C8FF5956360917820830 StibpPairingTrace;
    _SINGLE_LIST_ENTRY AbSelfIoBoostsList;
    _SINGLE_LIST_ENTRY AbPropagateBoostsList;
    _KDPC AbDpc;
    _IOP_IRP_STACK_PROFILER IoIrpStackProfilerCurrent;
    _IOP_IRP_STACK_PROFILER IoIrpStackProfilerPrevious;
    _KSECURE_FAULT_INFORMATION SecureFault;
    unsigned __int64 PrcbPad120;
    _KSHARED_READY_QUEUE LocalSharedReadyQueue;
    unsigned __int64 PrcbPad125[2];
    unsigned int TimerExpirationTraceCount;
    unsigned int PrcbPad127;
    _KTIMER_EXPIRATION_TRACE TimerExpirationTrace[16];
    unsigned __int64 PrcbPad128[7];
    _REQUEST_MAILBOX* Mailbox;
    unsigned __int64 PrcbPad130[7];
    _MACHINE_CHECK_CONTEXT McheckContext[2];
    unsigned __int64 PrcbPad134[4];
    _KLOCK_QUEUE_HANDLE SelfmapLockHandle[4];
    unsigned __int64 PrcbPad134a[4];
    unsigned __int8 PrcbPad138[128];
    unsigned __int8 PrcbPad138a[64];
    unsigned __int64 KernelDirectoryTableBase;
    unsigned __int64 RspBaseShadow;
    unsigned __int64 UserRspShadow;
    unsigned int ShadowFlags;
    unsigned int PrcbPad138b;
    unsigned __int64 PrcbPad138c;
    unsigned __int16 PrcbPad138d;
    unsigned __int16 PrcbPad138e;
    unsigned int DbgMceNestingLevel;
    unsigned int DbgMceFlags;
    unsigned int PrcbPad139b;
    unsigned __int64 PrcbPad140[505];
    unsigned __int64 PrcbPad140a[8];
    unsigned __int64 PrcbPad141[504];
    unsigned __int8 PrcbPad141a[64];
    _REQUEST_MAILBOX RequestMailbox[1];
};

/* 257 */
struct _KPCR
{
    $6D2BD277AAF6D9FAEE9DE564884AEDF4 ___u0;
    _KIDTENTRY64* IdtBase;
    unsigned __int64 Unused[2];
    unsigned __int8 Irql;
    unsigned __int8 SecondLevelCacheAssociativity;
    unsigned __int8 ObsoleteNumber;
    unsigned __int8 Fill0;
    unsigned int Unused0[3];
    unsigned __int16 MajorVersion;
    unsigned __int16 MinorVersion;
    unsigned int StallScaleFactor;
    void* Unused1[3];
    unsigned int KernelReserved[15];
    unsigned int SecondLevelCacheSize;
    unsigned int HalReserved[16];
    unsigned int Unused2;
    void* KdVersionBlock;
    void* Unused3;
    unsigned int PcrAlign1[24];
    _KPRCB Prcb;
};

/* 500 */
struct $3CCEB4C367AD314E5B0AA0D7724EC670
{
    unsigned __int16 OffsetLow;
    unsigned __int16 Selector;
    unsigned __int16 IstIndex : 3;
    unsigned __int16 Reserved0 : 5;
    unsigned __int16 Type : 5;
    unsigned __int16 Dpl : 2;
    unsigned __int16 Present : 1;
    unsigned __int16 OffsetMiddle;
    unsigned int OffsetHigh;
    unsigned int Reserved1;
};

/* 501 */
union _KIDTENTRY64
{
    $3CCEB4C367AD314E5B0AA0D7724EC670 __s0;
    unsigned __int64 Alignment;
};

/* 280 */
struct $6E3F869BADF0AE2AE79CB2D8108FC64A
{
    unsigned __int8 State : 3;
    unsigned __int8 Affinity : 1;
    unsigned __int8 Priority : 1;
    unsigned __int8 Apc : 1;
    unsigned __int8 UserApc : 1;
    unsigned __int8 Alert : 1;
};

/* 281 */
union _KWAIT_STATUS_REGISTER
{
    unsigned __int8 Flags;
    $6E3F869BADF0AE2AE79CB2D8108FC64A __s1;
};

/* 356 */
struct $BF47041B248301F87E570BEB78208C5A
{
    unsigned __int32 AutoBoostActive : 1;
    unsigned __int32 ReadyTransition : 1;
    unsigned __int32 WaitNext : 1;
    unsigned __int32 SystemAffinityActive : 1;
    unsigned __int32 Alertable : 1;
    unsigned __int32 UserStackWalkActive : 1;
    unsigned __int32 ApcInterruptRequest : 1;
    unsigned __int32 QuantumEndMigrate : 1;
    unsigned __int32 UmsDirectedSwitchEnable : 1;
    unsigned __int32 TimerActive : 1;
    unsigned __int32 SystemThread : 1;
    unsigned __int32 ProcessDetachActive : 1;
    unsigned __int32 CalloutActive : 1;
    unsigned __int32 ScbReadyQueue : 1;
    unsigned __int32 ApcQueueable : 1;
    unsigned __int32 ReservedStackInUse : 1;
    unsigned __int32 UmsPerformingSyscall : 1;
    unsigned __int32 TimerSuspended : 1;
    unsigned __int32 SuspendedWaitMode : 1;
    unsigned __int32 SuspendSchedulerApcWait : 1;
    unsigned __int32 CetUserShadowStack : 1;
    unsigned __int32 BypassProcessFreeze : 1;
    unsigned __int32 Reserved : 10;
    unsigned __int32 ThreadFlagsSpare : 2;
};

/* 357 */
union $2B75562D9B3CA82563345D3F63EA5F75
{
    $BF47041B248301F87E570BEB78208C5A __s0;
    int MiscFlags;
};

/* 300 */
struct $B5CD178F87BE184A5118D4920C61026E
{
    unsigned __int8 KernelApcInProgress : 1;
    unsigned __int8 SpecialApcInProgress : 1;
};

/* 301 */
union $06092A4FB3F5DED584FB2155717226DA
{
    unsigned __int8 InProgressFlags;
    $B5CD178F87BE184A5118D4920C61026E __s1;
};

/* 302 */
struct $A85FE12DE136A601A0C0FDA7C2290F98
{
    unsigned __int8 SpecialUserApcPending : 1;
    unsigned __int8 UserApcPending : 1;
};

/* 303 */
union $428921ED9F0946DBF45D03D6A893CE6A
{
    unsigned __int8 UserApcPendingAll;
    $A85FE12DE136A601A0C0FDA7C2290F98 __s1;
};

/* 304 */
struct __declspec(align(8)) _KAPC_STATE
{
    _LIST_ENTRY ApcListHead[2];
    _KPROCESS* Process;
    $06092A4FB3F5DED584FB2155717226DA ___u2;
    unsigned __int8 KernelApcPending;
    $428921ED9F0946DBF45D03D6A893CE6A ___u4;
};

/* 360 */
struct $27C39FE7D46E5A4FF9CC918391431252
{
    unsigned __int8 ApcStateFill[43];
    char Priority;
    unsigned int UserIdealProcessor;
};

/* 361 */
union $EE4249FCF0F83B8C78BFE230B15D5120
{
    _KAPC_STATE ApcState;
    $27C39FE7D46E5A4FF9CC918391431252 __s1;
};

/* 362 */
union $23556A872AF5EC88971A227A9D961019
{
    _LIST_ENTRY WaitListEntry;
    _SINGLE_LIST_ENTRY SwapListEntry;
};

/* 307 */
union $82AE483E45A0B3B792827F62FDBFB51D
{
    _KTHREAD* Thread;
    _KQUEUE* NotificationQueue;
};

/* 308 */
struct _KWAIT_BLOCK
{
    _LIST_ENTRY WaitListEntry;
    unsigned __int8 WaitType;
    volatile unsigned __int8 BlockState;
    unsigned __int16 WaitKey;
    int SpareLong;
    $82AE483E45A0B3B792827F62FDBFB51D ___u5;
    void* Object;
    void* SparePtr;
};

/* 363 */
struct $6F75370A431B7BFF0B7D9AAB2F24EE1A
{
    unsigned __int8 WaitBlockFill4[20];
    unsigned int ContextSwitches;
};

/* 364 */
struct $B3BEF7BDBC168283DEA09510CE83D7F4
{
    unsigned __int8 WaitBlockFill5[68];
    volatile unsigned __int8 State;
    char Spare13;
    unsigned __int8 WaitIrql;
    char WaitMode;
};

/* 365 */
struct $0625A4ED2E94AAC2B93F9283FDDC7823
{
    unsigned __int8 WaitBlockFill6[116];
    unsigned int WaitTime;
};

/* 366 */
struct $7DCC36E0B5D486429C75DF67089ED0A4
{
    unsigned __int8 WaitBlockFill7[164];
    __int16 KernelApcDisable;
    __int16 SpecialApcDisable;
};

/* 367 */
struct $5329866C647E20906E999AB87303C090
{
    unsigned __int8 WaitBlockFill8[40];
    _KTHREAD_COUNTERS* ThreadCounters;
};

/* 368 */
struct $E490932347F8C5C15617FC30EA18B21A
{
    unsigned __int8 WaitBlockFill9[88];
    _XSTATE_SAVE* XStateSave;
};

/* 369 */
struct $2EC6500799AD8ACCB8991200E50A5F88
{
    unsigned __int8 WaitBlockFill10[136];
    void* volatile Win32Thread;
    _BYTE gap90[20];
    unsigned int CombinedApcDisable;
};

/* 370 */
struct $5DE84B16CDED5583B97EC842DF204E7B
{
    unsigned __int8 WaitBlockFill11[176];
    _UMS_CONTROL_BLOCK* Ucb;
    _KUMS_CONTEXT_HEADER* volatile Uch;
};

/* 371 */
union $E827B0F4487E729C79AB3B938D13D0AF
{
    _KWAIT_BLOCK WaitBlock[4];
    $6F75370A431B7BFF0B7D9AAB2F24EE1A __s1;
    $B3BEF7BDBC168283DEA09510CE83D7F4 __s2;
    $0625A4ED2E94AAC2B93F9283FDDC7823 __s3;
    $7DCC36E0B5D486429C75DF67089ED0A4 __s4;
    $5329866C647E20906E999AB87303C090 __s5;
    $E490932347F8C5C15617FC30EA18B21A __s6;
    $2EC6500799AD8ACCB8991200E50A5F88 __s7;
    $5DE84B16CDED5583B97EC842DF204E7B __s8;
};

/* 372 */
struct $7A246959401267273691882055157DF5
{
    unsigned __int32 BamQosLevel : 8;
    unsigned __int32 ThreadFlags2Reserved : 24;
};

/* 373 */
union $2C872B7AE085AA8A6F32246D89006A13
{
    volatile int ThreadFlags2;
    $7A246959401267273691882055157DF5 __s1;
};

/* 374 */
struct $A66FD9C9E5CAEF30185BA12A0EDC69A5
{
    unsigned __int32 NextProcessorNumber : 31;
    unsigned __int32 SharedReadyQueue : 1;
};

/* 375 */
union $C637B68D9D511D1B0C75A2B2C14DDD09
{
    volatile unsigned int NextProcessor;
    $A66FD9C9E5CAEF30185BA12A0EDC69A5 __s1;
};

/* 331 */
struct _GROUP_AFFINITY
{
    unsigned __int64 Mask;
    unsigned __int16 Group;
    unsigned __int16 Reserved[3];
};

/* 376 */
struct $B6CB51A1DA3434545E27A8C20E08B827
{
    unsigned __int8 UserAffinityFill[10];
    char PreviousMode;
    char BasePriority;
    char PriorityDecrement;
    unsigned __int8 Preempted;
    unsigned __int8 AdjustReason;
    char AdjustIncrement;
};

/* 377 */
struct $13A6AA75F2E82EF1A3E175DB2660A84C
{
    _BYTE gap0[12];
    unsigned __int8 ForegroundBoost : 4;
    unsigned __int8 UnusualBoost : 4;
};

/* 378 */
union $ADD9A0E3FEB7435E0A61A0D52CA0F2C3
{
    _GROUP_AFFINITY UserAffinity;
    $B6CB51A1DA3434545E27A8C20E08B827 __s1;
    $13A6AA75F2E82EF1A3E175DB2660A84C __s2;
};

/* 379 */
struct $858DB5840CCD0218D6D1AB3973B9F998
{
    unsigned __int8 AffinityFill[10];
    unsigned __int8 ApcStateIndex;
    unsigned __int8 WaitBlockCount;
    unsigned int IdealProcessor;
};

/* 380 */
union $1F1A63B96DD8DEBB328F57964544AFE0
{
    _GROUP_AFFINITY Affinity;
    $858DB5840CCD0218D6D1AB3973B9F998 __s1;
};

/* 381 */
struct $D86763B09EF7CE5906B402ED884C55FE
{
    unsigned __int8 SavedApcStateFill[43];
    unsigned __int8 WaitReason;
    char SuspendCount;
    char Saturation;
    unsigned __int16 SListFaultCount;
};

/* 382 */
union $E7085D574C2B9D9A10D68FCB2A848A7B
{
    _KAPC_STATE SavedApcState;
    $D86763B09EF7CE5906B402ED884C55FE __s1;
};

/* 333 */
struct $D11079AE0F47DB80015C8DAA9C5BB9F5
{
    unsigned __int8 CallbackDataContext : 1;
    unsigned __int8 Unused : 7;
};

/* 334 */
union $BCA888D073769386570E17FA173288E0
{
    unsigned __int8 AllFlags;
    $D11079AE0F47DB80015C8DAA9C5BB9F5 __s1;
};

/* 335 */
struct $261DF305E18FFC1F4DBE813689CE34ED
{
    void(__fastcall* KernelRoutine)(_KAPC*, void(__fastcall**)(void*, void*, void*), void**, void**, void**);
    void(__fastcall* RundownRoutine)(_KAPC*);
    void(__fastcall* NormalRoutine)(void*, void*, void*);
};

/* 336 */
union $F45DA2063BE2DB3D5441B9FA312EE00E
{
    $261DF305E18FFC1F4DBE813689CE34ED __s0;
    void* Reserved[3];
};

/* 332 */
struct __declspec(align(8)) _KAPC
{
    unsigned __int8 Type;
    $BCA888D073769386570E17FA173288E0 ___u1;
    unsigned __int8 Size;
    unsigned __int8 SpareByte1;
    unsigned int SpareLong0;
    _KTHREAD* Thread;
    _LIST_ENTRY ApcListEntry;
    $F45DA2063BE2DB3D5441B9FA312EE00E ___u7;
    void* NormalContext;
    void* SystemArgument1;
    void* SystemArgument2;
    char ApcStateIndex;
    char ApcMode;
    unsigned __int8 Inserted;
};

/* 383 */
struct $B7D851223C17C6BA83CF7063C2464C70
{
    unsigned __int8 SchedulerApcFill1[3];
    unsigned __int8 QuantumReset;
    unsigned int KernelTime;
};

/* 384 */
struct $EB095CB9D6B577FA38FA567336108011
{
    unsigned __int8 SchedulerApcFill3[64];
    _KPRCB* volatile WaitPrcb;
    void* LegoData;
};

/* 385 */
struct $3EC6920169D450C7BC757B6CC342656A
{
    unsigned __int8 SchedulerApcFill5[83];
    unsigned __int8 CallbackNestingLevel;
    unsigned int UserTime;
};

/* 386 */
union $574C2819729A183475F8EDD11E442431
{
    _KAPC SchedulerApc;
    $B7D851223C17C6BA83CF7063C2464C70 __s1;
    unsigned __int8 SchedulerApcFill2[4];
    $EB095CB9D6B577FA38FA567336108011 __s3;
    unsigned __int8 SchedulerApcFill4[72];
    $3EC6920169D450C7BC757B6CC342656A __s5;
};

/* 322 */
struct _KEVENT
{
    _DISPATCHER_HEADER Header;
};

/* 387 */
struct $716A3CB886E10601200F39772D686412
{
    _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;
    unsigned __int64 InGlobalForegroundList;
};

/* 388 */
union $27DD1780E88C1ACF4F297B5EB250D587
{
    _LIST_ENTRY GlobalForegroundListEntry;
    $716A3CB886E10601200F39772D686412 __s1;
};

/* 389 */
struct $512ADB7001AF5792636BE2A0E143DFD4
{
    unsigned __int32 ThreadFlags3Reserved : 8;
    unsigned __int32 PpmPolicy : 2;
    unsigned __int32 ThreadFlags3Reserved2 : 22;
};

/* 390 */
union $A3DF899F64B82BD2CB764A71FD95FD4C
{
    volatile int ThreadFlags3;
    $512ADB7001AF5792636BE2A0E143DFD4 __s1;
};

/* 391 */
struct $72A8711B9FC50C296E3FAFBB9C2E2A65
{
    _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry;
    unsigned __int64 InGlobalUpdateVpThreadPriorityList;
};

/* 392 */
union $A839534973A6717E093D83C1AE4DDCF5
{
    _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;
    $72A8711B9FC50C296E3FAFBB9C2E2A65 __s1;
};

/* 305 */
struct _KTHREAD
{
    _DISPATCHER_HEADER Header;
    void* SListFaultAddress;
    unsigned __int64 QuantumTarget;
    void* InitialStack;
    void* volatile StackLimit;
    void* StackBase;
    unsigned __int64 ThreadLock;
    volatile unsigned __int64 CycleTime;
    unsigned int CurrentRunTime;
    unsigned int ExpectedRunTime;
    void* KernelStack;
    _XSAVE_FORMAT* StateSaveArea;
    _KSCHEDULING_GROUP* volatile SchedulingGroup;
    _KWAIT_STATUS_REGISTER WaitRegister;
    volatile unsigned __int8 Running;
    unsigned __int8 Alerted[2];
    $2B75562D9B3CA82563345D3F63EA5F75 ___u16;
    volatile unsigned __int8 Tag;
    unsigned __int8 SystemHeteroCpuPolicy;
    unsigned __int8 UserHeteroCpuPolicy : 7;
    unsigned __int8 ExplicitSystemHeteroCpuPolicy : 1;
    unsigned __int8 Spare0;
    unsigned int SystemCallNumber;
    unsigned int ReadyTime;
    void* FirstArgument;
    _KTRAP_FRAME* TrapFrame;
    $EE4249FCF0F83B8C78BFE230B15D5120 ___u27;
    volatile __int64 WaitStatus;
    _KWAIT_BLOCK* WaitBlockList;
    $23556A872AF5EC88971A227A9D961019 ___u30;
    _DISPATCHER_HEADER* volatile Queue;
    void* Teb;
    unsigned __int64 RelativeTimerBias;
    _KTIMER Timer;
    $E827B0F4487E729C79AB3B938D13D0AF ___u35;
    $2C872B7AE085AA8A6F32246D89006A13 ___u36;
    unsigned int Spare21;
    _LIST_ENTRY QueueListEntry;
    $C637B68D9D511D1B0C75A2B2C14DDD09 ___u39;
    int QueuePriority;
    _KPROCESS* Process;
    $ADD9A0E3FEB7435E0A61A0D52CA0F2C3 ___u42;
    unsigned __int64 AffinityVersion;
    $1F1A63B96DD8DEBB328F57964544AFE0 ___u44;
    unsigned __int64 NpxState;
    $E7085D574C2B9D9A10D68FCB2A848A7B ___u46;
    $574C2819729A183475F8EDD11E442431 ___u47;
    _KEVENT SuspendEvent;
    _LIST_ENTRY ThreadListEntry;
    _LIST_ENTRY MutantListHead;
    unsigned __int8 AbEntrySummary;
    unsigned __int8 AbWaitEntryCount;
    unsigned __int8 AbAllocationRegionCount;
    char SystemPriority;
    unsigned int SecureThreadCookie;
    _KLOCK_ENTRY* LockEntries;
    _SINGLE_LIST_ENTRY PropagateBoostsEntry;
    _SINGLE_LIST_ENTRY IoSelfBoostsEntry;
    unsigned __int8 PriorityFloorCounts[16];
    unsigned __int8 PriorityFloorCountsReserved[16];
    unsigned int PriorityFloorSummary;
    volatile int AbCompletedIoBoostCount;
    volatile int AbCompletedIoQoSBoostCount;
    volatile __int16 KeReferenceCount;
    unsigned __int8 AbOrphanedEntrySummary;
    unsigned __int8 AbOwnedEntryCount;
    unsigned int ForegroundLossTime;
    $27DD1780E88C1ACF4F297B5EB250D587 ___u68;
    __int64 ReadOperationCount;
    __int64 WriteOperationCount;
    __int64 OtherOperationCount;
    __int64 ReadTransferCount;
    __int64 WriteTransferCount;
    __int64 OtherTransferCount;
    _KSCB* QueuedScb;
    volatile unsigned int ThreadTimerDelay;
    $A3DF899F64B82BD2CB764A71FD95FD4C ___u77;
    unsigned __int64 TracingPrivate[1];
    void* SchedulerAssist;
    void* volatile AbWaitObject;
    unsigned int ReservedPreviousReadyTimeValue;
    unsigned __int64 KernelWaitTime;
    unsigned __int64 UserWaitTime;
    $A839534973A6717E093D83C1AE4DDCF5 ___u84;
    int SchedulerAssistPriorityFloor;
    unsigned int Spare28;
    unsigned __int8 ResourceIndex;
    unsigned __int8 Spare31[3];
    unsigned __int64 EndPadding[4];
};

/* 397 */
struct $0546781C5EA3D12C7B8713B38AAAA7E7
{
    unsigned __int8 AffinityFill[10];
    unsigned __int16 NodeNumber;
    unsigned __int16 PrimaryNodeNumber;
    unsigned __int16 Spare0;
};

/* 398 */
union $BD8049DD66333317AF2423E6FD4079B9
{
    _GROUP_AFFINITY Affinity;
    $0546781C5EA3D12C7B8713B38AAAA7E7 __s1;
};

/* 393 */
struct _flags
{
    unsigned __int8 Removable : 1;
    unsigned __int8 GroupAssigned : 1;
    unsigned __int8 GroupCommitted : 1;
    unsigned __int8 GroupAssignmentFixed : 1;
    unsigned __int8 ProcessorOnly : 1;
    unsigned __int8 SmtSetsPresent : 1;
    unsigned __int8 Fill : 2;
};

/* 394 */
struct _KHETERO_PROCESSOR_SET
{
    unsigned __int64 IdealMask;
    unsigned __int64 PreferredMask;
    unsigned __int64 AvailableMask;
};

/* 395 */
struct $30B55DB978BF6002BB343F706FAE00D7
{
    unsigned __int64 SingleCoreSet;
    unsigned __int64 SmtSet;
};

/* 396 */
union _KQOS_GROUPING_SETS
{
    $30B55DB978BF6002BB343F706FAE00D7 __s0;
};

/* 399 */
struct _KNODE
{
    unsigned __int64 IdleNonParkedCpuSet;
    unsigned __int64 IdleSmtSet;
    unsigned __int64 NonPairedSmtSet;
    unsigned __int64 IdleCpuSet;
    __declspec(align(64)) unsigned __int64 DeepIdleSet;
    unsigned __int64 IdleConstrainedSet;
    unsigned __int64 NonParkedSet;
    unsigned __int64 SoftParkedSet;
    unsigned __int64 NonIsrTargetedSet;
    int ParkLock;
    unsigned __int16 ThreadSeed;
    unsigned __int16 ProcessSeed;
    __declspec(align(32)) unsigned int SiblingMask;
    $BD8049DD66333317AF2423E6FD4079B9 ___u13;
    unsigned __int64 SharedReadyQueueMask;
    unsigned __int64 StrideMask;
    unsigned int ProximityId;
    unsigned int Lowest;
    unsigned int Highest;
    unsigned __int8 MaximumProcessors;
    _flags Flags;
    unsigned __int8 Spare10;
    _KHETERO_PROCESSOR_SET HeteroSets[5];
    unsigned __int64 PpmConfiguredQosSets[5];
    unsigned __int64 Spare11;
    _KQOS_GROUPING_SETS QosGroupingSets;
    unsigned __int64 QosPreemptibleSet;
    unsigned __int64 LLCLeaders;
};

/* 314 */
struct _XSAVE_AREA_HEADER
{
    unsigned __int64 Mask;
    unsigned __int64 CompactionMask;
    unsigned __int64 Reserved2[6];
};

/* 414 */
struct __declspec(align(64)) _GENERAL_LOOKASIDE
{
    $8A813D4E776EFDE239FDBDB1317DE833 ___u0;
    unsigned __int16 Depth;
    unsigned __int16 MaximumDepth;
    unsigned int TotalAllocates;
    $9D02AA4AC86E49CEAF084B97B97744B1 ___u4;
    unsigned int TotalFrees;
    $4290DA71080BA5C562B380EC38D3C295 ___u6;
    _POOL_TYPE Type;
    unsigned int Tag;
    unsigned int Size;
    $3ECDF33E7806C0DE2F6C4C70AFFAAD33 ___u10;
    $71CB7496F5B7FB86694EF1216DE71F14 ___u11;
    _LIST_ENTRY ListEntry;
    unsigned int LastTotalAllocates;
    $BA67176EA55FA2D963EA02A98A2C99D2 ___u14;
    unsigned int Future[2];
};

/* 406 */
struct _LOOKASIDE_LIST_EX
{
    _GENERAL_LOOKASIDE_POOL L;
};

/* 418 */
struct _RTL_HASH_TABLE
{
    unsigned int EntryCount;
    unsigned __int32 MaskBitCount : 5;
    unsigned __int32 BucketCount : 27;
    _SINGLE_LIST_ENTRY* Buckets;
};

/* 425 */
struct __declspec(align(2)) _PROCESSOR_IDLE_CONSTRAINTS
{
    unsigned __int64 TotalTime;
    unsigned __int64 IdleTime;
    unsigned __int64 ExpectedIdleDuration;
    unsigned __int64 MaxIdleDuration;
    unsigned int OverrideState;
    unsigned int TimeCheck;
    unsigned __int8 PromotePercent;
    unsigned __int8 DemotePercent;
    unsigned __int8 Parked;
    unsigned __int8 Interruptible;
    unsigned __int8 PlatformIdle;
    unsigned __int8 ExpectedWakeReason;
    unsigned __int8 IdleStateMax;
};

/* 427 */
struct __declspec(align(8)) _PROCESSOR_IDLE_PREPARE_INFO
{
    void* Context;
    _PROCESSOR_IDLE_CONSTRAINTS Constraints;
    unsigned int DependencyCount;
    unsigned int DependencyUsed;
    _PROCESSOR_IDLE_DEPENDENCY* DependencyArray;
    unsigned int PlatformIdleStateIndex;
    unsigned int ProcessorIdleStateIndex;
    unsigned int IdleSelectFailureMask;
};

/* 429 */
struct _PPM_SELECTION_MENU
{
    unsigned int Count;
    _PPM_SELECTION_MENU_ENTRY* Entries;
};

/* 432 */
struct _PPM_COORDINATED_SELECTION
{
    unsigned int MaximumStates;
    unsigned int SelectedStates;
    unsigned int DefaultSelection;
    unsigned int* Selection;
};

/* 434 */
struct _PPM_VETO_ACCOUNTING
{
    volatile int VetoPresent;
    _LIST_ENTRY VetoListHead;
    unsigned __int8 CsAccountingBlocks;
    unsigned __int8 BlocksDrips;
    unsigned int PreallocatedVetoCount;
    _PPM_VETO_ENTRY* PreallocatedVetoList;
};

/* 435 */
struct _PPM_IDLE_STATE
{
    _KAFFINITY_EX DomainMembers;
    _UNICODE_STRING Name;
    unsigned int Latency;
    unsigned int BreakEvenDuration;
    unsigned int Power;
    unsigned int StateFlags;
    _PPM_VETO_ACCOUNTING VetoAccounting;
    unsigned __int8 StateType;
    unsigned __int8 InterruptsEnabled;
    unsigned __int8 Interruptible;
    unsigned __int8 ContextRetained;
    unsigned __int8 CacheCoherent;
    unsigned __int8 WakesSpuriously;
    unsigned __int8 PlatformOnly;
    unsigned __int8 NoCState;
};

/* 436 */
struct _PPM_IDLE_STATES
{
    unsigned __int8 InterfaceVersion;
    unsigned __int8 IdleOverride;
    unsigned __int8 EstimateIdleDuration;
    unsigned __int8 ExitLatencyTraceEnabled;
    unsigned __int8 NonInterruptibleTransition;
    unsigned __int8 UnaccountedTransition;
    unsigned __int8 IdleDurationLimited;
    unsigned __int8 IdleCheckLimited;
    unsigned __int8 StrictVetoBias;
    unsigned int ExitLatencyCountdown;
    unsigned int TargetState;
    unsigned int ActualState;
    unsigned int OldState;
    unsigned int OverrideIndex;
    unsigned int ProcessorIdleCount;
    unsigned int Type;
    unsigned __int64 LevelId;
    unsigned __int16 ReasonFlags;
    volatile unsigned __int64 InitiateWakeStamp;
    int PreviousStatus;
    unsigned int PreviousCancelReason;
    _KAFFINITY_EX PrimaryProcessorMask;
    _KAFFINITY_EX SecondaryProcessorMask;
    void(__fastcall* IdlePrepare)(_PROCESSOR_IDLE_PREPARE_INFO*);
    int(__fastcall* IdlePreExecute)(void*, unsigned int, unsigned int, unsigned int, unsigned int*);
    int(__fastcall* IdleExecute)(void*, unsigned __int64, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int*);
    unsigned int(__fastcall* IdlePreselect)(void*, _PROCESSOR_IDLE_CONSTRAINTS*);
    unsigned int(__fastcall* IdleTest)(void*, unsigned int, unsigned int);
    unsigned int(__fastcall* IdleAvailabilityCheck)(void*, unsigned int);
    void(__fastcall* IdleComplete)(void*, unsigned int, unsigned int, unsigned int, unsigned int*);
    void(__fastcall* IdleCancel)(void*, unsigned int);
    unsigned __int8(__fastcall* IdleIsHalted)(void*);
    unsigned __int8(__fastcall* IdleInitiateWake)(void*);
    _PROCESSOR_IDLE_PREPARE_INFO PrepareInfo;
    _KAFFINITY_EX DeepIdleSnapshot;
    _PERFINFO_PPM_STATE_SELECTION* Tracing;
    _PERFINFO_PPM_STATE_SELECTION* CoordinatedTracing;
    _PPM_SELECTION_MENU ProcessorMenu;
    _PPM_SELECTION_MENU CoordinatedMenu;
    _PPM_COORDINATED_SELECTION CoordinatedSelection;
    _PPM_IDLE_STATE State[1];
};

/* 437 */
struct _PPM_SELECTION_STATISTICS
{
    unsigned __int64 SelectedCount;
    unsigned __int64 VetoCount;
    unsigned __int64 PreVetoCount;
    unsigned __int64 WrongProcessorCount;
    unsigned __int64 LatencyCount;
    unsigned __int64 IdleDurationCount;
    unsigned __int64 DeviceDependencyCount;
    unsigned __int64 ProcessorDependencyCount;
    unsigned __int64 PlatformOnlyCount;
    unsigned __int64 InterruptibleCount;
    unsigned __int64 LegacyOverrideCount;
    unsigned __int64 CstateCheckCount;
    unsigned __int64 NoCStateCount;
    unsigned __int64 CoordinatedDependencyCount;
    unsigned __int64 NotClockOwnerCount;
    _PPM_VETO_ACCOUNTING* PreVetoAccounting;
};

/* 438 */
struct __declspec(align(8)) _PROC_IDLE_STATE_BUCKET
{
    unsigned __int64 TotalTime;
    unsigned __int64 MinTime;
    unsigned __int64 MaxTime;
    unsigned int Count;
};

/* 439 */
struct _PROC_IDLE_STATE_ACCOUNTING
{
    unsigned __int64 TotalTime;
    unsigned int CancelCount;
    unsigned int FailureCount;
    unsigned int SuccessCount;
    unsigned int InvalidBucketIndex;
    unsigned __int64 MinTime;
    unsigned __int64 MaxTime;
    _PPM_SELECTION_STATISTICS SelectionStatistics;
    _PROC_IDLE_STATE_BUCKET IdleTimeBuckets[26];
};

/* 440 */
struct _PROC_IDLE_ACCOUNTING
{
    unsigned int StateCount;
    unsigned int TotalTransitions;
    unsigned int ResetCount;
    unsigned int AbortCount;
    unsigned __int64 StartTime;
    unsigned __int64 PriorIdleTime;
    PPM_IDLE_BUCKET_TIME_TYPE TimeUnit;
    _PROC_IDLE_STATE_ACCOUNTING State[1];
};

/* 444 */
union $23D3264716E8BCDB05722CA6474DA032
{
    void(__fastcall* InstantaneousRead)(unsigned __int64, unsigned int*);
    void(__fastcall* DifferentialRead)(unsigned __int64, unsigned __int8, unsigned __int64*, unsigned __int64*);
};

/* 445 */
struct _PROC_FEEDBACK_COUNTER
{
    $23D3264716E8BCDB05722CA6474DA032 ___u0;
    unsigned __int64 LastActualCount;
    unsigned __int64 LastReferenceCount;
    unsigned int CachedValue;
    __declspec(align(8)) unsigned __int8 Affinitized;
    unsigned __int8 Differential;
    unsigned __int8 DiscardIdleTime;
    unsigned __int8 Scaling;
    unsigned __int64 Context;
};

/* 452 */
struct __declspec(align(4)) _PROC_PERF_QOS_CLASS_POLICY
{
    unsigned int MaxPolicyPercent;
    unsigned int MaxEquivalentFrequencyPercent;
    unsigned int MinPolicyPercent;
    unsigned int AutonomousActivityWindow;
    unsigned int EnergyPerfPreference;
    unsigned __int8 ProvideGuidance;
    unsigned __int8 AllowThrottling;
    unsigned __int8 PerfBoostMode;
    unsigned __int8 LatencyHintPerf;
    unsigned __int8 TrackDesiredCrossClass;
};

/* 450 */
struct __declspec(align(4)) _PERF_CONTROL_STATE_SELECTION
{
    unsigned __int64 SelectedState;
    unsigned int SelectedPercent;
    unsigned int SelectedFrequency;
    unsigned int MinPercent;
    unsigned int MaxPercent;
    unsigned int TolerancePercent;
    unsigned int EppPercent;
    unsigned int AutonomousActivityWindow;
    unsigned __int8 Autonomous;
    unsigned __int8 InheritFromDomain;
};

/* 453 */
struct __declspec(align(2)) _PROC_PERF_DOMAIN
{
    _LIST_ENTRY Link;
    _PROC_PERF_CHECK_CONTEXT* Master;
    _KAFFINITY_EX Members;
    unsigned __int64 DomainContext;
    unsigned int ProcessorCount;
    unsigned __int8 EfficiencyClass;
    unsigned __int8 NominalPerformanceClass;
    unsigned __int8 HighestPerformanceClass;
    _PROCESSOR_PRESENCE Presence;
    _PROC_PERF_CONSTRAINT* Processors;
    void(__fastcall* GetFFHThrottleState)(unsigned __int64*);
    void(__fastcall* TimeWindowHandler)(unsigned __int64, unsigned int);
    void(__fastcall* BoostPolicyHandler)(unsigned __int64, unsigned int);
    void(__fastcall* BoostModeHandler)(unsigned __int64, unsigned int);
    void(__fastcall* AutonomousActivityWindowHandler)(unsigned __int64, unsigned int);
    void(__fastcall* AutonomousModeHandler)(unsigned __int64, unsigned int);
    void(__fastcall* ReinitializeHandler)(unsigned __int64);
    unsigned int(__fastcall* PerfSelectionHandler)(unsigned __int64, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int*, unsigned __int64*);
    void(__fastcall* PerfControlHandler)(unsigned __int64, _PERF_CONTROL_STATE_SELECTION*, unsigned __int8, unsigned __int8);
    void(__fastcall* PerfControlHandlerHidden)(unsigned __int64, _PERF_CONTROL_STATE_SELECTION*, unsigned __int8, unsigned __int8);
    void(__fastcall* DomainPerfControlHandler)(unsigned __int64, _PERF_CONTROL_STATE_SELECTION*, unsigned __int8, unsigned __int8);
    unsigned int MaxFrequency;
    unsigned int NominalFrequency;
    unsigned int MaxPercent;
    unsigned int MinPerfPercent;
    unsigned int MinThrottlePercent;
    unsigned int AdvertizedMaximumFrequency;
    unsigned __int64 MinimumRelativePerformance;
    unsigned __int64 NominalRelativePerformance;
    unsigned __int8 NominalRelativePerformancePercent;
    unsigned __int8 Coordination;
    unsigned __int8 HardPlatformCap;
    unsigned __int8 AffinitizeControl;
    unsigned __int8 EfficientThrottle;
    unsigned __int8 AllowSchedulerDirectedPerfStates;
    unsigned __int8 InitiateAllProcessors;
    unsigned __int8 AutonomousMode;
    unsigned __int8 ProvideGuidance;
    unsigned int DesiredPercent;
    unsigned int GuaranteedPercent;
    unsigned __int8 EngageResponsivenessOverrides;
    _PROC_PERF_QOS_CLASS_POLICY QosPolicies[5];
    unsigned int QosDisableReasons[5];
    unsigned __int16 QosEquivalencyMasks[5];
    unsigned __int8 QosSupported;
    volatile unsigned int SelectionGeneration;
    _PERF_CONTROL_STATE_SELECTION QosSelection[5];
    unsigned __int64 PerfChangeTime;
    unsigned int PerfChangeIntervalCount;
    unsigned __int8 Force;
    unsigned __int8 Update;
    unsigned __int8 Apply;
};

/* 451 */
struct _PROC_PERF_CONSTRAINT
{
    _PROC_PERF_CHECK_CONTEXT* CheckContext;
    unsigned __int64 PerfContext;
    _PROCESSOR_PRESENCE Presence;
    unsigned int ProcessorId;
    unsigned int PlatformCap;
    unsigned int ThermalCap;
    unsigned int LimitReasons;
    unsigned __int64 PlatformCapStartTime;
    unsigned int ProcCap;
    unsigned int ProcFloor;
    unsigned int TargetPercent;
    unsigned __int8 EngageResponsivenessOverrides;
    unsigned __int8 ResponsivenessChangeCount;
    _PERF_CONTROL_STATE_SELECTION Selection;
    unsigned int DomainSelectionGeneration;
    unsigned int PreviousFrequency;
    unsigned int PreviousPercent;
    unsigned int LatestFrequencyPercent;
    unsigned int LatestPerformancePercent;
    unsigned __int8 Force;
    unsigned __int8 UseQosUpdateLock;
    unsigned __int64 QosUpdateLock;
};

/* 454 */
struct __declspec(align(8)) _PROC_PERF_CHECK_SNAP
{
    unsigned __int64 Time;
    unsigned __int64 Active;
    unsigned __int64 Stall;
    unsigned __int64 FrequencyScaledActive;
    unsigned __int64 PerformanceScaledActive;
    unsigned __int64 PerformanceScaledKernelActive;
    unsigned __int64 CyclesActive;
    unsigned __int64 CyclesAffinitized;
    unsigned __int64 TaggedThreadCycles[3];
    unsigned int ResponsivenessEvents;
};

/* 455 */
struct __declspec(align(8)) _PROC_PERF_CHECK
{
    unsigned __int64 LastActive;
    unsigned __int64 LastTime;
    unsigned __int64 LastStall;
    unsigned int LastResponsivenessEvents;
    _PROC_PERF_CHECK_SNAP LastPerfCheckSnap;
    _PROC_PERF_CHECK_SNAP CurrentSnap;
    _PROC_PERF_CHECK_SNAP LastDeliveredSnap;
    unsigned int LastDeliveredPerformance;
    unsigned int LastDeliveredFrequency;
    unsigned __int8 TaggedThreadPercent[3];
    unsigned __int8 Class0FloorPerfSelection;
    unsigned __int8 Class1MinimumPerfSelection;
    unsigned int CurrentResponsivenessEvents;
};

/* 456 */
struct _PROC_PERF_LOAD
{
    unsigned __int8 BusyPercentage;
    unsigned __int8 FrequencyPercentage;
};

/* 457 */
struct __declspec(align(2)) _PROC_PERF_HISTORY_ENTRY
{
    unsigned __int16 Utility;
    unsigned __int16 AffinitizedUtility;
    unsigned __int16 Frequency;
    unsigned __int8 TaggedPercent[3];
};

/* 458 */
struct __declspec(align(4)) _PROC_PERF_HISTORY
{
    unsigned int Count;
    unsigned int Slot;
    unsigned int UtilityTotal;
    unsigned int AffinitizedUtilityTotal;
    unsigned int FrequencyTotal;
    unsigned int TaggedPercentTotal[3];
    _PROC_PERF_HISTORY_ENTRY HistoryList[1];
};

/* 459 */
struct _PPM_CONCURRENCY_ACCOUNTING
{
    unsigned __int64 Lock;
    unsigned int Processors;
    unsigned int ActiveProcessors;
    unsigned __int64 LastUpdateTime;
    unsigned __int64 TotalTime;
    unsigned __int64 AccumulatedTime[1];
};

/* 464 */
struct _PEBS_DS_SAVE_AREA32
{
    unsigned int BtsBufferBase;
    unsigned int BtsIndex;
    unsigned int BtsAbsoluteMaximum;
    unsigned int BtsInterruptThreshold;
    unsigned int PebsBufferBase;
    unsigned int PebsIndex;
    unsigned int PebsAbsoluteMaximum;
    unsigned int PebsInterruptThreshold;
    unsigned __int64 PebsGpCounterReset[8];
    unsigned __int64 PebsFixedCounterReset[4];
};

/* 465 */
struct _PEBS_DS_SAVE_AREA64
{
    unsigned __int64 BtsBufferBase;
    unsigned __int64 BtsIndex;
    unsigned __int64 BtsAbsoluteMaximum;
    unsigned __int64 BtsInterruptThreshold;
    unsigned __int64 PebsBufferBase;
    unsigned __int64 PebsIndex;
    unsigned __int64 PebsAbsoluteMaximum;
    unsigned __int64 PebsInterruptThreshold;
    unsigned __int64 PebsGpCounterReset[8];
    unsigned __int64 PebsFixedCounterReset[4];
};

/* 466 */
union $C279089FBA11F79AEFEB7A81775251C2
{
    _PEBS_DS_SAVE_AREA32 As32Bit;
    _PEBS_DS_SAVE_AREA64 As64Bit;
};

/* 467 */
struct _PEBS_DS_SAVE_AREA
{
    $C279089FBA11F79AEFEB7A81775251C2 ___u0;
};

/* 468 */
struct _PROCESSOR_PROFILE_CONTROL_AREA
{
    _PEBS_DS_SAVE_AREA PebsDsSaveArea;
};

/* 315 */
struct _XSAVE_AREA
{
    _XSAVE_FORMAT LegacyState;
    _XSAVE_AREA_HEADER Header;
};

/* 269 */
struct $6FAEF29703B46FE98A6AEC7A76F7EDDE
{
    unsigned __int16 Weight;
    unsigned __int16 MaxRate;
};

/* 270 */
union $DCCDB5956D88B4D2086C669B8E300D38
{
    unsigned int Value;
    $6FAEF29703B46FE98A6AEC7A76F7EDDE __s1;
    unsigned __int16 MinRate;
};

/* 271 */
struct $DD3BF4DB80F86D830756FEADC1CBB3C9
{
    unsigned __int32 Type : 1;
    unsigned __int32 Disabled : 1;
    unsigned __int32 RankBias : 1;
    unsigned __int32 Spare1 : 29;
};

/* 272 */
union $64C6926B1302A0067EE93D22A94DA19D
{
    unsigned int AllFlags;
    $DD3BF4DB80F86D830756FEADC1CBB3C9 __s1;
};

/* 273 */
struct _KSCHEDULING_GROUP_POLICY
{
    $DCCDB5956D88B4D2086C669B8E300D38 ___u0;
    $64C6926B1302A0067EE93D22A94DA19D ___u1;
};

/* 279 */
union $5AD224564FA2322E14222BE62EE4AB1C
{
    _LIST_ENTRY SchedulingGroupList;
    _LIST_ENTRY Sibling;
};

/* 278 */
struct _KSCB
{
    unsigned __int64 GenerationCycles;
    unsigned __int64 MinQuotaCycleTarget;
    unsigned __int64 MaxQuotaCycleTarget;
    unsigned __int64 RankCycleTarget;
    unsigned __int64 LongTermCycles;
    unsigned __int64 LastReportedCycles;
    volatile unsigned __int64 OverQuotaHistory;
    unsigned __int64 ReadyTime;
    unsigned __int64 InsertTime;
    _LIST_ENTRY PerProcessorList;
    _RTL_BALANCED_NODE QueueNode;
    unsigned __int8 Inserted : 1;
    unsigned __int8 MaxOverQuota : 1;
    unsigned __int8 MinOverQuota : 1;
    unsigned __int8 RankBias : 1;
    unsigned __int8 SoftCap : 1;
    unsigned __int8 ShareRankOwner : 1;
    unsigned __int8 Spare1 : 2;
    unsigned __int8 Depth;
    unsigned __int16 ReadySummary;
    unsigned int Rank;
    volatile unsigned int* ShareRank;
    volatile unsigned int OwnerShareRank;
    _LIST_ENTRY ReadyListHead[16];
    _RTL_RB_TREE ChildScbQueue;
    _KSCB* Parent;
    _KSCB* Root;
};

/* 277 */
struct _KSCHEDULING_GROUP
{
    _KSCHEDULING_GROUP_POLICY Policy;
    unsigned int RelativeWeight;
    unsigned int ChildMinRate;
    unsigned int ChildMinWeight;
    unsigned int ChildTotalWeight;
    unsigned __int64 QueryHistoryTimeStamp;
    __int64 NotificationCycles;
    __int64 MaxQuotaLimitCycles;
    volatile __int64 MaxQuotaCyclesRemaining;
    $5AD224564FA2322E14222BE62EE4AB1C ___u9;
    _KDPC* NotificationDpc;
    _LIST_ENTRY ChildList;
    _KSCHEDULING_GROUP* Parent;
    __declspec(align(32)) _KSCB PerProcessor[1];
};

/* 282 */
union $0A5B921805314784846D9B1A1C65E0B8
{
    char PreviousMode;
    unsigned __int8 InterruptRetpolineState;
};

/* 283 */
union $E1E85BDFF120969F243E40972FB7AAD0
{
    unsigned __int8 FaultIndicator;
    unsigned __int8 NmiMsrIbrs;
};

/* 284 */
union $8F6355D5F60D214191165731D383CB8C
{
    unsigned __int64 GsBase;
    unsigned __int64 GsSwap;
};

/* 285 */
union $7C5DE26D70D5BE3946A1648545D65AE0
{
    unsigned __int64 FaultAddress;
    unsigned __int64 ContextRecord;
};

/* 286 */
struct $4574AE3E4BAE34DEE7E0FCA2C1C2BD66
{
    unsigned int NmiPreviousSpecCtrl;
    unsigned int NmiPreviousSpecCtrlPad;
};

/* 287 */
union $8764F81CD454ECE1B9C0BFEFFFF63173
{
    $4574AE3E4BAE34DEE7E0FCA2C1C2BD66 __s0;
    unsigned __int64 Rbx;
};

/* 288 */
union $70C7D383085E14057A40B90B0C71A2A2
{
    unsigned __int64 ErrorCode;
    unsigned __int64 ExceptionFrame;
};

/* 289 */
struct _KTRAP_FRAME
{
    unsigned __int64 P1Home;
    unsigned __int64 P2Home;
    unsigned __int64 P3Home;
    unsigned __int64 P4Home;
    unsigned __int64 P5;
    $0A5B921805314784846D9B1A1C65E0B8 ___u5;
    unsigned __int8 PreviousIrql;
    $E1E85BDFF120969F243E40972FB7AAD0 ___u7;
    unsigned __int8 ExceptionActive;
    unsigned int MxCsr;
    unsigned __int64 Rax;
    unsigned __int64 Rcx;
    unsigned __int64 Rdx;
    unsigned __int64 R8;
    unsigned __int64 R9;
    unsigned __int64 R10;
    unsigned __int64 R11;
    $8F6355D5F60D214191165731D383CB8C ___u17;
    _M128A Xmm0;
    _M128A Xmm1;
    _M128A Xmm2;
    _M128A Xmm3;
    _M128A Xmm4;
    _M128A Xmm5;
    $7C5DE26D70D5BE3946A1648545D65AE0 ___u24;
    unsigned __int64 Dr0;
    unsigned __int64 Dr1;
    unsigned __int64 Dr2;
    unsigned __int64 Dr3;
    unsigned __int64 Dr6;
    unsigned __int64 Dr7;
    unsigned __int64 DebugControl;
    unsigned __int64 LastBranchToRip;
    unsigned __int64 LastBranchFromRip;
    unsigned __int64 LastExceptionToRip;
    unsigned __int64 LastExceptionFromRip;
    unsigned __int16 SegDs;
    unsigned __int16 SegEs;
    unsigned __int16 SegFs;
    unsigned __int16 SegGs;
    unsigned __int64 TrapFrame;
    $8764F81CD454ECE1B9C0BFEFFFF63173 ___u41;
    unsigned __int64 Rdi;
    unsigned __int64 Rsi;
    unsigned __int64 Rbp;
    $70C7D383085E14057A40B90B0C71A2A2 ___u45;
    unsigned __int64 Rip;
    unsigned __int16 SegCs;
    unsigned __int8 Fill0;
    unsigned __int8 Logging;
    unsigned __int16 Fill1[2];
    unsigned int EFlags;
    unsigned int Fill2;
    unsigned __int64 Rsp;
    unsigned __int16 SegSs;
    unsigned __int16 Fill3;
    unsigned int Fill4;
};

/* 295 */
struct $96CD4C94BAF617C0075F34B41386C5E3
{
    unsigned __int32 AutoAlignment : 1;
    unsigned __int32 DisableBoost : 1;
    unsigned __int32 DisableQuantum : 1;
    unsigned __int32 DeepFreeze : 1;
    unsigned __int32 TimerVirtualization : 1;
    unsigned __int32 CheckStackExtents : 1;
    unsigned __int32 CacheIsolationEnabled : 1;
    unsigned __int32 PpmPolicy : 3;
    unsigned __int32 VaSpaceDeleted : 1;
    unsigned __int32 ReservedFlags : 21;
};

/* 296 */
union $B6F007C06BECAFC39560EB5F9FEC4D72
{
    $96CD4C94BAF617C0075F34B41386C5E3 __s0;
    volatile int ProcessFlags;
};

/* 291 */
struct $0C2F1B0043396E6CDBDB29D72BF92FF3
{
    unsigned __int8 ExecuteDisable : 1;
    unsigned __int8 ExecuteEnable : 1;
    unsigned __int8 DisableThunkEmulation : 1;
    unsigned __int8 Permanent : 1;
    unsigned __int8 ExecuteDispatchEnable : 1;
    unsigned __int8 ImageDispatchEnable : 1;
    unsigned __int8 DisableExceptionChainValidation : 1;
    unsigned __int8 Spare : 1;
};

/* 292 */
union _KEXECUTE_OPTIONS
{
    $0C2F1B0043396E6CDBDB29D72BF92FF3 __s0;
    volatile unsigned __int8 ExecuteOptions;
    unsigned __int8 ExecuteOptionsNV;
};

/* 293 */
struct $1855273A941156425EBA8D11C2577346
{
    unsigned __int32 State : 3;
    unsigned __int32 StackCount : 29;
};

/* 294 */
volatile union _KSTACK_COUNT
{
    int Value;
    $1855273A941156425EBA8D11C2577346 __s1;
};

/* 298 */
struct $B54147CEEB143972DCA10BB1F637AA9B
{
    unsigned __int64 SecureProcess : 1;
    unsigned __int64 Unused : 1;
};

/* 299 */
union $7E7EDC83FD0AB33F86EB2AA0B8C764A3
{
    unsigned __int64 SecureHandle;
    $B54147CEEB143972DCA10BB1F637AA9B Flags;
};

/* 297 */
struct _KPROCESS
{
    _DISPATCHER_HEADER Header;
    _LIST_ENTRY ProfileListHead;
    unsigned __int64 DirectoryTableBase;
    _LIST_ENTRY ThreadListHead;
    unsigned int ProcessLock;
    unsigned int ProcessTimerDelay;
    unsigned __int64 DeepFreezeStartTime;
    _KAFFINITY_EX Affinity;
    unsigned __int64 AffinityPadding[12];
    _LIST_ENTRY ReadyListHead;
    _SINGLE_LIST_ENTRY SwapListEntry;
    volatile _KAFFINITY_EX ActiveProcessors;
    unsigned __int64 ActiveProcessorsPadding[12];
    $B6F007C06BECAFC39560EB5F9FEC4D72 ___u13;
    unsigned int ActiveGroupsMask;
    char BasePriority;
    char QuantumReset;
    char Visited;
    _KEXECUTE_OPTIONS Flags;
    unsigned __int16 ThreadSeed[20];
    unsigned __int16 ThreadSeedPadding[12];
    unsigned __int16 IdealProcessor[20];
    unsigned __int16 IdealProcessorPadding[12];
    unsigned __int16 IdealNode[20];
    unsigned __int16 IdealNodePadding[12];
    unsigned __int16 IdealGlobalNode;
    unsigned __int16 Spare1;
    volatile _KSTACK_COUNT StackCount;
    _LIST_ENTRY ProcessListEntry;
    unsigned __int64 CycleTime;
    unsigned __int64 ContextSwitches;
    _KSCHEDULING_GROUP* SchedulingGroup;
    unsigned int FreezeCount;
    unsigned int KernelTime;
    unsigned int UserTime;
    unsigned int ReadyTime;
    unsigned __int64 UserDirectoryTableBase;
    unsigned __int8 AddressPolicy;
    unsigned __int8 Spare2[71];
    void* InstrumentationCallback;
    $7E7EDC83FD0AB33F86EB2AA0B8C764A3 SecureState;
    unsigned __int64 KernelWaitTime;
    unsigned __int64 UserWaitTime;
    unsigned __int64 EndPadding[8];
};

/* 306 */
struct _KQUEUE
{
    _DISPATCHER_HEADER Header;
    _LIST_ENTRY EntryListHead;
    volatile unsigned int CurrentCount;
    unsigned int MaximumCount;
    _LIST_ENTRY ThreadListHead;
};

/* 310 */
struct _COUNTER_READING
{
    _HARDWARE_COUNTER_TYPE Type;
    unsigned int Index;
    unsigned __int64 Start;
    unsigned __int64 Total;
};

/* 312 */
struct _KTHREAD_COUNTERS
{
    unsigned __int64 WaitReasonBitMap;
    _THREAD_PERFORMANCE_DATA* UserData;
    unsigned int Flags;
    unsigned int ContextSwitches;
    unsigned __int64 CycleTimeBias;
    unsigned __int64 HardwareCounters;
    _COUNTER_READING HwCounter[16];
};

/* 316 */
struct _XSTATE_CONTEXT
{
    unsigned __int64 Mask;
    unsigned int Length;
    unsigned int Reserved1;
    _XSAVE_AREA* Area;
    void* Buffer;
};

/* 313 */
struct _XSTATE_SAVE
{
    _XSTATE_SAVE* Prev;
    _KTHREAD* Thread;
    unsigned __int8 Level;
    _XSTATE_CONTEXT XStateContext;
};

/* 323 */
#pragma pack(push, 1)
struct $354794490B8CB5E8F1473663AC0EADBB
{
    _KQUEUE* UmsAssociatedQueue;
    _LIST_ENTRY* UmsQueueListEntry;
    _KEVENT UmsWaitEvent;
    void* StagingArea;
    unsigned __int32 UmsPrimaryDeliveredContext : 1;
    unsigned __int32 UmsAssociatedQueueUsed : 1;
    unsigned __int32 UmsThreadParked : 1;
};
#pragma pack(pop)

/* 324 */
struct $5EA0C70E23C9E7CD094CA86E0793CB2A
{
    _BYTE gap0[48];
    unsigned int UmsFlags;
};

/* 325 */
union $11C80353EDF72A1F1C470E08883C5936
{
    _KQUEUE UmsQueue;
    $354794490B8CB5E8F1473663AC0EADBB __s1;
    $5EA0C70E23C9E7CD094CA86E0793CB2A __s2;
};

/* 326 */
struct _UMS_CONTROL_BLOCK
{
    _RTL_UMS_CONTEXT* UmsContext;
    _SINGLE_LIST_ENTRY* CompletionListEntry;
    _KEVENT* CompletionListEvent;
    unsigned int ServiceSequenceNumber;
    $11C80353EDF72A1F1C470E08883C5936 ___u4;
    _LIST_ENTRY QueueEntry;
    _RTL_UMS_CONTEXT* YieldingUmsContext;
    void* YieldingParam;
    void* UmsTeb;
};

/* 328 */
struct $6C44F11E89E9D437446E352FCF63E4B7
{
    unsigned __int64 Volatile : 1;
    unsigned __int64 Reserved : 63;
};

/* 329 */
union $FCFF5FA5F3E0C299E41DFE9C3564BC31
{
    $6C44F11E89E9D437446E352FCF63E4B7 __s0;
    unsigned __int64 Flags;
};

/* 330 */
struct _KUMS_CONTEXT_HEADER
{
    unsigned __int64 P1Home;
    unsigned __int64 P2Home;
    unsigned __int64 P3Home;
    unsigned __int64 P4Home;
    void* StackTop;
    unsigned __int64 StackSize;
    unsigned __int64 RspOffset;
    unsigned __int64 Rip;
    _XSAVE_FORMAT* FltSave;
    $FCFF5FA5F3E0C299E41DFE9C3564BC31 ___u9;
    _KTRAP_FRAME* TrapFrame;
    _KEXCEPTION_FRAME* ExceptionFrame;
    _KTHREAD* SourceThread;
    unsigned __int64 Return;
};

/* 346 */
union $BD7A38761429CE4927EDF14A31C43B69
{
    _RTL_BALANCED_NODE TreeNode;
    _SINGLE_LIST_ENTRY FreeListEntry;
};

/* 347 */
struct $EC07B23C3B7FAD634FE04CB02D3D38F8
{
    unsigned __int8 EntryOffset;
    unsigned __int8 ThreadLocalFlags;
    unsigned __int8 AcquiredByte;
    unsigned __int8 CrossThreadFlags;
};

/* 348 */
struct $32E3ABB8933517212EA7444AD29C7511
{
    unsigned __int32 StaticState : 8;
    unsigned __int32 WaitingBit : 1;
    unsigned __int32 Spare0 : 7;
    unsigned __int32 AcquiredBit : 1;
    unsigned __int32 : 7;
    unsigned __int32 HeadNodeBit : 1;
    unsigned __int32 IoPriorityBit : 1;
    unsigned __int32 IoQoSWaiter : 1;
    unsigned __int32 Spare1 : 5;
};

/* 349 */
struct $D148E6096860B0BA0391DF1ED7A6C924
{
    unsigned __int32 : 8;
    unsigned __int32 AllFlags : 24;
};

/* 350 */
union $CFF4A84497F34EBD881C0A0A873125C5
{
    unsigned int EntryFlags;
    $EC07B23C3B7FAD634FE04CB02D3D38F8 __s1;
    $32E3ABB8933517212EA7444AD29C7511 __s2;
    $D148E6096860B0BA0391DF1ED7A6C924 __s3;
};

/* 338 */
struct $A1A49EE4C6E599293708B9EDC35F5B5E
{
    unsigned __int64 CrossThreadReleasable : 1;
    unsigned __int64 Busy : 1;
    unsigned __int64 Reserved : 61;
    unsigned __int64 InTree : 1;
};

/* 339 */
union $CEC8DFAA11A109A40E1B8A87886CF00F
{
    $A1A49EE4C6E599293708B9EDC35F5B5E __s0;
    void* LockState;
};

/* 340 */
struct $3D3B8FE0BB28675FF9A69FDF4E0F0C17
{
    unsigned int SessionId;
    unsigned int SessionPad;
};

/* 341 */
union $F19B6670A787D26F51608A6A5941E8F5
{
    void* SessionState;
    $3D3B8FE0BB28675FF9A69FDF4E0F0C17 __s1;
};

/* 342 */
struct _KLOCK_ENTRY_LOCK_STATE
{
    $CEC8DFAA11A109A40E1B8A87886CF00F ___u0;
    $F19B6670A787D26F51608A6A5941E8F5 ___u1;
};

/* 351 */
struct $B44277A236BA2515446CFE9D2BD19FA1
{
    void* volatile LockUnsafe;
    void* SessionState;
};

/* 352 */
struct $A60C83F7E7D4D797BA8C6A44D96D42F2
{
    volatile unsigned __int8 CrossThreadReleasableAndBusyByte;
    unsigned __int8 Reserved[6];
    volatile unsigned __int8 InTreeByte;
    unsigned int SessionId;
    unsigned int SessionPad;
};

/* 353 */
union $183542E1131AB1D7DC0ACF6E7958CDB0
{
    _KLOCK_ENTRY_LOCK_STATE LockState;
    $B44277A236BA2515446CFE9D2BD19FA1 __s1;
    $A60C83F7E7D4D797BA8C6A44D96D42F2 __s2;
};

/* 354 */
union $9A302699601495C16C9824CE2E51BEF7
{
    _RTL_RB_TREE OwnerTree;
    char CpuPriorityKey;
};

/* 343 */
struct $985BA4769A85FD4AE85CD88F5E2D6C9B
{
    unsigned __int32 AllBoosts : 17;
    unsigned __int32 Reserved : 15;
};

/* 344 */
struct $3FFCD8F9FD83D2CCCD4C5C5A1C244794
{
    unsigned __int16 CpuBoostsBitmap : 15;
    unsigned __int16 IoBoost : 1;
    unsigned __int16 IoQoSBoost : 1;
    unsigned __int16 IoNormalPriorityWaiterCount : 8;
    unsigned __int16 IoQoSWaiterCount : 7;
};

/* 345 */
union _KLOCK_ENTRY_BOOST_BITMAP
{
    unsigned int AllFields;
    $985BA4769A85FD4AE85CD88F5E2D6C9B __s1;
    $3FFCD8F9FD83D2CCCD4C5C5A1C244794 __s2;
};

/* 355 */
struct _KLOCK_ENTRY
{
    $BD7A38761429CE4927EDF14A31C43B69 ___u0;
    $CFF4A84497F34EBD881C0A0A873125C5 ___u1;
    unsigned int SpareFlags;
    $183542E1131AB1D7DC0ACF6E7958CDB0 ___u3;
    $9A302699601495C16C9824CE2E51BEF7 ___u4;
    _RTL_RB_TREE WaiterTree;
    unsigned __int64 EntryLock;
    _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;
    unsigned int SparePad;
};

/* 426 */
struct __declspec(align(2)) _PROCESSOR_IDLE_DEPENDENCY
{
    unsigned int ProcessorIndex;
    unsigned __int8 ExpectedState;
    unsigned __int8 AllowDeeperStates;
    unsigned __int8 LooseDependency;
};

/* 428 */
struct _PERFINFO_PPM_STATE_SELECTION
{
    unsigned int SelectedState;
    unsigned int VetoedStates;
    unsigned int VetoReason[1];
};

/* 431 */
struct _PPM_SELECTION_MENU_ENTRY
{
    unsigned __int8 StrictDependency;
    unsigned __int8 InitiatingState;
    unsigned __int8 DependentState;
    unsigned int StateIndex;
    unsigned int Dependencies;
    _PPM_SELECTION_DEPENDENCY* DependencyList;
};

/* 433 */
struct _PPM_VETO_ENTRY
{
    _LIST_ENTRY Link;
    unsigned int VetoReason;
    unsigned int ReferenceCount;
    unsigned __int64 HitCount;
    unsigned __int64 LastActivationTime;
    unsigned __int64 TotalActiveTime;
    unsigned __int64 CsActivationTime;
    unsigned __int64 CsActiveTime;
};

/* 311 */
struct _THREAD_PERFORMANCE_DATA
{
    unsigned __int16 Size;
    unsigned __int16 Version;
    _PROCESSOR_NUMBER ProcessorNumber;
    unsigned int ContextSwitches;
    unsigned int HwCountersCount;
    volatile unsigned __int64 UpdateCount;
    unsigned __int64 WaitReasonBitMap;
    unsigned __int64 HardwareCounters;
    _COUNTER_READING CycleTime;
    _COUNTER_READING HwCounters[16];
};

/* 318 */
struct $EE958A3EEEF3B432DBF345C9EA16AB2C
{
    unsigned __int32 ScheduledThread : 1;
    unsigned __int32 Suspended : 1;
    unsigned __int32 VolatileContext : 1;
    unsigned __int32 Terminated : 1;
    unsigned __int32 DebugActive : 1;
    unsigned __int32 RunningOnSelfThread : 1;
    unsigned __int32 DenyRunningOnSelfThread : 1;
};

/* 319 */
union $5F81BD2CC11135F53CAB612413735728
{
    $EE958A3EEEF3B432DBF345C9EA16AB2C __s0;
    volatile int Flags;
};

/* 320 */
struct $F0BB6DED5B863CB5C1D5B6781ED3F5BA
{
    unsigned __int64 KernelUpdateLock : 2;
    unsigned __int64 PrimaryClientID : 62;
};

/* 321 */
union $856A22AFCF5F0A13F3C4FB098A483123
{
    $F0BB6DED5B863CB5C1D5B6781ED3F5BA __s0;
    volatile unsigned __int64 ContextLock;
};

/* 317 */
struct __declspec(align(16)) _RTL_UMS_CONTEXT
{
    _SINGLE_LIST_ENTRY Link;
    _CONTEXT Context;
    void* Teb;
    void* UserContext;
    $5F81BD2CC11135F53CAB612413735728 ___u4;
    $856A22AFCF5F0A13F3C4FB098A483123 ___u5;
    _RTL_UMS_CONTEXT* PrimaryUmsContext;
    unsigned int SwitchCount;
    unsigned int KernelYieldCount;
    unsigned int MixedYieldCount;
    unsigned int YieldCount;
};

/* 327 */
struct _KEXCEPTION_FRAME
{
    unsigned __int64 P1Home;
    unsigned __int64 P2Home;
    unsigned __int64 P3Home;
    unsigned __int64 P4Home;
    unsigned __int64 P5;
    unsigned __int64 Spare1;
    _M128A Xmm6;
    _M128A Xmm7;
    _M128A Xmm8;
    _M128A Xmm9;
    _M128A Xmm10;
    _M128A Xmm11;
    _M128A Xmm12;
    _M128A Xmm13;
    _M128A Xmm14;
    _M128A Xmm15;
    unsigned __int64 TrapFrame;
    unsigned __int64 OutputBuffer;
    unsigned __int64 OutputLength;
    unsigned __int64 Spare2;
    unsigned __int64 MxCsr;
    unsigned __int64 Rbp;
    unsigned __int64 Rbx;
    unsigned __int64 Rdi;
    unsigned __int64 Rsi;
    unsigned __int64 R12;
    unsigned __int64 R13;
    unsigned __int64 R14;
    unsigned __int64 R15;
    unsigned __int64 Return;
};

/* 430 */
struct _PPM_SELECTION_DEPENDENCY
{
    unsigned int Processor;
    _PPM_SELECTION_MENU Menu;
};

/* 358 */
struct $6E3F65CE18CC0B6AF3187BA21BE00A71
{
    unsigned __int32 : 2;
    unsigned __int32 AutoAlignment : 1;
    unsigned __int32 DisableBoost : 1;
    unsigned __int32 AlertedByThreadId : 1;
    unsigned __int32 QuantumDonation : 1;
    unsigned __int32 EnableStackSwap : 1;
    unsigned __int32 GuiThread : 1;
    unsigned __int32 DisableQuantum : 1;
    unsigned __int32 ChargeOnlySchedulingGroup : 1;
    unsigned __int32 DeferPreemption : 1;
    unsigned __int32 QueueDeferPreemption : 1;
    unsigned __int32 ForceDeferSchedule : 1;
    unsigned __int32 SharedReadyQueueAffinity : 1;
    unsigned __int32 FreezeCount : 1;
    unsigned __int32 TerminationApcRequest : 1;
    unsigned __int32 AutoBoostEntriesExhausted : 1;
    unsigned __int32 KernelStackResident : 1;
    unsigned __int32 TerminateRequestReason : 2;
    unsigned __int32 ProcessStackCountDecremented : 1;
    unsigned __int32 RestrictedGuiThread : 1;
    unsigned __int32 VpBackingThread : 1;
    unsigned __int32 ThreadFlagsSpare2 : 1;
    unsigned __int32 EtwStackTraceApcInserted : 8;
};

/* 359 */
union $56EB84CB2F609DB32F48EF5AF14EA933
{
    volatile int ThreadFlags;
    $6E3F65CE18CC0B6AF3187BA21BE00A71 __s1;
};

/* 504 */
struct _KFLOATING_SAVE
{
    unsigned int Dummy;
};

/* 505 */
struct $1DDC6B752DFFEE23147D3F7F53435B3B
{
    unsigned __int64 Pcid : 12;
    unsigned __int64 Reserved : 52;
};

/* 506 */
union $3E0858FAD33CF38B83F42C461981611F
{
    $1DDC6B752DFFEE23147D3F7F53435B3B __s0;
    unsigned __int64 EntirePcid;
};

/* 508 */
struct $D6321051E7D3927D2904B1E5AED8D260
{
    $3E0858FAD33CF38B83F42C461981611F ___u0;
    unsigned __int64 Virtual;
};

/* 509 */
struct $57BE736F4ADF9883DA678639FB040E89
{
    $3E0858FAD33CF38B83F42C461981611F ___u0;
    unsigned __int64 Reserved2;
};

/* 510 */
struct $683BA59AA4A1BF37711593DF073D8EC3
{
    unsigned __int64 Reserved[2];
};

/* 507 */
union _INVPCID_DESCRIPTOR
{
    $D6321051E7D3927D2904B1E5AED8D260 IndividualAddress;
    $57BE736F4ADF9883DA678639FB040E89 SingleContext;
    $683BA59AA4A1BF37711593DF073D8EC3 AllContextAndGlobals;
    $683BA59AA4A1BF37711593DF073D8EC3 AllContext;
};

/* 511 */
struct _SINGLE_LIST_ENTRY32
{
    unsigned int Next;
};

/* 512 */
struct _EXT_SET_PARAMETERS_V0
{
    unsigned int Version;
    unsigned int Reserved;
    __int64 NoWakeTolerance;
};

/* 513 */
struct $7CD1C28D37C5EB08109D31C3EA4A814A
{
    unsigned __int8 Trustlet : 1;
    unsigned __int8 Ntos : 1;
    unsigned __int8 WriteHandle : 1;
    unsigned __int8 ReadHandle : 1;
    unsigned __int8 Reserved : 4;
};

/* 514 */
union _PS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS
{
    $7CD1C28D37C5EB08109D31C3EA4A814A __s0;
    unsigned __int8 AccessRights;
};

/* 515 */
struct $02750328EA0807973E76A1BE04E82206
{
    unsigned __int8 Version;
    unsigned __int8 DataCount;
    unsigned __int8 SemanticType;
    _PS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS AccessRights;
};

/* 516 */
union $5355D8F7DDFBBE269F048C94EB8427A7
{
    $02750328EA0807973E76A1BE04E82206 __s0;
    unsigned int AttributeType;
};

/* 517 */
struct _PS_TRUSTLET_ATTRIBUTE_TYPE
{
    $5355D8F7DDFBBE269F048C94EB8427A7 ___u0;
};

/* 518 */
struct _PS_TRUSTLET_ATTRIBUTE_HEADER
{
    _PS_TRUSTLET_ATTRIBUTE_TYPE AttributeType;
    unsigned __int32 InstanceNumber : 8;
    unsigned __int32 Reserved : 24;
};

/* 519 */
struct _PS_TRUSTLET_ATTRIBUTE_DATA
{
    _PS_TRUSTLET_ATTRIBUTE_HEADER Header;
    unsigned __int64 Data[1];
};

/* 520 */
struct _PS_TRUSTLET_CREATE_ATTRIBUTES
{
    unsigned __int64 TrustletIdentity;
    _PS_TRUSTLET_ATTRIBUTE_DATA Attributes[1];
};

/* 521 */
struct _TRUSTLET_MAILBOX_KEY
{
    unsigned __int64 SecretValue[2];
};

/* 522 */
struct _TRUSTLET_COLLABORATION_ID
{
    unsigned __int64 Value[2];
};

/* 523 */
struct _KERNEL_STACK_SEGMENT
{
    unsigned __int64 StackBase;
    unsigned __int64 StackLimit;
    unsigned __int64 KernelStack;
    unsigned __int64 InitialStack;
};

/* 524 */
struct $340F835BEAD91BC7101C77A06ADEC28E
{
    unsigned __int64 StackExpansion : 1;
};

/* 525 */
union $88F1732808335EBCB85AEA95F206B32C
{
    unsigned __int64 ActualLimit;
    $340F835BEAD91BC7101C77A06ADEC28E __s1;
};

/* 526 */
struct _KSTACK_CONTROL
{
    unsigned __int64 StackBase;
    $88F1732808335EBCB85AEA95F206B32C ___u1;
    _KERNEL_STACK_SEGMENT Previous;
};

/* 527 */
struct __declspec(align(8)) _FAST_MUTEX
{
    int Count;
    void* Owner;
    unsigned int Contention;
    _KEVENT Event;
    unsigned int OldIrql;
};

/* 528 */
struct __declspec(align(16)) _SLIST_ENTRY
{
    _SLIST_ENTRY* Next;
};

/* 529 */
struct _NPAGED_LOOKASIDE_LIST
{
    _GENERAL_LOOKASIDE L;
};

/* 530 */
struct _PAGED_LOOKASIDE_LIST
{
    _GENERAL_LOOKASIDE L;
};

/* 531 */
union $250F5FE22B4503EFD7D48C86CC7F2167
{
    int Status;
    void* Pointer;
};

/* 532 */
struct _IO_STATUS_BLOCK
{
    $250F5FE22B4503EFD7D48C86CC7F2167 ___u0;
    unsigned __int64 Information;
};

/* 533 */
union $A28C18850CF3D184BADE16FA41548AB0
{
    __int64 UseThisFieldToCopy;
    long double DoNotUseThisField;
};

/* 534 */
struct _QUAD
{
    $A28C18850CF3D184BADE16FA41548AB0 ___u0;
};

/* 535 */
struct _WORK_QUEUE_ITEM
{
    _LIST_ENTRY List;
    void(__fastcall* WorkerRoutine)(void*);
    void* Parameter;
};

/* 536 */
struct _EXT_DELETE_PARAMETERS
{
    unsigned int Version;
    unsigned int Reserved;
    void(__fastcall* DeleteCallback)(void*);
    void* DeleteContext;
};

/* 537 */
struct $2F38BEDF952D5DA5F266621B11247D04
{
    unsigned __int64 Locked : 1;
    unsigned __int64 Waiting : 1;
    unsigned __int64 Waking : 1;
    unsigned __int64 MultipleShared : 1;
    unsigned __int64 Shared : 60;
};

/* 538 */
union $67516065B9352D64FC65CE98DA8F0107
{
    $2F38BEDF952D5DA5F266621B11247D04 __s0;
    unsigned __int64 Value;
    void* Ptr;
};

/* 539 */
struct _EX_PUSH_LOCK
{
    $67516065B9352D64FC65CE98DA8F0107 ___u0;
};

/* 540 */
struct __declspec(align(64)) _ENODE
{
    _KNODE Ncb;
    _WORK_QUEUE_ITEM HotAddProcessorWorkItem;
};

/* 541 */
union $888B7D2A033403A4DF437269584615CD
{
    unsigned __int64 Count;
    void* Ptr;
};

/* 542 */
struct _EX_RUNDOWN_REF
{
    $888B7D2A033403A4DF437269584615CD ___u0;
};

/* 543 */
struct $4DC8F54BDA4F40BD4A652537C8D44473
{
    unsigned __int64 RefCnt : 4;
};

/* 544 */
union $A1C15557DD47CC06872EBD3C877220B1
{
    void* Object;
    $4DC8F54BDA4F40BD4A652537C8D44473 __s1;
    unsigned __int64 Value;
};

/* 545 */
struct _EX_FAST_REF
{
    $A1C15557DD47CC06872EBD3C877220B1 ___u0;
};

/* 546 */
struct _TERMINATION_PORT
{
    _TERMINATION_PORT* Next;
    void* Port;
};

/* 749 */
union $421FB931CD8C0EB9A167A45BF6AE3BFA
{
    _LARGE_INTEGER ExitTime;
    _LIST_ENTRY KeyedWaitChain;
};

/* 750 */
struct $03D8BF64EDBF31DF6271812E8E91AA90
{
    void* ForwardLinkShadow;
    void* StartAddress;
};

/* 751 */
union $F0B48B36BD8686749EAAD0CAE8FABA3B
{
    _LIST_ENTRY PostBlockList;
    $03D8BF64EDBF31DF6271812E8E91AA90 __s1;
};

/* 752 */
union $811C7A4D388345C1309261382BF4D2A8
{
    _TERMINATION_PORT* TerminationPort;
    _ETHREAD* ReaperLink;
    void* KeyedWaitValue;
};

/* 548 */
struct __declspec(align(8)) _KSEMAPHORE
{
    _DISPATCHER_HEADER Header;
    int Limit;
};

/* 753 */
union $7D821DE8788AAC9C9663B195A767FDF1
{
    _KSEMAPHORE KeyedWaitSemaphore;
    _KSEMAPHORE AlpcWaitSemaphore;
};

/* 549 */
struct $8311FD7E80609E8180C960E59071DEBE
{
    unsigned __int64 ImpersonationLevel : 2;
    unsigned __int64 EffectiveOnly : 1;
};

/* 550 */
union _PS_CLIENT_SECURITY_CONTEXT
{
    unsigned __int64 ImpersonationData;
    void* ImpersonationToken;
    $8311FD7E80609E8180C960E59071DEBE __s2;
};

/* 754 */
struct $485F5E3313845498A12F0D26750C00B6
{
    unsigned __int32 Terminated : 1;
    unsigned __int32 ThreadInserted : 1;
    unsigned __int32 HideFromDebugger : 1;
    unsigned __int32 ActiveImpersonationInfo : 1;
    unsigned __int32 HardErrorsAreDisabled : 1;
    unsigned __int32 BreakOnTermination : 1;
    unsigned __int32 SkipCreationMsg : 1;
    unsigned __int32 SkipTerminationMsg : 1;
    unsigned __int32 CopyTokenOnOpen : 1;
    unsigned __int32 ThreadIoPriority : 3;
    unsigned __int32 ThreadPagePriority : 3;
    unsigned __int32 RundownFail : 1;
    unsigned __int32 UmsForceQueueTermination : 1;
    unsigned __int32 IndirectCpuSets : 1;
    unsigned __int32 DisableDynamicCodeOptOut : 1;
    unsigned __int32 ExplicitCaseSensitivity : 1;
    unsigned __int32 PicoNotifyExit : 1;
    unsigned __int32 DbgWerUserReportActive : 1;
    unsigned __int32 ForcedSelfTrimActive : 1;
    unsigned __int32 SamplingCoverage : 1;
    unsigned __int32 ReservedCrossThreadFlags : 8;
};

/* 755 */
union $A22490C863A700872A1D636125928697
{
    unsigned int CrossThreadFlags;
    $485F5E3313845498A12F0D26750C00B6 __s1;
};

/* 756 */
struct $FF80C4A6C862A386C6A1719D599D7204
{
    unsigned __int32 ActiveExWorker : 1;
    unsigned __int32 MemoryMaker : 1;
    unsigned __int32 StoreLockThread : 2;
    unsigned __int32 ClonedThread : 1;
    unsigned __int32 KeyedEventInUse : 1;
    unsigned __int32 SelfTerminate : 1;
    unsigned __int32 RespectIoPriority : 1;
    unsigned __int32 ActivePageLists : 1;
    unsigned __int32 SecureContext : 1;
    unsigned __int32 ZeroPageThread : 1;
    unsigned __int32 WorkloadClass : 1;
    unsigned __int32 ReservedSameThreadPassiveFlags : 20;
};

/* 757 */
union $43F6F3820EEA3ECE2B46806BEF8C4B66
{
    unsigned int SameThreadPassiveFlags;
    $FF80C4A6C862A386C6A1719D599D7204 __s1;
};

/* 758 */
struct $5410E070226BCD0DD5B85D9B02068595
{
    unsigned __int8 OwnsProcessAddressSpaceExclusive : 1;
    unsigned __int8 OwnsProcessAddressSpaceShared : 1;
    unsigned __int8 HardFaultBehavior : 1;
    unsigned __int8 StartAddressInvalid : 1;
    unsigned __int8 EtwCalloutActive : 1;
    unsigned __int8 SuppressSymbolLoad : 1;
    unsigned __int8 Prefetching : 1;
    unsigned __int8 OwnsVadExclusive : 1;
    unsigned __int8 SystemPagePriorityActive : 1;
    unsigned __int8 SystemPagePriority : 3;
    unsigned __int8 AllowUserWritesToExecutableMemory : 1;
    unsigned __int8 AllowKernelWritesToExecutableMemory : 1;
    unsigned __int8 OwnsVadShared : 1;
};

/* 759 */
union $E7FCBD6C22A000B0972A9D427B430BC1
{
    unsigned int SameThreadApcFlags;
    $5410E070226BCD0DD5B85D9B02068595 __s1;
};

/* 760 */
union $BCDEC18C25A84109137EA1753A3327D2
{
    void* AlpcMessage;
    unsigned int AlpcReceiveAttributeSet;
};

/* 696 */
struct _PS_PROPERTY_SET
{
    _LIST_ENTRY ListHead;
    unsigned __int64 Lock;
};

/* 761 */
union $2F5B20675905D9187E7A5970F6F306B8
{
    unsigned __int64 SelectedCpuSets;
    unsigned __int64* SelectedCpuSetsIndirect;
};

/* 547 */
struct _ETHREAD
{
    _KTHREAD Tcb;
    _LARGE_INTEGER CreateTime;
    $421FB931CD8C0EB9A167A45BF6AE3BFA ___u2;
    $F0B48B36BD8686749EAAD0CAE8FABA3B ___u3;
    $811C7A4D388345C1309261382BF4D2A8 ___u4;
    unsigned __int64 ActiveTimerListLock;
    _LIST_ENTRY ActiveTimerListHead;
    _CLIENT_ID Cid;
    $7D821DE8788AAC9C9663B195A767FDF1 ___u8;
    _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;
    _LIST_ENTRY IrpList;
    unsigned __int64 TopLevelIrp;
    _DEVICE_OBJECT* DeviceToVerify;
    void* Win32StartAddress;
    void* ChargeOnlySession;
    void* LegacyPowerObject;
    _LIST_ENTRY ThreadListEntry;
    _EX_RUNDOWN_REF RundownProtect;
    _EX_PUSH_LOCK ThreadLock;
    unsigned int ReadClusterSize;
    volatile int MmLockOrdering;
    $A22490C863A700872A1D636125928697 ___u21;
    $43F6F3820EEA3ECE2B46806BEF8C4B66 ___u22;
    $E7FCBD6C22A000B0972A9D427B430BC1 ___u23;
    unsigned __int8 CacheManagerActive;
    unsigned __int8 DisablePageFaultClustering;
    unsigned __int8 ActiveFaultCount;
    unsigned __int8 LockOrderState;
    unsigned int PerformanceCountLowReserved;
    int PerformanceCountHighReserved;
    unsigned __int64 AlpcMessageId;
    $BCDEC18C25A84109137EA1753A3327D2 ___u31;
    _LIST_ENTRY AlpcWaitListEntry;
    int ExitStatus;
    unsigned int CacheManagerCount;
    unsigned int IoBoostCount;
    unsigned int IoQoSBoostCount;
    unsigned int IoQoSThrottleCount;
    unsigned int KernelStackReference;
    _LIST_ENTRY BoostList;
    _LIST_ENTRY DeboostList;
    unsigned __int64 BoostListLock;
    unsigned __int64 IrpListLock;
    void* ReservedForSynchTracking;
    _SINGLE_LIST_ENTRY CmCallbackListHead;
    const _GUID* ActivityId;
    _SINGLE_LIST_ENTRY SeLearningModeListHead;
    void* VerifierContext;
    void* AdjustedClientToken;
    void* WorkOnBehalfThread;
    _PS_PROPERTY_SET PropertySet;
    void* PicoContext;
    unsigned __int64 UserFsBase;
    unsigned __int64 UserGsBase;
    _THREAD_ENERGY_VALUES* EnergyValues;
    $2F5B20675905D9187E7A5970F6F306B8 ___u55;
    _EJOB* Silo;
    _UNICODE_STRING* ThreadName;
    _CONTEXT* SetContextState;
    unsigned int LastExpectedRunTime;
    unsigned int HeapData;
    _LIST_ENTRY OwnerEntryListHead;
    unsigned __int64 DisownedOwnerEntryListLock;
    _LIST_ENTRY DisownedOwnerEntryListHead;
    _KLOCK_ENTRY LockEntries[6];
    void* CmDbgInfo;
};

/* 570 */
struct __declspec(align(4)) _KDEVICE_QUEUE_ENTRY
{
    _LIST_ENTRY DeviceListEntry;
    unsigned int SortKey;
    unsigned __int8 Inserted;
};

/* 688 */
struct $F8B49521450F419D274BD5AB14641BA7
{
    _LIST_ENTRY DmaWaitEntry;
    unsigned int NumberOfChannels;
    unsigned __int32 SyncCallback : 1;
    unsigned __int32 DmaContext : 1;
    unsigned __int32 ZeroMapRegisters : 1;
    unsigned __int32 Reserved : 9;
    unsigned __int32 NumberOfRemapPages : 20;
};

/* 689 */
union $29E645298F1C6363CD4421B4ED4C4A4B
{
    _KDEVICE_QUEUE_ENTRY WaitQueueEntry;
    $F8B49521450F419D274BD5AB14641BA7 __s1;
};

/* 690 */
struct _WAIT_CONTEXT_BLOCK
{
    $29E645298F1C6363CD4421B4ED4C4A4B ___u0;
    _IO_ALLOCATION_ACTION(__fastcall* DeviceRoutine)(_DEVICE_OBJECT*, _IRP*, void*, void*);
    void* DeviceContext;
    unsigned int NumberOfMapRegisters;
    void* DeviceObject;
    void* CurrentIrp;
    _KDPC* BufferChainingDpc;
};

/* 695 */
union $1E1C779D8310069EE2DDA30D7BD92BC9
{
    _LIST_ENTRY ListEntry;
    _WAIT_CONTEXT_BLOCK Wcb;
};

/* 691 */
struct $18E3EACC1E717291AA7C720ECCD5C45C
{
    __int64 Reserved : 8;
    __int64 Hint : 56;
};

/* 692 */
union $22FA3A993C5FD1ABE6C50DCEE1AE3EC1
{
    unsigned __int8 Busy;
    $18E3EACC1E717291AA7C720ECCD5C45C __s1;
};

/* 693 */
struct _KDEVICE_QUEUE
{
    __int16 Type;
    __int16 Size;
    _LIST_ENTRY DeviceListHead;
    unsigned __int64 Lock;
    $22FA3A993C5FD1ABE6C50DCEE1AE3EC1 ___u4;
};

/* 551 */
struct __declspec(align(16)) _DEVICE_OBJECT
{
    __int16 Type;
    unsigned __int16 Size;
    int ReferenceCount;
    _DRIVER_OBJECT* DriverObject;
    _DEVICE_OBJECT* NextDevice;
    _DEVICE_OBJECT* AttachedDevice;
    _IRP* CurrentIrp;
    _IO_TIMER* Timer;
    unsigned int Flags;
    unsigned int Characteristics;
    _VPB* Vpb;
    void* DeviceExtension;
    unsigned int DeviceType;
    char StackSize;
    $1E1C779D8310069EE2DDA30D7BD92BC9 Queue;
    unsigned int AlignmentRequirement;
    _KDEVICE_QUEUE DeviceQueue;
    _KDPC Dpc;
    unsigned int ActiveThreadCount;
    void* SecurityDescriptor;
    _KEVENT DeviceLock;
    unsigned __int16 SectorSize;
    unsigned __int16 Spare1;
    _DEVOBJ_EXTENSION* DeviceObjectExtension;
    void* Reserved;
};

/* 697 */
struct $D771432583654A30C3F0CC1F45CBD584
{
    unsigned int EndTime;
    unsigned int Bitmap;
};

/* 698 */
union _TIMELINE_BITMAP
{
    unsigned __int64 Value;
    $D771432583654A30C3F0CC1F45CBD584 __s1;
};

/* 699 */
struct _THREAD_ENERGY_VALUES
{
    unsigned __int64 Cycles[4][2];
    unsigned __int64 AttributedCycles[4][2];
    unsigned __int64 WorkOnBehalfCycles[4][2];
    _TIMELINE_BITMAP CpuTimeline;
};

/* 561 */
struct $9959C6898638794B7A02F04E7F980F81
{
    unsigned __int8 ReservedLowFlags;
    unsigned __int8 WaiterPriority;
};

/* 562 */
union $3770B3F57BF0B3C48A450F30EA6FBCD4
{
    unsigned __int16 Flag;
    $9959C6898638794B7A02F04E7F980F81 __s1;
};

/* 558 */
struct $E71B718CD8428E7C8AA4A0868051E710
{
    unsigned __int32 IoPriorityBoosted : 1;
    unsigned __int32 OwnerReferenced : 1;
    unsigned __int32 IoQoSPriorityBoosted : 1;
    unsigned __int32 OwnerCount : 29;
};

/* 559 */
union $1ACFDE5858C70FFBCA45C511E3A1BDD1
{
    $E71B718CD8428E7C8AA4A0868051E710 __s0;
    unsigned int TableSize;
};

/* 560 */
struct __declspec(align(8)) _OWNER_ENTRY
{
    unsigned __int64 OwnerThread;
    $1ACFDE5858C70FFBCA45C511E3A1BDD1 ___u1;
};

/* 563 */
union $FA8F2364BE4EE7049C389A9C36002332
{
    void* Address;
    unsigned __int64 CreatorBackTraceIndex;
};

/* 564 */
struct _ERESOURCE
{
    _LIST_ENTRY SystemResourcesList;
    _OWNER_ENTRY* OwnerTable;
    __int16 ActiveCount;
    $3770B3F57BF0B3C48A450F30EA6FBCD4 ___u3;
    void* SharedWaiters;
    void* ExclusiveWaiters;
    _OWNER_ENTRY OwnerEntry;
    unsigned int ActiveEntries;
    unsigned int ContentionCount;
    unsigned int NumberOfSharedWaiters;
    unsigned int NumberOfExclusiveWaiters;
    void* Reserved2;
    $FA8F2364BE4EE7049C389A9C36002332 ___u12;
    unsigned __int64 SpinLock;
};

/* 700 */
struct _PROCESS_DISK_COUNTERS
{
    unsigned __int64 BytesRead;
    unsigned __int64 BytesWritten;
    unsigned __int64 ReadOperationCount;
    unsigned __int64 WriteOperationCount;
    unsigned __int64 FlushOperationCount;
};

/* 702 */
struct _WNF_STATE_NAME
{
    unsigned int Data[2];
};

/* 703 */
struct _PS_JOB_WAKE_INFORMATION
{
    unsigned __int64 NotificationChannel;
    unsigned __int64 WakeCounters[7];
    unsigned __int64 NoWakeCounter;
};

/* 742 */
union $7E4E6024EE48CF74500BD58327144512
{
    _WNF_STATE_NAME WakeChannel;
    _PS_JOB_WAKE_INFORMATION WakeInfo;
};

/* 704 */
struct _JOBOBJECT_WAKE_FILTER
{
    unsigned int HighEdgeFilter;
    unsigned int LowEdgeFilter;
};

/* 743 */
union $3D3E7153CEF84D206880B550FCFEAB9D
{
    _EJOB** Ancestors;
    void* SessionObject;
};

/* 706 */
struct _EPROCESS_VALUES
{
    unsigned __int64 KernelTime;
    unsigned __int64 UserTime;
    unsigned __int64 ReadyTime;
    unsigned __int64 CycleTime;
    unsigned __int64 ContextSwitches;
    __int64 ReadOperationCount;
    __int64 WriteOperationCount;
    __int64 OtherOperationCount;
    __int64 ReadTransferCount;
    __int64 WriteTransferCount;
    __int64 OtherTransferCount;
    unsigned __int64 KernelWaitTime;
    unsigned __int64 UserWaitTime;
};

/* 744 */
struct $65D3EB519B1E7C760B05EEB88159A6EF
{
    unsigned __int32 CloseDone : 1;
    unsigned __int32 MultiGroup : 1;
    unsigned __int32 OutstandingNotification : 1;
    unsigned __int32 NotificationInProgress : 1;
    unsigned __int32 UILimits : 1;
    unsigned __int32 CpuRateControlActive : 1;
    unsigned __int32 OwnCpuRateControl : 1;
    unsigned __int32 Terminating : 1;
    unsigned __int32 WorkingSetLock : 1;
    unsigned __int32 JobFrozen : 1;
    unsigned __int32 Background : 1;
    unsigned __int32 WakeNotificationAllocated : 1;
    unsigned __int32 WakeNotificationEnabled : 1;
    unsigned __int32 WakeNotificationPending : 1;
    unsigned __int32 LimitNotificationRequired : 1;
    unsigned __int32 ZeroCountNotificationRequired : 1;
    unsigned __int32 CycleTimeNotificationRequired : 1;
    unsigned __int32 CycleTimeNotificationPending : 1;
    unsigned __int32 TimersVirtualized : 1;
    unsigned __int32 JobSwapped : 1;
    unsigned __int32 ViolationDetected : 1;
    unsigned __int32 EmptyJobNotified : 1;
    unsigned __int32 NoSystemCharge : 1;
    unsigned __int32 DropNoWakeCharges : 1;
    unsigned __int32 NoWakeChargePolicyDecided : 1;
    unsigned __int32 NetRateControlActive : 1;
    unsigned __int32 OwnNetRateControl : 1;
    unsigned __int32 IoRateControlActive : 1;
    unsigned __int32 OwnIoRateControl : 1;
    unsigned __int32 DisallowNewProcesses : 1;
    unsigned __int32 Silo : 1;
    unsigned __int32 ContainerTelemetryIdSet : 1;
};

/* 745 */
union $7FBCF365D05992FC63E53D9044EE1155
{
    unsigned int JobFlags;
    $65D3EB519B1E7C760B05EEB88159A6EF __s1;
};

/* 746 */
struct $4FFEC2D8DFB6AAE379F5515F45589EFE
{
    unsigned __int32 ParentLocked : 1;
    unsigned __int32 EnableUsermodeSiloThreadImpersonation : 1;
    unsigned __int32 DisallowUsermodeSiloThreadImpersonation : 1;
};

/* 747 */
union $BEAD43ACAD0A61B0CBD23FA905D23B8B
{
    unsigned int JobFlags2;
    $4FFEC2D8DFB6AAE379F5515F45589EFE __s1;
};

/* 748 */
union $EA20D7E47CF3B5767C5C3BE63561EDC9
{
    void* DiskIoAttributionContext;
    _EJOB* DiskIoAttributionOwnerJob;
};

/* 736 */
struct _JOB_RATE_CONTROL_HEADER
{
    void* RateControlQuotaReference;
    _RTL_BITMAP OverQuotaHistory;
    unsigned __int8* BitMapBuffer;
    unsigned __int64 BitMapBufferSize;
};

/* 737 */
struct $5888D86FED6A417FC0E89347D22567F4
{
    _LIST_ENTRY FreeListEntry;
    unsigned __int64 ReservedForParentValue;
};

/* 738 */
union $22B8C9028E032FBC8753D487E9035712
{
    _RTL_BALANCED_NODE VolumeTreeNode;
    $5888D86FED6A417FC0E89347D22567F4 __s1;
};

/* 739 */
struct _PS_IO_CONTROL_ENTRY
{
    $22B8C9028E032FBC8753D487E9035712 ___u0;
    unsigned __int64 VolumeKey;
    _EX_RUNDOWN_REF Rundown;
    void* IoControl;
    void* VolumeIoAttribution;
};

/* 740 */
struct $68EC590CC89D3F83C2346CB373973C81
{
    unsigned int UpdateMask;
    unsigned int DesiredState;
};

/* 741 */
union _JOBOBJECT_ENERGY_TRACKING_STATE
{
    unsigned __int64 Value;
    $68EC590CC89D3F83C2346CB373973C81 __s1;
};

/* 701 */
struct _EJOB
{
    _KEVENT Event;
    _LIST_ENTRY JobLinks;
    _LIST_ENTRY ProcessListHead;
    _ERESOURCE JobLock;
    _LARGE_INTEGER TotalUserTime;
    _LARGE_INTEGER TotalKernelTime;
    _LARGE_INTEGER TotalCycleTime;
    _LARGE_INTEGER ThisPeriodTotalUserTime;
    _LARGE_INTEGER ThisPeriodTotalKernelTime;
    unsigned __int64 TotalContextSwitches;
    unsigned int TotalPageFaultCount;
    unsigned int TotalProcesses;
    unsigned int ActiveProcesses;
    unsigned int TotalTerminatedProcesses;
    _LARGE_INTEGER PerProcessUserTimeLimit;
    _LARGE_INTEGER PerJobUserTimeLimit;
    unsigned __int64 MinimumWorkingSetSize;
    unsigned __int64 MaximumWorkingSetSize;
    unsigned int LimitFlags;
    unsigned int ActiveProcessLimit;
    _KAFFINITY_EX Affinity;
    struct _JOB_ACCESS_STATE* AccessState;
    void* AccessStateQuotaReference;
    unsigned int UIRestrictionsClass;
    unsigned int EndOfJobTimeAction;
    void* CompletionPort;
    void* CompletionKey;
    unsigned __int64 CompletionCount;
    unsigned int SessionId;
    unsigned int SchedulingClass;
    unsigned __int64 ReadOperationCount;
    unsigned __int64 WriteOperationCount;
    unsigned __int64 OtherOperationCount;
    unsigned __int64 ReadTransferCount;
    unsigned __int64 WriteTransferCount;
    unsigned __int64 OtherTransferCount;
    _PROCESS_DISK_COUNTERS DiskIoInfo;
    unsigned __int64 ProcessMemoryLimit;
    unsigned __int64 JobMemoryLimit;
    unsigned __int64 JobTotalMemoryLimit;
    unsigned __int64 PeakProcessMemoryUsed;
    unsigned __int64 PeakJobMemoryUsed;
    _KAFFINITY_EX EffectiveAffinity;
    _LARGE_INTEGER EffectivePerProcessUserTimeLimit;
    unsigned __int64 EffectiveMinimumWorkingSetSize;
    unsigned __int64 EffectiveMaximumWorkingSetSize;
    unsigned __int64 EffectiveProcessMemoryLimit;
    _EJOB* EffectiveProcessMemoryLimitJob;
    _EJOB* EffectivePerProcessUserTimeLimitJob;
    _EJOB* EffectiveNetIoRateLimitJob;
    _EJOB* EffectiveHeapAttributionJob;
    unsigned int EffectiveLimitFlags;
    unsigned int EffectiveSchedulingClass;
    unsigned int EffectiveFreezeCount;
    unsigned int EffectiveBackgroundCount;
    unsigned int EffectiveSwapCount;
    unsigned int EffectiveNotificationLimitCount;
    unsigned __int8 EffectivePriorityClass;
    unsigned __int8 PriorityClass;
    unsigned __int8 NestingDepth;
    unsigned __int8 Reserved1[1];
    unsigned int CompletionFilter;
    $7E4E6024EE48CF74500BD58327144512 ___u62;
    _JOBOBJECT_WAKE_FILTER WakeFilter;
    unsigned int LowEdgeLatchFilter;
    _EJOB* NotificationLink;
    unsigned __int64 CurrentJobMemoryUsed;
    struct _JOB_NOTIFICATION_INFORMATION* NotificationInfo;
    void* NotificationInfoQuotaReference;
    _IO_MINI_COMPLETION_PACKET_USER* NotificationPacket;
    struct _JOB_CPU_RATE_CONTROL* CpuRateControl;
    void* EffectiveSchedulingGroup;
    unsigned __int64 ReadyTime;
    _EX_PUSH_LOCK MemoryLimitsLock;
    _LIST_ENTRY SiblingJobLinks;
    _LIST_ENTRY ChildJobListHead;
    _EJOB* ParentJob;
    _EJOB* volatile RootJob;
    _LIST_ENTRY IteratorListHead;
    unsigned __int64 AncestorCount;
    $3D3E7153CEF84D206880B550FCFEAB9D ___u80;
    _EPROCESS_VALUES Accounting;
    unsigned int ShadowActiveProcessCount;
    unsigned int ActiveAuxiliaryProcessCount;
    unsigned int SequenceNumber;
    unsigned int JobId;
    _GUID ContainerId;
    _GUID ContainerTelemetryId;
    _ESERVERSILO_GLOBALS* ServerSiloGlobals;
    _PS_PROPERTY_SET PropertySet;
    struct _PSP_STORAGE* Storage;
    struct _JOB_NET_RATE_CONTROL* NetRateControl;
    $7FBCF365D05992FC63E53D9044EE1155 ___u92;
    $BEAD43ACAD0A61B0CBD23FA905D23B8B ___u93;
    _PROCESS_EXTENDED_ENERGY_VALUES* EnergyValues;
    volatile unsigned __int64 SharedCommitCharge;
    unsigned int DiskIoAttributionUserRefCount;
    unsigned int DiskIoAttributionRefCount;
    $EA20D7E47CF3B5767C5C3BE63561EDC9 ___u98;
    _JOB_RATE_CONTROL_HEADER IoRateControlHeader;
    _PS_IO_CONTROL_ENTRY GlobalIoControl;
    volatile int IoControlStateLock;
    _RTL_RB_TREE VolumeIoControlTree;
    unsigned __int64 IoRateOverQuotaHistory;
    unsigned int IoRateCurrentGeneration;
    unsigned int IoRateLastQueryGeneration;
    unsigned int IoRateGenerationLength;
    unsigned int IoRateOverQuotaNotifySequenceId;
    unsigned __int64 LastThrottledIoTime;
    _EX_PUSH_LOCK IoControlLock;
    __int64 SiloHardReferenceCount;
    _WORK_QUEUE_ITEM RundownWorkItem;
    void* PartitionObject;
    _EJOB* PartitionOwnerJob;
    _JOBOBJECT_ENERGY_TRACKING_STATE EnergyTrackingState;
    unsigned __int64 KernelWaitTime;
    unsigned __int64 UserWaitTime;
};

/* 552 */
struct _DRIVER_OBJECT
{
    __int16 Type;
    __int16 Size;
    _DEVICE_OBJECT* DeviceObject;
    unsigned int Flags;
    void* DriverStart;
    unsigned int DriverSize;
    void* DriverSection;
    _DRIVER_EXTENSION* DriverExtension;
    _UNICODE_STRING DriverName;
    _UNICODE_STRING* HardwareDatabase;
    _FAST_IO_DISPATCH* FastIoDispatch;
    int(__fastcall* DriverInit)(_DRIVER_OBJECT*, _UNICODE_STRING*);
    void(__fastcall* DriverStartIo)(_DEVICE_OBJECT*, _IRP*);
    void(__fastcall* DriverUnload)(_DRIVER_OBJECT*);
    int(__fastcall* MajorFunction[28])(_DEVICE_OBJECT*, _IRP*);
};

/* 668 */
union $04B1A7556B4AC6D95596C3902CEA633C
{
    _IRP* MasterIrp;
    int IrpCount;
    void* SystemBuffer;
};

/* 569 */
union $B85C1ACDA99511BE4B4882AAD9A496BD
{
    void(__fastcall* UserApcRoutine)(void*, _IO_STATUS_BLOCK*, unsigned int);
    void* IssuingProcess;
};

/* 669 */
struct $36C803820E1B0C191B191549F0E3ACC5
{
    $B85C1ACDA99511BE4B4882AAD9A496BD ___u0;
    void* UserApcContext;
};

/* 670 */
union $F1421C3CE1A732B18940EBC2DCBDA703
{
    $36C803820E1B0C191B191549F0E3ACC5 AsynchronousParameters;
    _LARGE_INTEGER AllocationSize;
};

/* 666 */
union $F2027A0C5D9A20DE75B1BD61E2F306BE
{
    _KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
    void* DriverContext[4];
};

/* 667 */
union $900F5A1D3133BD693FEF37F934A44A0F
{
    _IO_STACK_LOCATION* CurrentStackLocation;
    unsigned int PacketType;
};

/* 671 */
struct $4279A0F9897B3DD15E7FAA061F8A8539
{
    $F2027A0C5D9A20DE75B1BD61E2F306BE ___u0;
    _ETHREAD* Thread;
    char* AuxiliaryBuffer;
    _LIST_ENTRY ListEntry;
    $900F5A1D3133BD693FEF37F934A44A0F ___u4;
    _FILE_OBJECT* OriginalFileObject;
    void* IrpExtension;
};

/* 672 */
union $4B1BBB6603A74A6ED007A418CAB5A3E3
{
    $4279A0F9897B3DD15E7FAA061F8A8539 Overlay;
    _KAPC Apc;
    void* CompletionKey;
};

/* 568 */
struct _IRP
{
    __int16 Type;
    unsigned __int16 Size;
    unsigned __int16 AllocationProcessorNumber;
    unsigned __int16 Reserved;
    _MDL* MdlAddress;
    unsigned int Flags;
    $04B1A7556B4AC6D95596C3902CEA633C AssociatedIrp;
    _LIST_ENTRY ThreadListEntry;
    _IO_STATUS_BLOCK IoStatus;
    char RequestorMode;
    unsigned __int8 PendingReturned;
    char StackCount;
    char CurrentLocation;
    unsigned __int8 Cancel;
    unsigned __int8 CancelIrql;
    char ApcEnvironment;
    unsigned __int8 AllocationFlags;
    _IO_STATUS_BLOCK* UserIosb;
    _KEVENT* UserEvent;
    $F1421C3CE1A732B18940EBC2DCBDA703 Overlay;
    void(__fastcall* CancelRoutine)(_DEVICE_OBJECT*, _IRP*);
    void* UserBuffer;
    $4B1BBB6603A74A6ED007A418CAB5A3E3 Tail;
};

/* 687 */
struct _IO_TIMER
{
    __int16 Type;
    __int16 TimerFlag;
    _LIST_ENTRY TimerList;
    void(__fastcall* TimerRoutine)(_DEVICE_OBJECT*, void*);
    void* Context;
    _DEVICE_OBJECT* DeviceObject;
};

/* 554 */
struct _VPB
{
    __int16 Type;
    __int16 Size;
    unsigned __int16 Flags;
    unsigned __int16 VolumeLabelLength;
    _DEVICE_OBJECT* DeviceObject;
    _DEVICE_OBJECT* RealDevice;
    unsigned int SerialNumber;
    unsigned int ReferenceCount;
    wchar_t VolumeLabel[32];
};

/* 694 */
struct _DEVOBJ_EXTENSION
{
    __int16 Type;
    unsigned __int16 Size;
    _DEVICE_OBJECT* DeviceObject;
    unsigned int PowerFlags;
    struct _DEVICE_OBJECT_POWER_EXTENSION* Dope;
    unsigned int ExtensionFlags;
    void* DeviceNode;
    _DEVICE_OBJECT* AttachedTo;
    int StartIoCount;
    int StartIoKey;
    unsigned int StartIoFlags;
    _VPB* Vpb;
    void* DependencyNode;
    void* InterruptContext;
    int InterruptCount;
    void* VerifierContext;
};

/* 705 */
struct __declspec(align(8)) _IO_MINI_COMPLETION_PACKET_USER
{
    _LIST_ENTRY ListEntry;
    unsigned int PacketType;
    void* KeyContext;
    void* ApcContext;
    int IoStatus;
    unsigned __int64 IoStatusInformation;
    void(__fastcall* MiniPacketCallback)(_IO_MINI_COMPLETION_PACKET_USER*, void*);
    void* Context;
    unsigned __int8 Allocated;
};

/* 710 */
struct _OBP_SYSTEM_DOS_DEVICE_STATE
{
    unsigned int GlobalDeviceMap;
    unsigned int LocalDeviceCount[26];
};

/* 711 */
struct __declspec(align(8)) _OBJECT_NAMESPACE_LOOKUPTABLE
{
    _LIST_ENTRY HashBuckets[37];
    _EX_PUSH_LOCK Lock;
    unsigned int NumberOfPrivateSpaces;
};

/* 712 */
struct _OBP_SILODRIVERSTATE
{
    _DEVICE_MAP* SystemDeviceMap;
    _OBP_SYSTEM_DOS_DEVICE_STATE SystemDosDeviceState;
    _EX_PUSH_LOCK DeviceMapLock;
    _OBJECT_NAMESPACE_LOOKUPTABLE PrivateNamespaceLookupTable;
};

/* 713 */
struct _SEP_SILOSTATE
{
    struct _SEP_LOGON_SESSION_REFERENCES* SystemLogonSession;
    struct _SEP_LOGON_SESSION_REFERENCES* AnonymousLogonSession;
    void* AnonymousLogonToken;
    void* AnonymousLogonTokenNoEveryone;
    _UNICODE_STRING* UncSystemPaths;
    struct _CI_NGEN_PATHS* NgenPaths;
};

/* 714 */
struct __declspec(align(4)) _SEP_RM_LSA_CONNECTION_STATE
{
    void* LsaProcessHandle;
    void* LsaCommandPortHandle;
    void* SepRmThreadHandle;
    void* RmCommandPortHandle;
    void* RmCommandServerPortHandle;
    void* LsaCommandPortSectionHandle;
    _LARGE_INTEGER LsaCommandPortSectionSize;
    void* LsaViewPortMemory;
    void* RmViewPortMemory;
    int LsaCommandPortMemoryDelta;
    unsigned __int8 LsaCommandPortActive;
};

/* 715 */
struct _WNF_LOCK
{
    _EX_PUSH_LOCK PushLock;
};

/* 716 */
struct _WNF_SILODRIVERSTATE
{
    struct _WNF_SCOPE_MAP* ScopeMap;
    void* volatile PermanentNameStoreRootKey;
    void* volatile PersistentNameStoreRootKey;
    volatile __int64 PermanentNameSequenceNumber;
    _WNF_LOCK PermanentNameSequenceNumberLock;
    volatile __int64 PermanentNameSequenceNumberPool;
    volatile __int64 RuntimeNameSequenceNumber;
};

/* 717 */
struct _DBGK_SILOSTATE
{
    _EX_PUSH_LOCK ErrorPortLock;
    struct _DBGKP_ERROR_PORT* ErrorPort;
    _EPROCESS* ErrorProcess;
    _KEVENT* ErrorPortRegisteredEvent;
};

/* 724 */
struct __declspec(align(8)) _ESERVERSILO_GLOBALS
{
    _OBP_SILODRIVERSTATE ObSiloState;
    _SEP_SILOSTATE SeSiloState;
    _SEP_RM_LSA_CONNECTION_STATE SeRmSiloState;
    struct _ETW_SILODRIVERSTATE* EtwSiloState;
    _EPROCESS* MiSessionLeaderProcess;
    _EPROCESS* ExpDefaultErrorPortProcess;
    void* ExpDefaultErrorPort;
    unsigned int HardErrorState;
    struct _EXP_LICENSE_STATE* ExpLicenseState;
    _WNF_SILODRIVERSTATE WnfSiloState;
    _DBGK_SILOSTATE DbgkSiloState;
    _UNICODE_STRING PsProtectedCurrentDirectory;
    _UNICODE_STRING PsProtectedEnvironment;
    void* ApiSetSection;
    void* ApiSetSchema;
    unsigned __int8 OneCoreForwardersEnabled;
    unsigned __int8 TzVirtualizationSupported;
    void* ImgFileExecOptions;
    _EX_TIMEZONE_STATE* ExTimeZoneState;
    _UNICODE_STRING NtSystemRoot;
    _UNICODE_STRING SiloRootDirectoryName;
    struct _PSP_STORAGE* Storage;
    _SERVERSILO_STATE State;
    int ExitStatus;
    _KEVENT* DeleteEvent;
    _SILO_USER_SHARED_DATA* UserSharedData;
    void* UserSharedSection;
    _WORK_QUEUE_ITEM TerminateWorkItem;
    unsigned __int8 IsDownlevelContainer;
};

/* 725 */
struct $408B3E5B3364B70B8AC22EB7EACE9DD4
{
    unsigned int LastChangeTime;
    unsigned __int32 Duration : 31;
    unsigned __int32 IsInState : 1;
};

/* 726 */
union _ENERGY_STATE_DURATION
{
    unsigned __int64 Value;
    $408B3E5B3364B70B8AC22EB7EACE9DD4 __s1;
};

/* 727 */
struct $BBFA0BEA0A21E2C8CA4E7ADE20A32007
{
    _ENERGY_STATE_DURATION ForegroundDuration;
    _ENERGY_STATE_DURATION DesktopVisibleDuration;
    _ENERGY_STATE_DURATION PSMForegroundDuration;
};

/* 728 */
union $0D98028D0891B8DB5DD0BFC05EF6F679
{
    _ENERGY_STATE_DURATION Durations[3];
    $BBFA0BEA0A21E2C8CA4E7ADE20A32007 __s1;
};

/* 729 */
struct _PROCESS_ENERGY_VALUES
{
    unsigned __int64 Cycles[4][2];
    unsigned __int64 DiskEnergy;
    unsigned __int64 NetworkTailEnergy;
    unsigned __int64 MBBTailEnergy;
    unsigned __int64 NetworkTxRxBytes;
    unsigned __int64 MBBTxRxBytes;
    $0D98028D0891B8DB5DD0BFC05EF6F679 ___u6;
    unsigned int CompositionRendered;
    unsigned int CompositionDirtyGenerated;
    unsigned int CompositionDirtyPropagated;
    unsigned int Reserved1;
    unsigned __int64 AttributedCycles[4][2];
    unsigned __int64 WorkOnBehalfCycles[4][2];
};

/* 730 */
struct $4732CF270D9FFEE3403DB5A9AC75AC6C
{
    _TIMELINE_BITMAP CpuTimeline;
    _TIMELINE_BITMAP DiskTimeline;
    _TIMELINE_BITMAP NetworkTimeline;
    _TIMELINE_BITMAP MBBTimeline;
    _TIMELINE_BITMAP ForegroundTimeline;
    _TIMELINE_BITMAP DesktopVisibleTimeline;
    _TIMELINE_BITMAP CompositionRenderedTimeline;
    _TIMELINE_BITMAP CompositionDirtyGeneratedTimeline;
    _TIMELINE_BITMAP CompositionDirtyPropagatedTimeline;
    _TIMELINE_BITMAP InputTimeline;
    _TIMELINE_BITMAP AudioInTimeline;
    _TIMELINE_BITMAP AudioOutTimeline;
    _TIMELINE_BITMAP DisplayRequiredTimeline;
    _TIMELINE_BITMAP KeyboardInputTimeline;
};

/* 731 */
union $D080931B6C84BF933E66368E83DDD13C
{
    _TIMELINE_BITMAP Timelines[14];
    $4732CF270D9FFEE3403DB5A9AC75AC6C __s1;
};

/* 732 */
struct $E227A1F1714C2D7A520697230244013B
{
    _ENERGY_STATE_DURATION InputDuration;
    _ENERGY_STATE_DURATION AudioInDuration;
    _ENERGY_STATE_DURATION AudioOutDuration;
    _ENERGY_STATE_DURATION DisplayRequiredDuration;
    _ENERGY_STATE_DURATION PSMBackgroundDuration;
};

/* 733 */
union $FD60EE9E2B90BE113CD52423E8A83A63
{
    _ENERGY_STATE_DURATION Durations[5];
    $E227A1F1714C2D7A520697230244013B __s1;
};

/* 734 */
struct _PROCESS_ENERGY_VALUES_EXTENSION
{
    $D080931B6C84BF933E66368E83DDD13C ___u0;
    $FD60EE9E2B90BE113CD52423E8A83A63 ___u1;
    unsigned int KeyboardInput;
    unsigned int MouseInput;
};

/* 735 */
struct _PROCESS_EXTENDED_ENERGY_VALUES
{
    _PROCESS_ENERGY_VALUES Base;
    _PROCESS_ENERGY_VALUES_EXTENSION Extension;
};

/* 681 */
struct _DRIVER_EXTENSION
{
    _DRIVER_OBJECT* DriverObject;
    int(__fastcall* AddDevice)(_DRIVER_OBJECT*, _DEVICE_OBJECT*);
    unsigned int Count;
    _UNICODE_STRING ServiceKeyName;
    _IO_CLIENT_EXTENSION* ClientDriverExtension;
    _FS_FILTER_CALLBACKS* FsFilterCallbacks;
    void* KseCallbacks;
    void* DvCallbacks;
    void* VerifierContext;
};

/* 686 */
struct _FAST_IO_DISPATCH
{
    unsigned int SizeOfFastIoDispatch;
    unsigned __int8(__fastcall* FastIoCheckIfPossible)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned __int8, unsigned int, unsigned __int8, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoRead)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned __int8, unsigned int, void*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoWrite)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned __int8, unsigned int, void*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoQueryBasicInfo)(_FILE_OBJECT*, unsigned __int8, _FILE_BASIC_INFORMATION*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoQueryStandardInfo)(_FILE_OBJECT*, unsigned __int8, _FILE_STANDARD_INFORMATION*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoLock)(_FILE_OBJECT*, _LARGE_INTEGER*, _LARGE_INTEGER*, _EPROCESS*, unsigned int, unsigned __int8, unsigned __int8, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoUnlockSingle)(_FILE_OBJECT*, _LARGE_INTEGER*, _LARGE_INTEGER*, _EPROCESS*, unsigned int, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoUnlockAll)(_FILE_OBJECT*, _EPROCESS*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoUnlockAllByKey)(_FILE_OBJECT*, void*, unsigned int, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoDeviceControl)(_FILE_OBJECT*, unsigned __int8, void*, unsigned int, void*, unsigned int, unsigned int, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    void(__fastcall* AcquireFileForNtCreateSection)(_FILE_OBJECT*);
    void(__fastcall* ReleaseFileForNtCreateSection)(_FILE_OBJECT*);
    void(__fastcall* FastIoDetachDevice)(_DEVICE_OBJECT*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoQueryNetworkOpenInfo)(_FILE_OBJECT*, unsigned __int8, _FILE_NETWORK_OPEN_INFORMATION*, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    int(__fastcall* AcquireForModWrite)(_FILE_OBJECT*, _LARGE_INTEGER*, _ERESOURCE**, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* MdlRead)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned int, _MDL**, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* MdlReadComplete)(_FILE_OBJECT*, _MDL*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* PrepareMdlWrite)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned int, _MDL**, _IO_STATUS_BLOCK*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* MdlWriteComplete)(_FILE_OBJECT*, _LARGE_INTEGER*, _MDL*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoReadCompressed)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned int, void*, _MDL**, _IO_STATUS_BLOCK*, _COMPRESSED_DATA_INFO*, unsigned int, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoWriteCompressed)(_FILE_OBJECT*, _LARGE_INTEGER*, unsigned int, unsigned int, void*, _MDL**, _IO_STATUS_BLOCK*, _COMPRESSED_DATA_INFO*, unsigned int, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* MdlReadCompleteCompressed)(_FILE_OBJECT*, _MDL*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* MdlWriteCompleteCompressed)(_FILE_OBJECT*, _LARGE_INTEGER*, _MDL*, _DEVICE_OBJECT*);
    unsigned __int8(__fastcall* FastIoQueryOpen)(_IRP*, _FILE_NETWORK_OPEN_INFORMATION*, _DEVICE_OBJECT*);
    int(__fastcall* ReleaseForModWrite)(_FILE_OBJECT*, _ERESOURCE*, _DEVICE_OBJECT*);
    int(__fastcall* AcquireForCcFlush)(_FILE_OBJECT*, _DEVICE_OBJECT*);
    int(__fastcall* ReleaseForCcFlush)(_FILE_OBJECT*, _DEVICE_OBJECT*);
};

/* 566 */
struct _MDL
{
    _MDL* Next;
    __int16 Size;
    __int16 MdlFlags;
    unsigned __int16 AllocationProcessorNumber;
    unsigned __int16 Reserved;
    _EPROCESS* Process;
    void* MappedSystemVa;
    void* StartVa;
    unsigned int ByteCount;
    unsigned int ByteOffset;
};

/* 630 */
struct $67E6ACA09B0C2FB21A66F8B28280D78B
{
    _IO_SECURITY_CONTEXT* SecurityContext;
    unsigned int Options;
    __declspec(align(8)) unsigned __int16 FileAttributes;
    unsigned __int16 ShareAccess;
    __declspec(align(8)) unsigned int EaLength;
};

/* 631 */
struct $2BA3B618392C2223C980E52090B66F3C
{
    _IO_SECURITY_CONTEXT* SecurityContext;
    unsigned int Options;
    __declspec(align(8)) unsigned __int16 Reserved;
    unsigned __int16 ShareAccess;
    _NAMED_PIPE_CREATE_PARAMETERS* Parameters;
};

/* 632 */
struct $EA2F389F5E9AA8781B310E4AF25FCE60
{
    _IO_SECURITY_CONTEXT* SecurityContext;
    unsigned int Options;
    __declspec(align(8)) unsigned __int16 Reserved;
    unsigned __int16 ShareAccess;
    _MAILSLOT_CREATE_PARAMETERS* Parameters;
};

/* 633 */
struct $9C4F888B5A914148CB4B2219EE4C61F5
{
    unsigned int Length;
    __declspec(align(8)) unsigned int Key;
    unsigned int Flags;
    _LARGE_INTEGER ByteOffset;
};

/* 634 */
struct $8270F973F880FD2BDB37AB37561CF70A
{
    unsigned int Length;
    _UNICODE_STRING* FileName;
    _FILE_INFORMATION_CLASS FileInformationClass;
    __declspec(align(8)) unsigned int FileIndex;
};

/* 635 */
struct $4C7536B798FF1E8DFFBB44C6988FA2B4
{
    unsigned int Length;
    __declspec(align(8)) unsigned int CompletionFilter;
};

/* 636 */
struct $66001E97D9678199CCDA067A69A3BCAC
{
    unsigned int Length;
    __declspec(align(8)) unsigned int CompletionFilter;
    __declspec(align(8)) _DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass;
};

/* 637 */
struct $0794B7C0E91828BD0611B6AA8DB3CDB2
{
    unsigned int Length;
    __declspec(align(8)) _FILE_INFORMATION_CLASS FileInformationClass;
};

/* 581 */
struct $BBD6C80A82148A7CAD5B218A5A41C1D9
{
    unsigned __int8 ReplaceIfExists;
    unsigned __int8 AdvanceOnly;
};

/* 582 */
union $F0D346BF1B61082B0EE4779DBF51B8C4
{
    $BBD6C80A82148A7CAD5B218A5A41C1D9 __s0;
    unsigned int ClusterCount;
    void* DeleteHandle;
};

/* 638 */
struct $3FCD13A0C8C846C7FD262238FEE6E8B2
{
    unsigned int Length;
    __declspec(align(8)) _FILE_INFORMATION_CLASS FileInformationClass;
    _FILE_OBJECT* FileObject;
    $F0D346BF1B61082B0EE4779DBF51B8C4 ___u3;
};

/* 639 */
struct $4419D7ADAC9681A2918B5F55FED05CE9
{
    unsigned int Length;
    void* EaList;
    unsigned int EaListLength;
    __declspec(align(8)) unsigned int EaIndex;
};

/* 640 */
struct $44CAF4394294FD1AA9144BF9A47D2B76
{
    unsigned int Length;
};

/* 641 */
struct $901BA1ABE2D166BF474B06BF4F44E4B6
{
    unsigned int Length;
    __declspec(align(8)) _FSINFOCLASS FsInformationClass;
};

/* 642 */
struct $A22BD7BB3E21894C53BB3BDEE59F3F9E
{
    unsigned int OutputBufferLength;
    __declspec(align(8)) unsigned int InputBufferLength;
    __declspec(align(8)) unsigned int FsControlCode;
    void* Type3InputBuffer;
};

/* 643 */
struct $7A37E7C44AD27ED755B740DF14333054
{
    _LARGE_INTEGER* Length;
    unsigned int Key;
    _LARGE_INTEGER ByteOffset;
};

/* 644 */
struct $8D5C9EAED6F9D55C3CB85DD43C7B39BC
{
    unsigned int OutputBufferLength;
    __declspec(align(8)) unsigned int InputBufferLength;
    __declspec(align(8)) unsigned int IoControlCode;
    void* Type3InputBuffer;
};

/* 645 */
struct $3F50B7E2595815BB2F06B4888C38A138
{
    unsigned int SecurityInformation;
    __declspec(align(8)) unsigned int Length;
};

/* 646 */
struct $29E784017BF8D630C3CED492840B3F1E
{
    unsigned int SecurityInformation;
    void* SecurityDescriptor;
};

/* 647 */
struct $116D76AACC4971899C7D3E9B819FC04A
{
    _VPB* Vpb;
    _DEVICE_OBJECT* DeviceObject;
};

/* 648 */
struct $B2B4984C7002DD41520623255E2F9497
{
    struct _SCSI_REQUEST_BLOCK* Srb;
};

/* 649 */
struct __declspec(align(8)) $E710F148272B37755A2A5A480540DDFB
{
    unsigned int Length;
    void* StartSid;
    _FILE_GET_QUOTA_INFORMATION* SidList;
    unsigned int SidListLength;
};

/* 650 */
struct $0F193EB57E38EF5279F2D2A8D7BF0B2D
{
    _DEVICE_RELATION_TYPE Type;
};

/* 651 */
struct $1B5D1632E33CA1B60E08B85CA2287F1A
{
    const _GUID* InterfaceType;
    unsigned __int16 Size;
    unsigned __int16 Version;
    _INTERFACE* Interface;
    void* InterfaceSpecificData;
};

/* 652 */
struct $E3E177F180DEC75153524CF0837BAF88
{
    _DEVICE_CAPABILITIES* Capabilities;
};

/* 653 */
struct $89F579A250E3E264A51EB8CD5E8B0F08
{
    _IO_RESOURCE_REQUIREMENTS_LIST* IoResourceRequirementList;
};

/* 654 */
struct $38AAAD12F7E95B1C50E1D11A7519EC16
{
    unsigned int WhichSpace;
    void* Buffer;
    unsigned int Offset;
    __declspec(align(8)) unsigned int Length;
};

/* 655 */
struct $B367FCCFB95D7087158A479FE9C2D0D7
{
    unsigned __int8 Lock;
};

/* 656 */
struct $03E399533941020534C84F7B69BA6C0D
{
    BUS_QUERY_ID_TYPE IdType;
};

/* 657 */
struct $F5D0DCCD5872E96D58CDCFED958383C8
{
    DEVICE_TEXT_TYPE DeviceTextType;
    __declspec(align(8)) unsigned int LocaleId;
};

/* 658 */
struct $67A68EE3B7A46E720658AF2D462E5186
{
    unsigned __int8 InPath;
    unsigned __int8 Reserved[3];
    __declspec(align(8)) _DEVICE_USAGE_NOTIFICATION_TYPE Type;
};

/* 659 */
struct $11F4275C5C519326409AF4E80485B892
{
    _SYSTEM_POWER_STATE PowerState;
};

/* 660 */
struct $1AC6A45646DA69A47788B37653A19A55
{
    _POWER_SEQUENCE* PowerSequence;
};

/* 604 */
struct $D446BF98445B25F2A957A6F10A39C71E
{
    unsigned __int32 Reserved1 : 8;
    unsigned __int32 TargetSystemState : 4;
    unsigned __int32 EffectiveSystemState : 4;
    unsigned __int32 CurrentSystemState : 4;
    unsigned __int32 IgnoreHibernationPath : 1;
    unsigned __int32 PseudoTransition : 1;
    unsigned __int32 KernelSoftReboot : 1;
    unsigned __int32 DirectedDripsTransition : 1;
    unsigned __int32 Reserved2 : 8;
};

/* 605 */
union $86A9AB5BA123BB9021BEDF3514121F1D
{
    $D446BF98445B25F2A957A6F10A39C71E __s0;
    unsigned int ContextAsUlong;
};

/* 606 */
struct _SYSTEM_POWER_STATE_CONTEXT
{
    $86A9AB5BA123BB9021BEDF3514121F1D ___u0;
};

/* 608 */
union $77B58F94A6C4FA42266891905476D472
{
    unsigned int SystemContext;
    _SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext;
};

/* 607 */
union _POWER_STATE
{
    _SYSTEM_POWER_STATE SystemState;
    _DEVICE_POWER_STATE DeviceState;
};

/* 661 */
struct $B954D42A608456A6639D08ABA68A839C
{
    $77B58F94A6C4FA42266891905476D472 ___u0;
    __declspec(align(8)) _POWER_STATE_TYPE Type;
    __declspec(align(8)) _POWER_STATE State;
    __declspec(align(8)) POWER_ACTION ShutdownType;
};

/* 662 */
struct $02B1E0EE1D255BA24585A07B68855512
{
    _CM_RESOURCE_LIST* AllocatedResources;
    _CM_RESOURCE_LIST* AllocatedResourcesTranslated;
};

/* 663 */
struct $4EB0307B916438E21EB61718614F2F9B
{
    unsigned __int64 ProviderId;
    void* DataPath;
    unsigned int BufferSize;
    void* Buffer;
};

/* 664 */
struct $228F32E73A128818A25FF1959272C294
{
    void* Argument1;
    void* Argument2;
    void* Argument3;
    void* Argument4;
};

/* 665 */
union $F747E0A1347AF9CB0D1447D244D7A011
{
    $67E6ACA09B0C2FB21A66F8B28280D78B Create;
    $2BA3B618392C2223C980E52090B66F3C CreatePipe;
    $EA2F389F5E9AA8781B310E4AF25FCE60 CreateMailslot;
    $9C4F888B5A914148CB4B2219EE4C61F5 Read;
    $9C4F888B5A914148CB4B2219EE4C61F5 Write;
    $8270F973F880FD2BDB37AB37561CF70A QueryDirectory;
    $4C7536B798FF1E8DFFBB44C6988FA2B4 NotifyDirectory;
    $66001E97D9678199CCDA067A69A3BCAC NotifyDirectoryEx;
    $0794B7C0E91828BD0611B6AA8DB3CDB2 QueryFile;
    $3FCD13A0C8C846C7FD262238FEE6E8B2 SetFile;
    $4419D7ADAC9681A2918B5F55FED05CE9 QueryEa;
    $44CAF4394294FD1AA9144BF9A47D2B76 SetEa;
    $901BA1ABE2D166BF474B06BF4F44E4B6 QueryVolume;
    $901BA1ABE2D166BF474B06BF4F44E4B6 SetVolume;
    $A22BD7BB3E21894C53BB3BDEE59F3F9E FileSystemControl;
    $7A37E7C44AD27ED755B740DF14333054 LockControl;
    $8D5C9EAED6F9D55C3CB85DD43C7B39BC DeviceIoControl;
    $3F50B7E2595815BB2F06B4888C38A138 QuerySecurity;
    $29E784017BF8D630C3CED492840B3F1E SetSecurity;
    $116D76AACC4971899C7D3E9B819FC04A MountVolume;
    $116D76AACC4971899C7D3E9B819FC04A VerifyVolume;
    $B2B4984C7002DD41520623255E2F9497 Scsi;
    $E710F148272B37755A2A5A480540DDFB QueryQuota;
    $44CAF4394294FD1AA9144BF9A47D2B76 SetQuota;
    $0F193EB57E38EF5279F2D2A8D7BF0B2D QueryDeviceRelations;
    $1B5D1632E33CA1B60E08B85CA2287F1A QueryInterface;
    $E3E177F180DEC75153524CF0837BAF88 DeviceCapabilities;
    $89F579A250E3E264A51EB8CD5E8B0F08 FilterResourceRequirements;
    $38AAAD12F7E95B1C50E1D11A7519EC16 ReadWriteConfig;
    $B367FCCFB95D7087158A479FE9C2D0D7 SetLock;
    $03E399533941020534C84F7B69BA6C0D QueryId;
    $F5D0DCCD5872E96D58CDCFED958383C8 QueryDeviceText;
    $67A68EE3B7A46E720658AF2D462E5186 UsageNotification;
    $11F4275C5C519326409AF4E80485B892 WaitWake;
    $1AC6A45646DA69A47788B37653A19A55 PowerSequence;
    $B954D42A608456A6639D08ABA68A839C Power;
    $02B1E0EE1D255BA24585A07B68855512 StartDevice;
    $4EB0307B916438E21EB61718614F2F9B WMI;
    $228F32E73A128818A25FF1959272C294 Others;
};

/* 629 */
struct _IO_STACK_LOCATION
{
    unsigned __int8 MajorFunction;
    unsigned __int8 MinorFunction;
    unsigned __int8 Flags;
    unsigned __int8 Control;
    $F747E0A1347AF9CB0D1447D244D7A011 Parameters;
    _DEVICE_OBJECT* DeviceObject;
    _FILE_OBJECT* FileObject;
    int(__fastcall* CompletionRoutine)(_DEVICE_OBJECT*, _IRP*, void*);
    void* Context;
};

/* 556 */
struct _FILE_OBJECT
{
    __int16 Type;
    __int16 Size;
    _DEVICE_OBJECT* DeviceObject;
    _VPB* Vpb;
    void* FsContext;
    void* FsContext2;
    _SECTION_OBJECT_POINTERS* SectionObjectPointer;
    void* PrivateCacheMap;
    int FinalStatus;
    _FILE_OBJECT* RelatedFileObject;
    unsigned __int8 LockOperation;
    unsigned __int8 DeletePending;
    unsigned __int8 ReadAccess;
    unsigned __int8 WriteAccess;
    unsigned __int8 DeleteAccess;
    unsigned __int8 SharedRead;
    unsigned __int8 SharedWrite;
    unsigned __int8 SharedDelete;
    unsigned int Flags;
    _UNICODE_STRING FileName;
    _LARGE_INTEGER CurrentByteOffset;
    unsigned int Waiters;
    unsigned int Busy;
    void* LastLock;
    _KEVENT Lock;
    _KEVENT Event;
    _IO_COMPLETION_CONTEXT* CompletionContext;
    unsigned __int64 IrpListLock;
    _LIST_ENTRY IrpList;
    void* FileObjectExtension;
};

/* 708 */
struct _DEVICE_MAP
{
    _OBJECT_DIRECTORY* DosDevicesDirectory;
    _OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
    void* DosDevicesDirectoryHandle;
    volatile int ReferenceCount;
    unsigned int DriveMap;
    unsigned __int8 DriveType[32];
    _EJOB* ServerSilo;
};

/* 787 */
struct $7B1C7633D0AA2678FDCC8BAA1F719E6E
{
    unsigned __int32 JobNotReallyActive : 1;
    unsigned __int32 AccountingFolded : 1;
    unsigned __int32 NewProcessReported : 1;
    unsigned __int32 ExitProcessReported : 1;
    unsigned __int32 ReportCommitChanges : 1;
    unsigned __int32 LastReportMemory : 1;
    unsigned __int32 ForceWakeCharge : 1;
    unsigned __int32 CrossSessionCreate : 1;
    unsigned __int32 NeedsHandleRundown : 1;
    unsigned __int32 RefTraceEnabled : 1;
    unsigned __int32 PicoCreated : 1;
    unsigned __int32 EmptyJobEvaluated : 1;
    unsigned __int32 DefaultPagePriority : 3;
    unsigned __int32 PrimaryTokenFrozen : 1;
    unsigned __int32 ProcessVerifierTarget : 1;
    unsigned __int32 RestrictSetThreadContext : 1;
    unsigned __int32 AffinityPermanent : 1;
    unsigned __int32 AffinityUpdateEnable : 1;
    unsigned __int32 PropagateNode : 1;
    unsigned __int32 ExplicitAffinity : 1;
    unsigned __int32 ProcessExecutionState : 2;
    unsigned __int32 EnableReadVmLogging : 1;
    unsigned __int32 EnableWriteVmLogging : 1;
    unsigned __int32 FatalAccessTerminationRequested : 1;
    unsigned __int32 DisableSystemAllowedCpuSet : 1;
    unsigned __int32 ProcessStateChangeRequest : 2;
    unsigned __int32 ProcessStateChangeInProgress : 1;
    unsigned __int32 InPrivate : 1;
};

/* 788 */
union $6052A14AE4794E9BCCA5CF920F9F20DB
{
    unsigned int Flags2;
    $7B1C7633D0AA2678FDCC8BAA1F719E6E __s1;
};

/* 789 */
struct $08F27CF7CCE24551C9037C5E7EA427C5
{
    unsigned __int32 CreateReported : 1;
    unsigned __int32 NoDebugInherit : 1;
    unsigned __int32 ProcessExiting : 1;
    unsigned __int32 ProcessDelete : 1;
    unsigned __int32 ManageExecutableMemoryWrites : 1;
    unsigned __int32 VmDeleted : 1;
    unsigned __int32 OutswapEnabled : 1;
    unsigned __int32 Outswapped : 1;
    unsigned __int32 FailFastOnCommitFail : 1;
    unsigned __int32 Wow64VaSpace4Gb : 1;
    unsigned __int32 AddressSpaceInitialized : 2;
    unsigned __int32 SetTimerResolution : 1;
    unsigned __int32 BreakOnTermination : 1;
    unsigned __int32 DeprioritizeViews : 1;
    unsigned __int32 WriteWatch : 1;
    unsigned __int32 ProcessInSession : 1;
    unsigned __int32 OverrideAddressSpace : 1;
    unsigned __int32 HasAddressSpace : 1;
    unsigned __int32 LaunchPrefetched : 1;
    unsigned __int32 Background : 1;
    unsigned __int32 VmTopDown : 1;
    unsigned __int32 ImageNotifyDone : 1;
    unsigned __int32 PdeUpdateNeeded : 1;
    unsigned __int32 VdmAllowed : 1;
    unsigned __int32 ProcessRundown : 1;
    unsigned __int32 ProcessInserted : 1;
    unsigned __int32 DefaultIoPriority : 3;
    unsigned __int32 ProcessSelfDelete : 1;
    unsigned __int32 SetTimerResolutionLink : 1;
};

/* 790 */
union $C997E678BFADE09AAE810FE8C3B8063D
{
    unsigned int Flags;
    $08F27CF7CCE24551C9037C5E7EA427C5 __s1;
};

/* 791 */
struct $2C107811C1475D6DEE5B06B393CB8A4E
{
    unsigned __int64 ExceptionPortState : 3;
};

/* 792 */
union $A288F1DA9D7E312C3AE4AFA44654E9D4
{
    void* ExceptionPortData;
    unsigned __int64 ExceptionPortValue;
    $2C107811C1475D6DEE5B06B393CB8A4E __s2;
};

/* 765 */
struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    _OBJECT_NAME_INFORMATION* ImageFileName;
};

/* 766 */
struct $3F85127412E45D453B47E0230FB8DC78
{
    unsigned __int8 WorkingSetType : 3;
    unsigned __int8 Reserved0 : 3;
    unsigned __int8 MaximumWorkingSetHard : 1;
    unsigned __int8 MinimumWorkingSetHard : 1;
    unsigned __int8 SessionMaster : 1;
    unsigned __int8 TrimmerState : 2;
    unsigned __int8 Reserved : 1;
    unsigned __int8 PageStealers : 4;
};

/* 767 */
union $34B5D8D058F71367EA0296A3BE882178
{
    $3F85127412E45D453B47E0230FB8DC78 __s0;
    unsigned __int16 u1;
};

/* 768 */
struct $56A022E0416FA8F0D143F219D5D8FA21
{
    unsigned __int8 WsleDeleted : 1;
    unsigned __int8 SvmEnabled : 1;
    unsigned __int8 ForceAge : 1;
    unsigned __int8 ForceTrim : 1;
    unsigned __int8 NewMaximum : 1;
    unsigned __int8 CommitReleaseState : 2;
};

/* 769 */
union $3C4817AD725534EBEB94E91C1F388DA9
{
    $56A022E0416FA8F0D143F219D5D8FA21 __s0;
    unsigned __int8 u2;
};

/* 770 */
struct _MMSUPPORT_FLAGS
{
    $34B5D8D058F71367EA0296A3BE882178 ___u0;
    unsigned __int8 MemoryPriority;
    $3C4817AD725534EBEB94E91C1F388DA9 ___u2;
};

/* 771 */
struct __declspec(align(8)) _MMSUPPORT_INSTANCE
{
    unsigned int NextPageColor;
    unsigned int PageFaultCount;
    unsigned __int64 TrimmedPageCount;
    struct _MMWSL_INSTANCE* VmWorkingSetList;
    _LIST_ENTRY WorkingSetExpansionLinks;
    unsigned __int64 AgeDistribution[8];
    _KGATE* ExitOutswapGate;
    unsigned __int64 MinimumWorkingSetSize;
    unsigned __int64 WorkingSetLeafSize;
    unsigned __int64 WorkingSetLeafPrivateSize;
    unsigned __int64 WorkingSetSize;
    unsigned __int64 WorkingSetPrivateSize;
    unsigned __int64 MaximumWorkingSetSize;
    unsigned __int64 PeakWorkingSetSize;
    unsigned int HardFaultCount;
    unsigned __int16 LastTrimStamp;
    unsigned __int16 PartitionId;
    unsigned __int64 SelfmapLock;
    _MMSUPPORT_FLAGS Flags;
};

/* 772 */
struct __declspec(align(64)) _MMSUPPORT_SHARED
{
    volatile int WorkingSetLock;
    int GoodCitizenWaiting;
    unsigned __int64 ReleasedCommitDebt;
    unsigned __int64 ResetPagesRepurposedCount;
    void* WsSwapSupport;
    void* CommitReleaseContext;
    void* AccessLog;
    volatile unsigned __int64 ChargedWslePages;
    unsigned __int64 ActualWslePages;
    unsigned __int64 WorkingSetCoreLock;
    void* ShadowMapping;
};

/* 773 */
struct _MMSUPPORT_FULL
{
    _MMSUPPORT_INSTANCE Instance;
    _MMSUPPORT_SHARED Shared;
};

/* 774 */
struct _ALPC_PROCESS_CONTEXT
{
    _EX_PUSH_LOCK Lock;
    _LIST_ENTRY ViewListHead;
    volatile unsigned __int64 PagedPoolQuotaCache;
};

/* 780 */
struct $86F7F41651E05A1B839282BAFC23F161
{
    unsigned __int8 Type : 3;
    unsigned __int8 Audit : 1;
    unsigned __int8 Signer : 4;
};

/* 781 */
union $63504DBF114535DBD133D4F5740C8A7F
{
    unsigned __int8 Level;
    $86F7F41651E05A1B839282BAFC23F161 __s1;
};

/* 782 */
struct _PS_PROTECTION
{
    $63504DBF114535DBD133D4F5740C8A7F ___u0;
};

/* 793 */
struct $8B1CE780B74600C3E83BA456EFE03C76
{
    unsigned __int32 Minimal : 1;
    unsigned __int32 ReplacingPageRoot : 1;
    unsigned __int32 Crashed : 1;
    unsigned __int32 JobVadsAreTracked : 1;
    unsigned __int32 VadTrackingDisabled : 1;
    unsigned __int32 AuxiliaryProcess : 1;
    unsigned __int32 SubsystemProcess : 1;
    unsigned __int32 IndirectCpuSets : 1;
    unsigned __int32 RelinquishedCommit : 1;
    unsigned __int32 HighGraphicsPriority : 1;
    unsigned __int32 CommitFailLogged : 1;
    unsigned __int32 ReserveFailLogged : 1;
    unsigned __int32 SystemProcess : 1;
    unsigned __int32 HideImageBaseAddresses : 1;
    unsigned __int32 AddressPolicyFrozen : 1;
    unsigned __int32 ProcessFirstResume : 1;
    unsigned __int32 ForegroundExternal : 1;
    unsigned __int32 ForegroundSystem : 1;
    unsigned __int32 HighMemoryPriority : 1;
    unsigned __int32 EnableProcessSuspendResumeLogging : 1;
    unsigned __int32 EnableThreadSuspendResumeLogging : 1;
    unsigned __int32 SecurityDomainChanged : 1;
    unsigned __int32 SecurityFreezeComplete : 1;
    unsigned __int32 VmProcessorHost : 1;
    unsigned __int32 VmProcessorHostTransition : 1;
    unsigned __int32 AltSyscall : 1;
    unsigned __int32 TimerResolutionIgnore : 1;
    unsigned __int32 DisallowUserTerminate : 1;
};

/* 794 */
union $E66916EFDDB1446875235A85780DBCFB
{
    unsigned int Flags3;
    $8B1CE780B74600C3E83BA456EFE03C76 __s1;
};

/* 795 */
union $991E1CBB7797929499350D8948279CF6
{
    unsigned __int64 AllowedCpuSets;
    unsigned __int64* AllowedCpuSetsIndirect;
};

/* 796 */
union $7D7CAE6D41B81FF54781561F08F4E01A
{
    unsigned __int64 DefaultCpuSets;
    unsigned __int64* DefaultCpuSetsIndirect;
};

/* 783 */
struct $85D0B69AF5B42F702B391336437C1040
{
    unsigned __int64 DelayMs : 30;
    unsigned __int64 CoalescingWindowMs : 30;
    unsigned __int64 Reserved : 1;
    unsigned __int64 NewTimerWheel : 1;
    unsigned __int64 Retry : 1;
    unsigned __int64 Locked : 1;
};

/* 784 */
volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    $85D0B69AF5B42F702B391336437C1040 __s0;
    unsigned __int64 All;
};

/* 785 */
struct _PS_PROCESS_WAKE_INFORMATION
{
    unsigned __int64 NotificationChannel;
    unsigned int WakeCounters[7];
    _JOBOBJECT_WAKE_FILTER WakeFilter;
    unsigned int NoWakeCounter;
};

/* 797 */
union $DC5EC0569021CB8BE86702C5D8BE6538
{
    _WNF_STATE_NAME WakeChannel;
    _PS_PROCESS_WAKE_INFORMATION WakeInfo;
};

/* 799 */
struct $3B2606E05EC94DAF2A442A3591BA3EDA
{
    unsigned __int32 ControlFlowGuardEnabled : 1;
    unsigned __int32 ControlFlowGuardExportSuppressionEnabled : 1;
    unsigned __int32 ControlFlowGuardStrict : 1;
    unsigned __int32 DisallowStrippedImages : 1;
    unsigned __int32 ForceRelocateImages : 1;
    unsigned __int32 HighEntropyASLREnabled : 1;
    unsigned __int32 StackRandomizationDisabled : 1;
    unsigned __int32 ExtensionPointDisable : 1;
    unsigned __int32 DisableDynamicCode : 1;
    unsigned __int32 DisableDynamicCodeAllowOptOut : 1;
    unsigned __int32 DisableDynamicCodeAllowRemoteDowngrade : 1;
    unsigned __int32 AuditDisableDynamicCode : 1;
    unsigned __int32 DisallowWin32kSystemCalls : 1;
    unsigned __int32 AuditDisallowWin32kSystemCalls : 1;
    unsigned __int32 EnableFilteredWin32kAPIs : 1;
    unsigned __int32 AuditFilteredWin32kAPIs : 1;
    unsigned __int32 DisableNonSystemFonts : 1;
    unsigned __int32 AuditNonSystemFontLoading : 1;
    unsigned __int32 PreferSystem32Images : 1;
    unsigned __int32 ProhibitRemoteImageMap : 1;
    unsigned __int32 AuditProhibitRemoteImageMap : 1;
    unsigned __int32 ProhibitLowILImageMap : 1;
    unsigned __int32 AuditProhibitLowILImageMap : 1;
    unsigned __int32 SignatureMitigationOptIn : 1;
    unsigned __int32 AuditBlockNonMicrosoftBinaries : 1;
    unsigned __int32 AuditBlockNonMicrosoftBinariesAllowStore : 1;
    unsigned __int32 LoaderIntegrityContinuityEnabled : 1;
    unsigned __int32 AuditLoaderIntegrityContinuity : 1;
    unsigned __int32 EnableModuleTamperingProtection : 1;
    unsigned __int32 EnableModuleTamperingProtectionNoInherit : 1;
    unsigned __int32 RestrictIndirectBranchPrediction : 1;
    unsigned __int32 IsolateSecurityDomain : 1;
};

/* 798 */
union $9E6F4DE8D8EBF60EF1749FF3BC13ADD5
{
    unsigned int MitigationFlags;
    $3B2606E05EC94DAF2A442A3591BA3EDA MitigationFlagsValues;
};

/* 801 */
struct $AB3F314240AC5C4019C86816511E642F
{
    unsigned __int32 EnableExportAddressFilter : 1;
    unsigned __int32 AuditExportAddressFilter : 1;
    unsigned __int32 EnableExportAddressFilterPlus : 1;
    unsigned __int32 AuditExportAddressFilterPlus : 1;
    unsigned __int32 EnableRopStackPivot : 1;
    unsigned __int32 AuditRopStackPivot : 1;
    unsigned __int32 EnableRopCallerCheck : 1;
    unsigned __int32 AuditRopCallerCheck : 1;
    unsigned __int32 EnableRopSimExec : 1;
    unsigned __int32 AuditRopSimExec : 1;
    unsigned __int32 EnableImportAddressFilter : 1;
    unsigned __int32 AuditImportAddressFilter : 1;
    unsigned __int32 DisablePageCombine : 1;
    unsigned __int32 SpeculativeStoreBypassDisable : 1;
    unsigned __int32 CetUserShadowStacks : 1;
    unsigned __int32 AuditCetUserShadowStacks : 1;
    unsigned __int32 AuditCetUserShadowStacksLogged : 1;
    unsigned __int32 UserCetSetContextIpValidation : 1;
    unsigned __int32 AuditUserCetSetContextIpValidation : 1;
    unsigned __int32 AuditUserCetSetContextIpValidationLogged : 1;
    unsigned __int32 CetUserShadowStacksStrictMode : 1;
    unsigned __int32 BlockNonCetBinaries : 1;
    unsigned __int32 BlockNonCetBinariesNonEhcont : 1;
    unsigned __int32 AuditBlockNonCetBinaries : 1;
    unsigned __int32 AuditBlockNonCetBinariesLogged : 1;
    unsigned __int32 Reserved1 : 1;
    unsigned __int32 Reserved2 : 1;
    unsigned __int32 Reserved3 : 1;
    unsigned __int32 Reserved4 : 1;
    unsigned __int32 Reserved5 : 1;
    unsigned __int32 CetDynamicApisOutOfProcOnly : 1;
    unsigned __int32 UserCetSetContextIpValidationRelaxedMode : 1;
};

/* 800 */
union $93355E6245E9B890F41B0ABE48395969
{
    unsigned int MitigationFlags2;
    $AB3F314240AC5C4019C86816511E642F MitigationFlags2Values;
};

/* 786 */
struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    _RTL_AVL_TREE Tree;
    _EX_PUSH_LOCK Lock;
};

/* 803 */
struct $10AD0A6692195125576248B3625ED027
{
    unsigned __int32 RestrictCoreSharing : 1;
    unsigned __int32 DisallowFsctlSystemCalls : 1;
    unsigned __int32 AuditDisallowFsctlSystemCalls : 1;
    unsigned __int32 MitigationFlags3Spare : 29;
};

/* 802 */
union $4D81ECBAA4002F39E816CAB804C8C6E2
{
    unsigned int MitigationFlags3;
    $10AD0A6692195125576248B3625ED027 MitigationFlags3Values;
};

/* 567 */
struct __declspec(align(16)) _EPROCESS
{
    _KPROCESS Pcb;
    _EX_PUSH_LOCK ProcessLock;
    void* UniqueProcessId;
    _LIST_ENTRY ActiveProcessLinks;
    _EX_RUNDOWN_REF RundownProtect;
    $6052A14AE4794E9BCCA5CF920F9F20DB ___u5;
    $C997E678BFADE09AAE810FE8C3B8063D ___u6;
    _LARGE_INTEGER CreateTime;
    unsigned __int64 ProcessQuotaUsage[2];
    unsigned __int64 ProcessQuotaPeak[2];
    unsigned __int64 PeakVirtualSize;
    unsigned __int64 VirtualSize;
    _LIST_ENTRY SessionProcessLinks;
    $A288F1DA9D7E312C3AE4AFA44654E9D4 ___u13;
    _EX_FAST_REF Token;
    unsigned __int64 MmReserved;
    _EX_PUSH_LOCK AddressCreationLock;
    _EX_PUSH_LOCK PageTableCommitmentLock;
    _ETHREAD* RotateInProgress;
    _ETHREAD* ForkInProgress;
    _EJOB* volatile CommitChargeJob;
    _RTL_AVL_TREE CloneRoot;
    volatile unsigned __int64 NumberOfPrivatePages;
    volatile unsigned __int64 NumberOfLockedPages;
    void* Win32Process;
    _EJOB* volatile Job;
    void* SectionObject;
    void* SectionBaseAddress;
    unsigned int Cookie;
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;
    void* Win32WindowStation;
    void* InheritedFromUniqueProcessId;
    volatile unsigned __int64 OwnerProcessId;
    _PEB* Peb;
    struct _MM_SESSION_SPACE* Session;
    void* Spare1;
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
    _HANDLE_TABLE* ObjectTable;
    void* DebugPort;
    _EWOW64PROCESS* WoW64Process;
    void* DeviceMap;
    void* EtwDataSource;
    unsigned __int64 PageDirectoryPte;
    _FILE_OBJECT* ImageFilePointer;
    unsigned __int8 ImageFileName[15];
    unsigned __int8 PriorityClass;
    void* SecurityPort;
    _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    _LIST_ENTRY JobLinks;
    void* HighestUserAddress;
    _LIST_ENTRY ThreadListHead;
    volatile unsigned int ActiveThreads;
    unsigned int ImagePathHash;
    unsigned int DefaultHardErrorProcessing;
    int LastThreadExitStatus;
    _EX_FAST_REF PrefetchTrace;
    void* LockedPagesList;
    _LARGE_INTEGER ReadOperationCount;
    _LARGE_INTEGER WriteOperationCount;
    _LARGE_INTEGER OtherOperationCount;
    _LARGE_INTEGER ReadTransferCount;
    _LARGE_INTEGER WriteTransferCount;
    _LARGE_INTEGER OtherTransferCount;
    unsigned __int64 CommitChargeLimit;
    volatile unsigned __int64 CommitCharge;
    volatile unsigned __int64 CommitChargePeak;
    _MMSUPPORT_FULL Vm;
    _LIST_ENTRY MmProcessLinks;
    unsigned int ModifiedPageCount;
    int ExitStatus;
    _RTL_AVL_TREE VadRoot;
    void* VadHint;
    unsigned __int64 VadCount;
    volatile unsigned __int64 VadPhysicalPages;
    unsigned __int64 VadPhysicalPagesLimit;
    _ALPC_PROCESS_CONTEXT AlpcContext;
    _LIST_ENTRY TimerResolutionLink;
    _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
    unsigned int RequestedTimerResolution;
    unsigned int SmallestTimerResolution;
    _LARGE_INTEGER ExitTime;
    _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;
    _EX_PUSH_LOCK InvertedFunctionTableLock;
    unsigned int ActiveThreadsHighWatermark;
    unsigned int LargePrivateVadCount;
    _EX_PUSH_LOCK ThreadListLock;
    void* WnfContext;
    _EJOB* ServerSilo;
    unsigned __int8 SignatureLevel;
    unsigned __int8 SectionSignatureLevel;
    _PS_PROTECTION Protection;
    unsigned __int8 HangCount : 3;
    unsigned __int8 GhostCount : 3;
    unsigned __int8 PrefilterException : 1;
    $E66916EFDDB1446875235A85780DBCFB ___u94;
    int DeviceAsid;
    void* SvmData;
    _EX_PUSH_LOCK SvmProcessLock;
    unsigned __int64 SvmLock;
    _LIST_ENTRY SvmProcessDeviceListHead;
    unsigned __int64 LastFreezeInterruptTime;
    _PROCESS_DISK_COUNTERS* DiskCounters;
    void* PicoContext;
    void* EnclaveTable;
    unsigned __int64 EnclaveNumber;
    _EX_PUSH_LOCK EnclaveLock;
    unsigned int HighPriorityFaultsAllowed;
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;
    void* VmContext;
    unsigned __int64 SequenceNumber;
    unsigned __int64 CreateInterruptTime;
    unsigned __int64 CreateUnbiasedInterruptTime;
    unsigned __int64 TotalUnbiasedFrozenTime;
    unsigned __int64 LastAppStateUpdateTime;
    unsigned __int64 LastAppStateUptime : 61;
    unsigned __int64 LastAppState : 3;
    volatile unsigned __int64 SharedCommitCharge;
    _EX_PUSH_LOCK SharedCommitLock;
    _LIST_ENTRY SharedCommitLinks;
    $991E1CBB7797929499350D8948279CF6 ___u119;
    $7D7CAE6D41B81FF54781561F08F4E01A ___u120;
    void* DiskIoAttribution;
    void* DxgProcess;
    unsigned int Win32KFilterSet;
    volatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;
    volatile unsigned int KTimerSets;
    volatile unsigned int KTimer2Sets;
    volatile unsigned int ThreadTimerSets;
    unsigned __int64 VirtualTimerListLock;
    _LIST_ENTRY VirtualTimerListHead;
    $DC5EC0569021CB8BE86702C5D8BE6538 ___u130;
    $9E6F4DE8D8EBF60EF1749FF3BC13ADD5 ___u131;
    $93355E6245E9B890F41B0ABE48395969 ___u132;
    void* PartitionObject;
    unsigned __int64 SecurityDomain;
    unsigned __int64 ParentSecurityDomain;
    void* CoverageSamplerContext;
    void* MmHotPatchContext;
    _RTL_AVL_TREE DynamicEHContinuationTargetsTree;
    _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
    _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;
    unsigned int DisabledComponentFlags;
    unsigned int* volatile PathRedirectionHashes;
    $4D81ECBAA4002F39E816CAB804C8C6E2 ___u143;
};

/* 718 */
struct _TIME_FIELDS
{
    __int16 Year;
    __int16 Month;
    __int16 Day;
    __int16 Hour;
    __int16 Minute;
    __int16 Second;
    __int16 Milliseconds;
    __int16 Weekday;
};

/* 719 */
struct _RTL_TIME_ZONE_INFORMATION
{
    int Bias;
    wchar_t StandardName[32];
    _TIME_FIELDS StandardStart;
    int StandardBias;
    wchar_t DaylightName[32];
    _TIME_FIELDS DaylightStart;
    int DaylightBias;
};

/* 720 */
struct __declspec(align(4)) _RTL_DYNAMIC_TIME_ZONE_INFORMATION
{
    _RTL_TIME_ZONE_INFORMATION tzi;
    wchar_t TimeZoneKeyName[128];
    unsigned __int8 DynamicDaylightTimeDisabled;
};

/* 721 */
struct _TIMEZONE_CHANGE_EVENT
{
    _KDPC Dpc;
    _KTIMER Timer;
    _WORK_QUEUE_ITEM WorkItem;
};

/* 722 */
struct __declspec(align(8)) _EX_TIMEZONE_STATE
{
    _RTL_DYNAMIC_TIME_ZONE_INFORMATION TimeZoneInformation;
    unsigned int CurrentTimeZoneId;
    int LastTimeZoneBias;
    _LARGE_INTEGER TimeZoneBias;
    _TIMEZONE_CHANGE_EVENT TimeZone;
    _TIMEZONE_CHANGE_EVENT Century;
    _TIMEZONE_CHANGE_EVENT NextYear;
    int OkToTimeZoneRefresh;
    _LARGE_INTEGER NextCenturyTimeInUTC;
    _TIME_FIELDS NextCenturyTimeFieldsInLocalTime;
    _LARGE_INTEGER NextYearTimeInUTC;
    _TIME_FIELDS NextYearTimeFieldsInLocalTime;
    __int16 LastDynamicTimeZoneYear;
    _LARGE_INTEGER NextSystemCutoverInUTC;
    unsigned int RefreshFailures;
};

/* 723 */
struct _SILO_USER_SHARED_DATA
{
    unsigned int ServiceSessionId;
    unsigned int ActiveConsoleId;
    __int64 ConsoleSessionForegroundProcessId;
    _NT_PRODUCT_TYPE NtProductType;
    unsigned int SuiteMask;
    unsigned int SharedUserSessionId;
    unsigned __int8 IsMultiSessionSku;
    wchar_t NtSystemRoot[260];
    unsigned __int16 UserModeGlobalLogger[16];
    unsigned int TimeZoneId;
    volatile int TimeZoneBiasStamp;
    _KSYSTEM_TIME TimeZoneBias;
    _LARGE_INTEGER TimeZoneBiasEffectiveStart;
    _LARGE_INTEGER TimeZoneBiasEffectiveEnd;
};

/* 553 */
struct _IO_CLIENT_EXTENSION
{
    _IO_CLIENT_EXTENSION* NextExtension;
    void* ClientIdentificationAddress;
};

/* 680 */
struct _FS_FILTER_CALLBACKS
{
    unsigned int SizeOfFsFilterCallbacks;
    unsigned int Reserved;
    int(__fastcall* PreAcquireForSectionSynchronization)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostAcquireForSectionSynchronization)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreReleaseForSectionSynchronization)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostReleaseForSectionSynchronization)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreAcquireForCcFlush)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostAcquireForCcFlush)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreReleaseForCcFlush)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostReleaseForCcFlush)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreAcquireForModifiedPageWriter)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostAcquireForModifiedPageWriter)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreReleaseForModifiedPageWriter)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostReleaseForModifiedPageWriter)(_FS_FILTER_CALLBACK_DATA*, int, void*);
    int(__fastcall* PreQueryOpen)(_FS_FILTER_CALLBACK_DATA*, void**);
    void(__fastcall* PostQueryOpen)(_FS_FILTER_CALLBACK_DATA*, int, void*);
};

/* 682 */
struct __declspec(align(8)) _FILE_BASIC_INFORMATION
{
    _LARGE_INTEGER CreationTime;
    _LARGE_INTEGER LastAccessTime;
    _LARGE_INTEGER LastWriteTime;
    _LARGE_INTEGER ChangeTime;
    unsigned int FileAttributes;
};

/* 683 */
struct __declspec(align(4)) _FILE_STANDARD_INFORMATION
{
    _LARGE_INTEGER AllocationSize;
    _LARGE_INTEGER EndOfFile;
    unsigned int NumberOfLinks;
    unsigned __int8 DeletePending;
    unsigned __int8 Directory;
};

/* 684 */
struct __declspec(align(8)) _FILE_NETWORK_OPEN_INFORMATION
{
    _LARGE_INTEGER CreationTime;
    _LARGE_INTEGER LastAccessTime;
    _LARGE_INTEGER LastWriteTime;
    _LARGE_INTEGER ChangeTime;
    _LARGE_INTEGER AllocationSize;
    _LARGE_INTEGER EndOfFile;
    unsigned int FileAttributes;
};

/* 685 */
struct _COMPRESSED_DATA_INFO
{
    unsigned __int16 CompressionFormatAndEngine;
    unsigned __int8 CompressionUnitShift;
    unsigned __int8 ChunkShift;
    unsigned __int8 ClusterShift;
    unsigned __int8 Reserved;
    unsigned __int16 NumberOfChunks;
    unsigned int CompressedChunkSizes[1];
};

/* 578 */
struct _IO_SECURITY_CONTEXT
{
    _SECURITY_QUALITY_OF_SERVICE* SecurityQos;
    _ACCESS_STATE* AccessState;
    unsigned int DesiredAccess;
    unsigned int FullCreateOptions;
};

/* 579 */
struct __declspec(align(8)) _NAMED_PIPE_CREATE_PARAMETERS
{
    unsigned int NamedPipeType;
    unsigned int ReadMode;
    unsigned int CompletionMode;
    unsigned int MaximumInstances;
    unsigned int InboundQuota;
    unsigned int OutboundQuota;
    _LARGE_INTEGER DefaultTimeout;
    unsigned __int8 TimeoutSpecified;
};

/* 580 */
struct __declspec(align(8)) _MAILSLOT_CREATE_PARAMETERS
{
    unsigned int MailslotQuota;
    unsigned int MaximumMessageSize;
    _LARGE_INTEGER ReadTimeout;
    unsigned __int8 TimeoutSpecified;
};

/* 583 */
struct _SID_IDENTIFIER_AUTHORITY
{
    unsigned __int8 Value[6];
};

/* 584 */
struct _SID
{
    unsigned __int8 Revision;
    unsigned __int8 SubAuthorityCount;
    _SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    unsigned int SubAuthority[1];
};

/* 585 */
struct _FILE_GET_QUOTA_INFORMATION
{
    unsigned int NextEntryOffset;
    unsigned int SidLength;
    _SID Sid;
};

/* 586 */
struct _INTERFACE
{
    unsigned __int16 Size;
    unsigned __int16 Version;
    void* Context;
    void(__fastcall* InterfaceReference)(void*);
    void(__fastcall* InterfaceDereference)(void*);
};

/* 587 */
struct _DEVICE_CAPABILITIES
{
    unsigned __int16 Size;
    unsigned __int16 Version;
    unsigned __int32 DeviceD1 : 1;
    unsigned __int32 DeviceD2 : 1;
    unsigned __int32 LockSupported : 1;
    unsigned __int32 EjectSupported : 1;
    unsigned __int32 Removable : 1;
    unsigned __int32 DockDevice : 1;
    unsigned __int32 UniqueID : 1;
    unsigned __int32 SilentInstall : 1;
    unsigned __int32 RawDeviceOK : 1;
    unsigned __int32 SurpriseRemovalOK : 1;
    unsigned __int32 WakeFromD0 : 1;
    unsigned __int32 WakeFromD1 : 1;
    unsigned __int32 WakeFromD2 : 1;
    unsigned __int32 WakeFromD3 : 1;
    unsigned __int32 HardwareDisabled : 1;
    unsigned __int32 NonDynamic : 1;
    unsigned __int32 WarmEjectSupported : 1;
    unsigned __int32 NoDisplayInUI : 1;
    unsigned __int32 Reserved1 : 1;
    unsigned __int32 WakeFromInterrupt : 1;
    unsigned __int32 SecureDevice : 1;
    unsigned __int32 ChildOfVgaEnabledBridge : 1;
    unsigned __int32 DecodeIoOnBoot : 1;
    unsigned __int32 Reserved : 9;
    unsigned int Address;
    unsigned int UINumber;
    _DEVICE_POWER_STATE DeviceState[7];
    _SYSTEM_POWER_STATE SystemWake;
    _DEVICE_POWER_STATE DeviceWake;
    unsigned int D1Latency;
    unsigned int D2Latency;
    unsigned int D3Latency;
};

/* 589 */
struct $130A7129919975FDC4C81447BA8BA5C9
{
    unsigned int Length;
    unsigned int Alignment;
    _LARGE_INTEGER MinimumAddress;
    _LARGE_INTEGER MaximumAddress;
};

/* 590 */
struct $EAC54C29E1E751287C1E6AB93FAAFA8C
{
    unsigned int MinimumVector;
    unsigned int MaximumVector;
    unsigned __int16 AffinityPolicy;
    unsigned __int16 Group;
    _IRQ_PRIORITY PriorityPolicy;
    unsigned __int64 TargetedProcessors;
};

/* 591 */
struct $290D34FD7868E94AFEC0383C08CB9B28
{
    unsigned int MinimumChannel;
    unsigned int MaximumChannel;
};

/* 592 */
struct $66D8BAE383F9288207BB026A64AFF51A
{
    unsigned int RequestLine;
    unsigned int Reserved;
    unsigned int Channel;
    unsigned int TransferWidth;
};

/* 593 */
struct $B14DB811EDFC1214B110A98B000FF49B
{
    unsigned int Data[3];
};

/* 594 */
struct $CF7D779FCF8501AF42168A39ACA3AE76
{
    unsigned int Length;
    unsigned int MinBusNumber;
    unsigned int MaxBusNumber;
    unsigned int Reserved;
};

/* 595 */
struct $5D61DD2957AFDEE7ED67BD2EDF2BEA99
{
    unsigned int Priority;
    unsigned int Reserved1;
    unsigned int Reserved2;
};

/* 596 */
struct $E4AC98A553C00A4AE7CE1E56EA8D3AA4
{
    unsigned int Length40;
    unsigned int Alignment40;
    _LARGE_INTEGER MinimumAddress;
    _LARGE_INTEGER MaximumAddress;
};

/* 597 */
struct $F93BBC2A850942DAAA7E6EE5F3A354EB
{
    unsigned int Length48;
    unsigned int Alignment48;
    _LARGE_INTEGER MinimumAddress;
    _LARGE_INTEGER MaximumAddress;
};

/* 598 */
struct $77FF8D7A9174E96165AF613B66560A06
{
    unsigned int Length64;
    unsigned int Alignment64;
    _LARGE_INTEGER MinimumAddress;
    _LARGE_INTEGER MaximumAddress;
};

/* 599 */
struct $EDAC022CDA01C704ED739E663C6F28A2
{
    unsigned __int8 Class;
    unsigned __int8 Type;
    unsigned __int8 Reserved1;
    unsigned __int8 Reserved2;
    unsigned int IdLowPart;
    unsigned int IdHighPart;
};

/* 600 */
union $FD7FCFBBF1ED7538D0AC0BB585386FBC
{
    $130A7129919975FDC4C81447BA8BA5C9 Port;
    $130A7129919975FDC4C81447BA8BA5C9 Memory;
    $EAC54C29E1E751287C1E6AB93FAAFA8C Interrupt;
    $290D34FD7868E94AFEC0383C08CB9B28 Dma;
    $66D8BAE383F9288207BB026A64AFF51A DmaV3;
    $130A7129919975FDC4C81447BA8BA5C9 Generic;
    $B14DB811EDFC1214B110A98B000FF49B DevicePrivate;
    $CF7D779FCF8501AF42168A39ACA3AE76 BusNumber;
    $5D61DD2957AFDEE7ED67BD2EDF2BEA99 ConfigData;
    $E4AC98A553C00A4AE7CE1E56EA8D3AA4 Memory40;
    $F93BBC2A850942DAAA7E6EE5F3A354EB Memory48;
    $77FF8D7A9174E96165AF613B66560A06 Memory64;
    $EDAC022CDA01C704ED739E663C6F28A2 Connection;
};

/* 588 */
struct _IO_RESOURCE_DESCRIPTOR
{
    unsigned __int8 Option;
    unsigned __int8 Type;
    unsigned __int8 ShareDisposition;
    unsigned __int8 Spare1;
    unsigned __int16 Flags;
    unsigned __int16 Spare2;
    $FD7FCFBBF1ED7538D0AC0BB585386FBC u;
};

/* 601 */
struct _IO_RESOURCE_LIST
{
    unsigned __int16 Version;
    unsigned __int16 Revision;
    unsigned int Count;
    _IO_RESOURCE_DESCRIPTOR Descriptors[1];
};

/* 602 */
struct _IO_RESOURCE_REQUIREMENTS_LIST
{
    unsigned int ListSize;
    _INTERFACE_TYPE InterfaceType;
    unsigned int BusNumber;
    unsigned int SlotNumber;
    unsigned int Reserved[3];
    unsigned int AlternativeLists;
    _IO_RESOURCE_LIST List[1];
};

/* 603 */
struct _POWER_SEQUENCE
{
    unsigned int SequenceD1;
    unsigned int SequenceD2;
    unsigned int SequenceD3;
};

/* 613 */
#pragma pack(push, 1)
struct $8503B6F693FA9C0BBAB1BF53F905DB8D
{
  _LARGE_INTEGER Start;
  unsigned int Length;
};
#pragma pack(pop)

/* 614 */
struct $A4C8F98C438ECB53B11C8817B10C66B5
{
    unsigned __int16 Level;
    unsigned __int16 Group;
    unsigned int Vector;
    unsigned __int64 Affinity;
};

/* 610 */
struct $69138CE2BB6A34B6EE0EDED588F41203
{
    unsigned __int16 Group;
    unsigned __int16 MessageCount;
    unsigned int Vector;
    unsigned __int64 Affinity;
};

/* 609 */
union $0F11D120215A904468D7C13BA04E3E03
{
    $69138CE2BB6A34B6EE0EDED588F41203 Raw;
    $A4C8F98C438ECB53B11C8817B10C66B5 Translated;
};

/* 615 */
struct $37E23FF4EAC8CD988EBD57B7280CB290
{
    $0F11D120215A904468D7C13BA04E3E03 ___u0;
};

/* 616 */
struct $72748C417E05990EBECC6BB8D043D8B0
{
    unsigned int Channel;
    unsigned int Port;
    unsigned int Reserved1;
};

/* 617 */
struct $CC0360DD0852F9AAB36A2B2BBC2DF141
{
    unsigned int Channel;
    unsigned int RequestLine;
    unsigned __int8 TransferWidth;
    unsigned __int8 Reserved1;
    unsigned __int8 Reserved2;
    unsigned __int8 Reserved3;
};

/* 619 */
struct $6C467299E1DD150E8FDAFB428553E9E9
{
    unsigned int Start;
    unsigned int Length;
    unsigned int Reserved;
};

/* 620 */
struct $D735038633D506DCA1748B01FF7747C2
{
    unsigned int DataSize;
    unsigned int Reserved1;
    unsigned int Reserved2;
};

/* 621 */
#pragma pack(push, 1)
struct $B276437CEF68E2905F7C8D6644F1C387
{
  _LARGE_INTEGER Start;
  unsigned int Length40;
};

/* 622 */
struct $B043EE6E7AEB504FE4C86B0B28D956B7
{
  _LARGE_INTEGER Start;
  unsigned int Length48;
};

/* 623 */
struct $3F64B1B96FA14F04BAE177084A7F893B
{
  _LARGE_INTEGER Start;
  unsigned int Length64;
};
#pragma pack(pop)

/* 625 */
union $C8BABAD661B27BAF559DF156E837BDE2
{
    $8503B6F693FA9C0BBAB1BF53F905DB8D Generic;
    $8503B6F693FA9C0BBAB1BF53F905DB8D Port;
    $A4C8F98C438ECB53B11C8817B10C66B5 Interrupt;
    $37E23FF4EAC8CD988EBD57B7280CB290 MessageInterrupt;
    $8503B6F693FA9C0BBAB1BF53F905DB8D Memory;
    $72748C417E05990EBECC6BB8D043D8B0 Dma;
    $CC0360DD0852F9AAB36A2B2BBC2DF141 DmaV3;
    $B14DB811EDFC1214B110A98B000FF49B DevicePrivate;
    $6C467299E1DD150E8FDAFB428553E9E9 BusNumber;
    $D735038633D506DCA1748B01FF7747C2 DeviceSpecificData;
    $B276437CEF68E2905F7C8D6644F1C387 Memory40;
    $B043EE6E7AEB504FE4C86B0B28D956B7 Memory48;
    $3F64B1B96FA14F04BAE177084A7F893B Memory64;
    $EDAC022CDA01C704ED739E663C6F28A2 Connection;
};

/* 612 */
#pragma pack(push, 1)
struct _CM_PARTIAL_RESOURCE_DESCRIPTOR
{
    unsigned __int8 Type;
    unsigned __int8 ShareDisposition;
    unsigned __int16 Flags;
    $C8BABAD661B27BAF559DF156E837BDE2 u;
};
#pragma pack(pop)
/* 626 */
struct _CM_PARTIAL_RESOURCE_LIST
{
    unsigned __int16 Version;
    unsigned __int16 Revision;
    unsigned int Count;
    _CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
};

/* 627 */
struct _CM_FULL_RESOURCE_DESCRIPTOR
{
    _INTERFACE_TYPE InterfaceType;
    unsigned int BusNumber;
    _CM_PARTIAL_RESOURCE_LIST PartialResourceList;
};

/* 628 */
struct _CM_RESOURCE_LIST
{
    unsigned int Count;
    _CM_FULL_RESOURCE_DESCRIPTOR List[1];
};

/* 555 */
struct _SECTION_OBJECT_POINTERS
{
    void* DataSectionObject;
    void* SharedCacheMap;
    void* ImageSectionObject;
};

/* 557 */
struct _IO_COMPLETION_CONTEXT
{
    void* Port;
    void* Key;
    __int64 UsageCount;
};

/* 709 */
struct _OBJECT_DIRECTORY
{
    _OBJECT_DIRECTORY_ENTRY* HashBuckets[37];
    _EX_PUSH_LOCK Lock;
    _DEVICE_MAP* DeviceMap;
    _OBJECT_DIRECTORY* ShadowDirectory;
    void* NamespaceEntry;
    void* SessionObject;
    unsigned int Flags;
    unsigned int SessionId;
};

/* 817 */
struct $674F156C788F89EBCBFDC1492D6BA90B
{
    unsigned __int8 StrictFIFO : 1;
    unsigned __int8 EnableHandleExceptions : 1;
    unsigned __int8 Rundown : 1;
    unsigned __int8 Duplicated : 1;
    unsigned __int8 RaiseUMExceptionOnInvalidHandleClose : 1;
};

/* 818 */
union $5DAA1C10533DCC41AEBED4233F033E04
{
    unsigned int Flags;
    $674F156C788F89EBCBFDC1492D6BA90B __s1;
};

/* 814 */
struct __declspec(align(64)) _HANDLE_TABLE_FREE_LIST
{
    _EX_PUSH_LOCK FreeListLock;
    _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;
    _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;
    int HandleCount;
    unsigned int HighWaterMark;
};

/* 819 */
struct $030F8289E0C4288886FF060E9D8F9A68
{
    unsigned __int8 ActualEntry[32];
    _HANDLE_TRACE_DEBUG_INFO* DebugInfo;
};

/* 820 */
union $9CE3AAD50FC0B0D9541489A7BE38BB95
{
    _HANDLE_TABLE_FREE_LIST FreeLists[1];
    $030F8289E0C4288886FF060E9D8F9A68 __s1;
};

/* 762 */
struct _HANDLE_TABLE
{
    unsigned int NextHandleNeedingPool;
    int ExtraInfoPages;
    volatile unsigned __int64 TableCode;
    _EPROCESS* QuotaProcess;
    _LIST_ENTRY HandleTableList;
    unsigned int UniqueProcessId;
    $5DAA1C10533DCC41AEBED4233F033E04 ___u6;
    _EX_PUSH_LOCK HandleContentionEvent;
    _EX_PUSH_LOCK HandleTableLock;
    $9CE3AAD50FC0B0D9541489A7BE38BB95 ___u9;
};

/* 763 */
struct _EWOW64PROCESS
{
    void* Peb;
    unsigned __int16 Machine;
    _SYSTEM_DLL_TYPE NtdllType;
};

/* 764 */
struct _OBJECT_NAME_INFORMATION
{
    _UNICODE_STRING Name;
};

/* 775 */
struct _PO_DIAG_STACK_RECORD
{
    unsigned int StackDepth;
    void* Stack[1];
};

/* 777 */
union $916738358CBA556EC7AAE2E56DE412D8
{
    _IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
    _DYNAMIC_FUNCTION_TABLE* DynamicTable;
};

/* 778 */
struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    $916738358CBA556EC7AAE2E56DE412D8 ___u0;
    void* ImageBase;
    unsigned int SizeOfImage;
    unsigned int SizeOfTable;
};

/* 779 */
struct _INVERTED_FUNCTION_TABLE
{
    unsigned int CurrentSize;
    unsigned int MaximumSize;
    volatile unsigned int Epoch;
    unsigned __int8 Overflow;
    _INVERTED_FUNCTION_TABLE_ENTRY TableEntry[512];
};

/* 674 */
struct $FA41E37569E7BC0AF86000F1B6092389
{
    _LARGE_INTEGER* EndingOffset;
    _ERESOURCE** ResourceToRelease;
};

/* 675 */
struct $6E4C83F2A89D0D096E5AA852EC8AFF91
{
    _ERESOURCE* ResourceToRelease;
};

/* 676 */
struct __declspec(align(8)) $1560BA015A2068F2583E62C5CD961A89
{
    _FS_FILTER_SECTION_SYNC_TYPE SyncType;
    unsigned int PageProtection;
    _FS_FILTER_SECTION_SYNC_OUTPUT* OutputInformation;
    unsigned int Flags;
};

/* 677 */
struct $4153F868308207D16FDC2CD8F63C76DA
{
    _IRP* Irp;
    void* FileInformation;
    unsigned int* Length;
    _FILE_INFORMATION_CLASS FileInformationClass;
    int CompletionStatus;
};

/* 678 */
struct $6C06832CE408E29966CF29075B64912A
{
    void* Argument1;
    void* Argument2;
    void* Argument3;
    void* Argument4;
    void* Argument5;
};

/* 673 */
union _FS_FILTER_PARAMETERS
{
    $FA41E37569E7BC0AF86000F1B6092389 AcquireForModifiedPageWriter;
    $6E4C83F2A89D0D096E5AA852EC8AFF91 ReleaseForModifiedPageWriter;
    $1560BA015A2068F2583E62C5CD961A89 AcquireForSectionSynchronization;
    $4153F868308207D16FDC2CD8F63C76DA QueryOpen;
    $6C06832CE408E29966CF29075B64912A Others;
};

/* 679 */
struct _FS_FILTER_CALLBACK_DATA
{
    unsigned int SizeOfFsFilterCallbackData;
    unsigned __int8 Operation;
    unsigned __int8 Reserved;
    _DEVICE_OBJECT* DeviceObject;
    _FILE_OBJECT* FileObject;
    _FS_FILTER_PARAMETERS Parameters;
};

/* 571 */
struct __declspec(align(4)) _SECURITY_QUALITY_OF_SERVICE
{
    unsigned int Length;
    _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    unsigned __int8 ContextTrackingMode;
    unsigned __int8 EffectiveOnly;
};

/* 572 */
struct _SECURITY_SUBJECT_CONTEXT
{
    void* ClientToken;
    _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    void* PrimaryToken;
    void* ProcessAuditId;
};

/* 573 */
struct _LUID_AND_ATTRIBUTES
{
    _LUID Luid;
    unsigned int Attributes;
};

/* 574 */
struct _INITIAL_PRIVILEGE_SET
{
    unsigned int PrivilegeCount;
    unsigned int Control;
    _LUID_AND_ATTRIBUTES Privilege[3];
};

/* 575 */
struct _PRIVILEGE_SET
{
    unsigned int PrivilegeCount;
    unsigned int Control;
    _LUID_AND_ATTRIBUTES Privilege[1];
};

/* 577 */
union $21D042CF191E52B29C42D83612F1D8C8
{
    _INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
    _PRIVILEGE_SET PrivilegeSet;
};

/* 576 */
struct _ACCESS_STATE
{
    _LUID OperationID;
    unsigned __int8 SecurityEvaluated;
    unsigned __int8 GenerateAudit;
    unsigned __int8 GenerateOnClose;
    unsigned __int8 PrivilegesAllocated;
    unsigned int Flags;
    unsigned int RemainingDesiredAccess;
    unsigned int PreviouslyGrantedAccess;
    unsigned int OriginalDesiredAccess;
    _SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
    void* SecurityDescriptor;
    void* AuxData;
    $21D042CF191E52B29C42D83612F1D8C8 Privileges;
    unsigned __int8 AuditPrivileges;
    _UNICODE_STRING ObjectName;
    _UNICODE_STRING ObjectTypeName;
};

/* 707 */
struct __declspec(align(8)) _OBJECT_DIRECTORY_ENTRY
{
    _OBJECT_DIRECTORY_ENTRY* ChainLink;
    void* Object;
    unsigned int HashValue;
};

/* 809 */
struct $E5B3C52FE72490EE6A49ADBB8529F30E
{
    volatile __int64 VolatileLowValue;
    __int64 HighValue;
};

/* 810 */
struct $6E0B9871B83DCFD0BA079B103C96C6C6
{
    __int64 LowValue;
    _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
};

/* 806 */
struct $97D278A0CD42BCAC54E6F6C01CA8A55F
{
    unsigned __int32 TagBits : 2;
    unsigned __int32 Index : 30;
};

/* 807 */
union $B8881A4E75818BD9A20ADA96E29A0C78
{
    $97D278A0CD42BCAC54E6F6C01CA8A55F __s0;
    void* GenericHandleOverlay;
    unsigned __int64 Value;
};

/* 808 */
struct _EXHANDLE
{
    $B8881A4E75818BD9A20ADA96E29A0C78 ___u0;
};

/* 811 */
struct $CB311EFE4FC8BA22F1DA2EFE7EBCF3CE
{
    _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;
    _EXHANDLE LeafHandleValue;
};

/* 812 */
struct $2C5CC9DC28D9F2B79C281990513743F8
{
    __int64 RefCountField;
    unsigned __int32 GrantedAccessBits : 25;
    unsigned __int32 NoRightsUpgrade : 1;
    unsigned __int32 Spare1 : 6;
    unsigned int Spare2;
};

/* 813 */
struct $32CC4987E53F1E217602E82975918B96
{
    unsigned __int64 Unlocked : 1;
    unsigned __int64 RefCnt : 16;
    unsigned __int64 Attributes : 3;
    unsigned __int64 ObjectPointerBits : 44;
};

/* 805 */
union _HANDLE_TABLE_ENTRY
{
    $E5B3C52FE72490EE6A49ADBB8529F30E __s0;
    $6E0B9871B83DCFD0BA079B103C96C6C6 __s1;
    $CB311EFE4FC8BA22F1DA2EFE7EBCF3CE __s2;
    $2C5CC9DC28D9F2B79C281990513743F8 __s3;
    $32CC4987E53F1E217602E82975918B96 __s4;
};

/* 815 */
struct _HANDLE_TRACE_DB_ENTRY
{
    _CLIENT_ID ClientId;
    void* Handle;
    unsigned int Type;
    void* StackTrace[16];
};

/* 816 */
struct _HANDLE_TRACE_DEBUG_INFO
{
    int RefCount;
    unsigned int TableSize;
    unsigned int BitMaskFlags;
    _FAST_MUTEX CloseCompactionLock;
    unsigned int CurrentStackIndex;
    _HANDLE_TRACE_DB_ENTRY TraceDb[1];
};

/* 776 */
struct _DYNAMIC_FUNCTION_TABLE
{
    _LIST_ENTRY ListEntry;
    _IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
    _LARGE_INTEGER TimeStamp;
    unsigned __int64 MinimumAddress;
    unsigned __int64 MaximumAddress;
    unsigned __int64 BaseAddress;
    _IMAGE_RUNTIME_FUNCTION_ENTRY* (__fastcall* Callback)(unsigned __int64, void*);
    void* Context;
    wchar_t* OutOfProcessCallbackDll;
    _FUNCTION_TABLE_TYPE Type;
    unsigned int EntryCount;
    _RTL_BALANCED_NODE TreeNodeMin;
    _RTL_BALANCED_NODE TreeNodeMax;
};

/* 565 */
struct _FS_FILTER_SECTION_SYNC_OUTPUT
{
    unsigned int StructureSize;
    unsigned int SizeReturned;
    unsigned int Flags;
    unsigned int DesiredReadAlignment;
};

/* 804 */
struct _HANDLE_TABLE_ENTRY_INFO
{
    unsigned int AuditMask;
    unsigned int MaxRelativeAccessMask;
};

/* 821 */
struct _GENERIC_MAPPING
{
    unsigned int GenericRead;
    unsigned int GenericWrite;
    unsigned int GenericExecute;
    unsigned int GenericAll;
};

/* 822 */
struct _ACCESS_REASONS
{
    unsigned int Data[32];
};

/* 823 */
struct __declspec(align(8)) _AUX_ACCESS_DATA
{
    _PRIVILEGE_SET* PrivilegesUsed;
    _GENERIC_MAPPING GenericMapping;
    unsigned int AccessesToAudit;
    unsigned int MaximumAuditMask;
    _GUID TransactionId;
    void* NewSecurityDescriptor;
    void* ExistingSecurityDescriptor;
    void* ParentSecurityDescriptor;
    void(__fastcall* DeRefSecurityDescriptor)(void*, void*);
    void* SDLock;
    _ACCESS_REASONS AccessReasons;
    unsigned __int8 GenerateStagingEvents;
};

/* 824 */
struct __declspec(align(8)) _OBJECT_DUMP_CONTROL
{
    void* Stream;
    unsigned int Detail;
};

/* 825 */
struct _OB_EXTENDED_PARSE_PARAMETERS
{
    unsigned __int16 Length;
    unsigned int RestrictedAccessMask;
    _EJOB* Silo;
};

/* 826 */
struct $6C0C97183427D3B13AB876397F49C231
{
    unsigned __int8 CaseInsensitive : 1;
    unsigned __int8 UnnamedObjectsOnly : 1;
    unsigned __int8 UseDefaultObject : 1;
    unsigned __int8 SecurityRequired : 1;
    unsigned __int8 MaintainHandleCount : 1;
    unsigned __int8 MaintainTypeList : 1;
    unsigned __int8 SupportsObjectCallbacks : 1;
    unsigned __int8 CacheAligned : 1;
    unsigned __int8 UseExtendedParameters : 1;
    unsigned __int8 Reserved : 7;
};

/* 827 */
union $27A826164319C237F7FB14C0D144D643
{
    unsigned __int16 ObjectTypeFlags;
    $6C0C97183427D3B13AB876397F49C231 __s1;
};

/* 828 */
union $D32C7BD7D879174F328464F18CC64A4E
{
    int(__fastcall* ParseProcedure)(void*, void*, _ACCESS_STATE*, char, unsigned int, _UNICODE_STRING*, _UNICODE_STRING*, void*, _SECURITY_QUALITY_OF_SERVICE*, void**);
    int(__fastcall* ParseProcedureEx)(void*, void*, _ACCESS_STATE*, char, unsigned int, _UNICODE_STRING*, _UNICODE_STRING*, void*, _SECURITY_QUALITY_OF_SERVICE*, _OB_EXTENDED_PARSE_PARAMETERS*, void**);
};

/* 829 */
struct _OBJECT_TYPE_INITIALIZER
{
    unsigned __int16 Length;
    $27A826164319C237F7FB14C0D144D643 ___u1;
    unsigned int ObjectTypeCode;
    unsigned int InvalidAttributes;
    _GENERIC_MAPPING GenericMapping;
    unsigned int ValidAccessMask;
    unsigned int RetainAccess;
    _POOL_TYPE PoolType;
    unsigned int DefaultPagedPoolCharge;
    unsigned int DefaultNonPagedPoolCharge;
    void(__fastcall* DumpProcedure)(void*, _OBJECT_DUMP_CONTROL*);
    int(__fastcall* OpenProcedure)(_OB_OPEN_REASON, char, _EPROCESS*, void*, unsigned int*, unsigned int);
    void(__fastcall* CloseProcedure)(_EPROCESS*, void*, unsigned __int64, unsigned __int64);
    void(__fastcall* DeleteProcedure)(void*);
    $D32C7BD7D879174F328464F18CC64A4E ___u14;
    int(__fastcall* SecurityProcedure)(void*, _SECURITY_OPERATION_CODE, unsigned int*, void*, unsigned int*, void**, _POOL_TYPE, _GENERIC_MAPPING*, char);
    int(__fastcall* QueryNameProcedure)(void*, unsigned __int8, _OBJECT_NAME_INFORMATION*, unsigned int, unsigned int*, char);
    unsigned __int8(__fastcall* OkayToCloseProcedure)(_EPROCESS*, void*, void*, char);
    unsigned int WaitObjectFlagMask;
    unsigned __int16 WaitObjectFlagOffset;
    unsigned __int16 WaitObjectPointerOffset;
};

/* 830 */
struct _OBJECT_TYPE
{
    _LIST_ENTRY TypeList;
    _UNICODE_STRING Name;
    void* DefaultObject;
    unsigned __int8 Index;
    unsigned int TotalNumberOfObjects;
    unsigned int TotalNumberOfHandles;
    unsigned int HighWaterNumberOfObjects;
    unsigned int HighWaterNumberOfHandles;
    _OBJECT_TYPE_INITIALIZER TypeInfo;
    _EX_PUSH_LOCK TypeLock;
    unsigned int Key;
    _LIST_ENTRY CallbackList;
};

/* 831 */
struct _OBJECT_HANDLE_INFORMATION
{
    unsigned int HandleAttributes;
    unsigned int GrantedAccess;
};

/* 832 */
struct _TXN_PARAMETER_BLOCK
{
    unsigned __int16 Length;
    unsigned __int16 TxFsContext;
    void* TransactionObject;
};

/* 833 */
struct _IO_DRIVER_CREATE_CONTEXT
{
    __int16 Size;
    struct _ECP_LIST* ExtraCreateParameter;
    void* DeviceObjectHint;
    _TXN_PARAMETER_BLOCK* TxnParameters;
    _EJOB* SiloContext;
};

/* 834 */
struct _IO_PRIORITY_INFO
{
    unsigned int Size;
    unsigned int ThreadPriority;
    unsigned int PagePriority;
    _IO_PRIORITY_HINT IoPriority;
};

/* 835 */
struct $0C5828C8BB62FF2F1199CF985F8D6E45
{
    unsigned __int8 Type;
    unsigned __int8 Reserved1;
    unsigned __int16 Reserved2;
};

/* 836 */
union $532816E00A502BDF4DC8B7F1825DD87D
{
    unsigned int Reserved;
    $0C5828C8BB62FF2F1199CF985F8D6E45 __s1;
};

/* 837 */
struct _EVENT_DATA_DESCRIPTOR
{
    unsigned __int64 Ptr;
    unsigned int Size;
    $532816E00A502BDF4DC8B7F1825DD87D ___u2;
};

/* 838 */
struct _EVENT_DESCRIPTOR
{
    unsigned __int16 Id;
    unsigned __int8 Version;
    unsigned __int8 Channel;
    unsigned __int8 Level;
    unsigned __int8 Opcode;
    unsigned __int16 Task;
    unsigned __int64 Keyword;
};

/* 839 */
struct $4DE972276DA75B0A8C3B01FB1799153A
{
    unsigned int KernelTime;
    unsigned int UserTime;
};

/* 840 */
union $DC8019FA227959B96114CE78AF1A26C8
{
    $4DE972276DA75B0A8C3B01FB1799153A __s0;
    unsigned __int64 ProcessorTime;
};

/* 841 */
struct _EVENT_HEADER
{
    unsigned __int16 Size;
    unsigned __int16 HeaderType;
    unsigned __int16 Flags;
    unsigned __int16 EventProperty;
    unsigned int ThreadId;
    unsigned int ProcessId;
    _LARGE_INTEGER TimeStamp;
    _GUID ProviderId;
    _EVENT_DESCRIPTOR EventDescriptor;
    $DC8019FA227959B96114CE78AF1A26C8 ___u9;
    _GUID ActivityId;
};

/* 842 */
struct $F7432ABE0171147119B3CC6D5D7B4734
{
    unsigned __int8 ProcessorNumber;
    unsigned __int8 Alignment;
};

/* 843 */
union $491F467FB17F756E141E36F08E5D74FE
{
    $F7432ABE0171147119B3CC6D5D7B4734 __s0;
    unsigned __int16 ProcessorIndex;
};

/* 844 */
struct _ETW_BUFFER_CONTEXT
{
    $491F467FB17F756E141E36F08E5D74FE ___u0;
    unsigned __int16 LoggerId;
};

/* 845 */
struct _EVENT_HEADER_EXTENDED_DATA_ITEM
{
    unsigned __int16 Reserved1;
    unsigned __int16 ExtType;
    unsigned __int16 Linkage : 1;
    unsigned __int16 Reserved2 : 15;
    unsigned __int16 DataSize;
    unsigned __int64 DataPtr;
};

/* 846 */
struct _EVENT_RECORD
{
    _EVENT_HEADER EventHeader;
    _ETW_BUFFER_CONTEXT BufferContext;
    unsigned __int16 ExtendedDataCount;
    unsigned __int16 UserDataLength;
    _EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData;
    void* UserData;
    void* UserContext;
};

/* 847 */
struct _PERFINFO_GROUPMASK
{
    unsigned int Masks[8];
};

/* 849 */
struct $9A3075D787B3FA6390236B5128BA7861
{
    unsigned __int32 FilePointerIndex : 9;
    unsigned __int32 HardFault : 1;
    unsigned __int32 Image : 1;
    unsigned __int32 Spare0 : 1;
};

/* 850 */
struct $8085C7622DD7274482910D646E99F4FF
{
    unsigned __int32 FilePointerIndex : 9;
    unsigned __int32 HardFault : 1;
    unsigned __int32 Spare1 : 2;
};

/* 848 */
union _MM_PAGE_ACCESS_INFO_FLAGS
{
    $9A3075D787B3FA6390236B5128BA7861 File;
    $8085C7622DD7274482910D646E99F4FF Private;
};

/* 851 */
union $426659B8DD2A11265B13B7E110F0C895
{
    _MM_PAGE_ACCESS_INFO_FLAGS Flags;
    unsigned __int64 FileOffset;
    void* VirtualAddress;
    void* PointerProtoPte;
};

/* 852 */
struct _MM_PAGE_ACCESS_INFO
{
    $426659B8DD2A11265B13B7E110F0C895 ___u0;
};

/* 853 */
union $B199E3D3D43313813CA7041F0E5F3B08
{
    unsigned int EmptySequenceNumber;
    unsigned int CurrentFileIndex;
};

/* 854 */
union $BC7920DDAEE1B53CA983D70B78F026F7
{
    unsigned __int64 EmptyTime;
    _MM_PAGE_ACCESS_INFO* TempEntry;
};

/* 855 */
union $C0817A5F8333B20053DEFEEDCFC21725
{
    _MM_PAGE_ACCESS_INFO* PageEntry;
    unsigned __int64* PageFrameEntry;
};

/* 856 */
union $758C0EA08C12BBEF220FC904BB5FE373
{
    unsigned __int64* FileEntry;
    unsigned __int64* LastPageFrameEntry;
};

/* 857 */
struct __declspec(align(8)) _MM_PAGE_ACCESS_INFO_HEADER
{
    _SINGLE_LIST_ENTRY Link;
    _MM_PAGE_ACCESS_TYPE Type;
    $B199E3D3D43313813CA7041F0E5F3B08 ___u2;
    unsigned __int64 CreateTime;
    $BC7920DDAEE1B53CA983D70B78F026F7 ___u4;
    $C0817A5F8333B20053DEFEEDCFC21725 ___u5;
    $758C0EA08C12BBEF220FC904BB5FE373 ___u6;
    unsigned __int64* FirstFileEntry;
    _EPROCESS* Process;
    unsigned int SessionId;
};

/* 858 */
struct _MCUPDATE_INFO
{
    _LIST_ENTRY List;
    unsigned int Status;
    unsigned __int64 Id;
    unsigned __int64 VendorScratch[2];
};

/* 859 */
struct $BEDAFFCF8B2FE2B464F6E114319CEB5E
{
    unsigned __int32 MCG_CapabilityRW : 1;
    unsigned __int32 MCG_GlobalControlRW : 1;
    unsigned __int32 Reserved : 30;
};

/* 860 */
union _XPF_MCE_FLAGS
{
    $BEDAFFCF8B2FE2B464F6E114319CEB5E __s0;
    unsigned int AsULONG;
};

/* 861 */
struct $DD3EFD26B55353E648024B9E0E8957B6
{
    unsigned __int8 ClearOnInitializationRW : 1;
    unsigned __int8 ControlDataRW : 1;
    unsigned __int8 Reserved : 6;
};

/* 862 */
union _XPF_MC_BANK_FLAGS
{
    $DD3EFD26B55353E648024B9E0E8957B6 __s0;
    unsigned __int8 AsUCHAR;
};

/* 863 */
#pragma pack(push, 1)
struct _WHEA_XPF_MC_BANK_DESCRIPTOR
{
    unsigned __int8 BankNumber;
    unsigned __int8 ClearOnInitialization;
    unsigned __int8 StatusDataFormat;
    _XPF_MC_BANK_FLAGS Flags;
    unsigned int ControlMsr;
    unsigned int StatusMsr;
    unsigned int AddressMsr;
    unsigned int MiscMsr;
    unsigned __int64 ControlData;
};
#pragma pack(pop)

/* 864 */
struct _WHEA_XPF_MCE_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 NumberOfBanks;
    _XPF_MCE_FLAGS Flags;
    unsigned __int64 MCG_Capability;
    unsigned __int64 MCG_GlobalControl;
    _WHEA_XPF_MC_BANK_DESCRIPTOR Banks[32];
};

/* 865 */
struct $D9F8BA727F02FA7D5CD681B2EFB762AC
{
    unsigned __int16 PollIntervalRW : 1;
    unsigned __int16 SwitchToPollingThresholdRW : 1;
    unsigned __int16 SwitchToPollingWindowRW : 1;
    unsigned __int16 ErrorThresholdRW : 1;
    unsigned __int16 ErrorThresholdWindowRW : 1;
    unsigned __int16 Reserved : 11;
};

/* 866 */
union _WHEA_NOTIFICATION_FLAGS
{
    $D9F8BA727F02FA7D5CD681B2EFB762AC __s0;
    unsigned __int16 AsUSHORT;
};

/* 868 */
struct $87B1EB75E3F8B7E7A5154BA9A750B013
{
    unsigned int PollInterval;
};

/* 869 */
struct $14FDC6AF8D27250B1B67344E0F6A0113
{
    unsigned int PollInterval;
    unsigned int Vector;
    unsigned int SwitchToPollingThreshold;
    unsigned int SwitchToPollingWindow;
    unsigned int ErrorThreshold;
    unsigned int ErrorThresholdWindow;
};

/* 870 */
union $4AD816D64AD9BD8296817C56FFD41612
{
    $87B1EB75E3F8B7E7A5154BA9A750B013 Polled;
    $14FDC6AF8D27250B1B67344E0F6A0113 Interrupt;
    $14FDC6AF8D27250B1B67344E0F6A0113 LocalInterrupt;
    $14FDC6AF8D27250B1B67344E0F6A0113 Sci;
    $14FDC6AF8D27250B1B67344E0F6A0113 Nmi;
    $14FDC6AF8D27250B1B67344E0F6A0113 Sea;
    $14FDC6AF8D27250B1B67344E0F6A0113 Sei;
    $14FDC6AF8D27250B1B67344E0F6A0113 Gsiv;
};

/* 867 */
struct _WHEA_NOTIFICATION_DESCRIPTOR
{
    unsigned __int8 Type;
    unsigned __int8 Length;
    _WHEA_NOTIFICATION_FLAGS Flags;
    $4AD816D64AD9BD8296817C56FFD41612 u;
};

/* 871 */
struct _WHEA_XPF_CMC_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 NumberOfBanks;
    unsigned int Reserved;
    _WHEA_NOTIFICATION_DESCRIPTOR Notify;
    _WHEA_XPF_MC_BANK_DESCRIPTOR Banks[32];
};

/* 872 */
#pragma pack(push, 1)
struct _WHEA_XPF_NMI_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
};
#pragma pack(pop)
/* 873 */
struct _WHEA_IPF_MCA_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
};

/* 874 */
struct _WHEA_IPF_CMC_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
};

/* 875 */
struct _WHEA_IPF_CPE_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
};

/* 877 */
struct $A9FC48894F8D14019CAF4D8F08A526D6
{
    unsigned __int32 DeviceNumber : 5;
    unsigned __int32 FunctionNumber : 3;
    unsigned __int32 Reserved : 24;
};

/* 878 */
union $E9F27CEAF0B4B9D2EA94FAB0CB342A8C
{
    $A9FC48894F8D14019CAF4D8F08A526D6 bits;
    unsigned int AsULONG;
};

/* 876 */
struct _WHEA_PCI_SLOT_NUMBER
{
    $E9F27CEAF0B4B9D2EA94FAB0CB342A8C u;
};

/* 879 */
struct $EFF43A9EAE4B7B62E532E338439EC9F9
{
    unsigned __int16 UncorrectableErrorMaskRW : 1;
    unsigned __int16 UncorrectableErrorSeverityRW : 1;
    unsigned __int16 CorrectableErrorMaskRW : 1;
    unsigned __int16 AdvancedCapsAndControlRW : 1;
    unsigned __int16 RootErrorCommandRW : 1;
    unsigned __int16 Reserved : 11;
};

/* 880 */
union _AER_ROOTPORT_DESCRIPTOR_FLAGS
{
    $EFF43A9EAE4B7B62E532E338439EC9F9 __s0;
    unsigned __int16 AsUSHORT;
};

/* 881 */
struct _WHEA_AER_ROOTPORT_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
    unsigned int BusNumber;
    _WHEA_PCI_SLOT_NUMBER Slot;
    unsigned __int16 DeviceControl;
    _AER_ROOTPORT_DESCRIPTOR_FLAGS Flags;
    unsigned int UncorrectableErrorMask;
    unsigned int UncorrectableErrorSeverity;
    unsigned int CorrectableErrorMask;
    unsigned int AdvancedCapsAndControl;
    unsigned int RootErrorCommand;
};

/* 882 */
struct $644EF056A6BCD34BEB130C59ECDD245F
{
    unsigned __int16 UncorrectableErrorMaskRW : 1;
    unsigned __int16 UncorrectableErrorSeverityRW : 1;
    unsigned __int16 CorrectableErrorMaskRW : 1;
    unsigned __int16 AdvancedCapsAndControlRW : 1;
    unsigned __int16 Reserved : 12;
};

/* 883 */
union _AER_ENDPOINT_DESCRIPTOR_FLAGS
{
    $644EF056A6BCD34BEB130C59ECDD245F __s0;
    unsigned __int16 AsUSHORT;
};

/* 884 */
struct _WHEA_AER_ENDPOINT_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
    unsigned int BusNumber;
    _WHEA_PCI_SLOT_NUMBER Slot;
    unsigned __int16 DeviceControl;
    _AER_ENDPOINT_DESCRIPTOR_FLAGS Flags;
    unsigned int UncorrectableErrorMask;
    unsigned int UncorrectableErrorSeverity;
    unsigned int CorrectableErrorMask;
    unsigned int AdvancedCapsAndControl;
};

/* 885 */
struct $DA323376D87A17572D4BAAC59ACA696A
{
    unsigned __int16 UncorrectableErrorMaskRW : 1;
    unsigned __int16 UncorrectableErrorSeverityRW : 1;
    unsigned __int16 CorrectableErrorMaskRW : 1;
    unsigned __int16 AdvancedCapsAndControlRW : 1;
    unsigned __int16 SecondaryUncorrectableErrorMaskRW : 1;
    unsigned __int16 SecondaryUncorrectableErrorSevRW : 1;
    unsigned __int16 SecondaryCapsAndControlRW : 1;
    unsigned __int16 Reserved : 9;
};

/* 886 */
union _AER_BRIDGE_DESCRIPTOR_FLAGS
{
    $DA323376D87A17572D4BAAC59ACA696A __s0;
    unsigned __int16 AsUSHORT;
};

/* 887 */
struct _WHEA_AER_BRIDGE_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
    unsigned int BusNumber;
    _WHEA_PCI_SLOT_NUMBER Slot;
    unsigned __int16 DeviceControl;
    _AER_BRIDGE_DESCRIPTOR_FLAGS Flags;
    unsigned int UncorrectableErrorMask;
    unsigned int UncorrectableErrorSeverity;
    unsigned int CorrectableErrorMask;
    unsigned int AdvancedCapsAndControl;
    unsigned int SecondaryUncorrectableErrorMask;
    unsigned int SecondaryUncorrectableErrorSev;
    unsigned int SecondaryCapsAndControl;
};

/* 888 */
#pragma pack(push, 1)
struct _WHEA_GENERIC_ERROR_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Reserved;
    unsigned __int8 Enabled;
    unsigned int ErrStatusBlockLength;
    unsigned int RelatedErrorSourceId;
    unsigned __int8 ErrStatusAddressSpaceID;
    unsigned __int8 ErrStatusAddressBitWidth;
    unsigned __int8 ErrStatusAddressBitOffset;
    unsigned __int8 ErrStatusAddressAccessSize;
    _LARGE_INTEGER ErrStatusAddress;
    _WHEA_NOTIFICATION_DESCRIPTOR Notify;
};
#pragma pack(pop)
/* 889 */
struct _WHEA_GENERIC_ERROR_DESCRIPTOR_V2
{
    unsigned __int16 Type;
    unsigned __int8 Reserved;
    unsigned __int8 Enabled;
    unsigned int ErrStatusBlockLength;
    unsigned int RelatedErrorSourceId;
    unsigned __int8 ErrStatusAddressSpaceID;
    unsigned __int8 ErrStatusAddressBitWidth;
    unsigned __int8 ErrStatusAddressBitOffset;
    unsigned __int8 ErrStatusAddressAccessSize;
    _LARGE_INTEGER ErrStatusAddress;
    _WHEA_NOTIFICATION_DESCRIPTOR Notify;
    unsigned __int8 ReadAckAddressSpaceID;
    unsigned __int8 ReadAckAddressBitWidth;
    unsigned __int8 ReadAckAddressBitOffset;
    unsigned __int8 ReadAckAddressAccessSize;
    _LARGE_INTEGER ReadAckAddress;
    unsigned __int64 ReadAckPreserveMask;
    unsigned __int64 ReadAckWriteMask;
};

/* 890 */
struct _WHEA_ERROR_SOURCE_CONFIGURATION_DD
{
    int(__fastcall* Initialize)(void*, unsigned int);
    void(__fastcall* Uninitialize)(void*);
    int(__fastcall* Correct)(void*, unsigned int*);
};

/* 891 */
#pragma pack(push, 1)
struct _WHEA_DEVICE_DRIVER_DESCRIPTOR
{
    unsigned __int16 Type;
    unsigned __int8 Enabled;
    unsigned __int8 Reserved;
    _GUID SourceGuid;
    unsigned __int16 LogTag;
    unsigned __int16 Reserved2;
    unsigned int PacketLength;
    unsigned int PacketCount;
    unsigned __int8* PacketBuffer;
    _WHEA_ERROR_SOURCE_CONFIGURATION_DD Config;
    _GUID CreatorId;
    _GUID PartitionId;
    unsigned int MaxSectionDataLength;
    unsigned int MaxSectionsPerRecord;
    unsigned __int8* PacketStateBuffer;
    int OpenHandles;
};

/* 893 */
union $B8ED658053E0A7BBD43A8EB19CA26330
{
  _WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;
  _WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;
  _WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;
  _WHEA_IPF_MCA_DESCRIPTOR IpfMcaDescriptor;
  _WHEA_IPF_CMC_DESCRIPTOR IpfCmcDescriptor;
  _WHEA_IPF_CPE_DESCRIPTOR IpfCpeDescriptor;
  _WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;
  _WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;
  _WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;
  _WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;
  _WHEA_GENERIC_ERROR_DESCRIPTOR_V2 GenErrDescriptorV2;
  _WHEA_DEVICE_DRIVER_DESCRIPTOR DeviceDriverDescriptor;
};
#pragma pack(pop)
/* 892 */
struct _WHEA_ERROR_SOURCE_DESCRIPTOR
{
    unsigned int Length;
    unsigned int Version;
    _WHEA_ERROR_SOURCE_TYPE Type;
    _WHEA_ERROR_SOURCE_STATE State;
    unsigned int MaxRawDataLength;
    unsigned int NumRecordsToPreallocate;
    unsigned int MaxSectionsPerRecord;
    unsigned int ErrorSourceId;
    unsigned int PlatformErrorSourceId;
    unsigned int Flags;
    $B8ED658053E0A7BBD43A8EB19CA26330 Info;
};

/* 894 */
struct $26E95845B33B84F42665E352BF23E268
{
    unsigned __int32 Reserved1 : 1;
    unsigned __int32 LogInternalEtw : 1;
    unsigned __int32 LogBlackbox : 1;
    unsigned __int32 LogSel : 1;
    unsigned __int32 RawSel : 1;
    unsigned __int32 NoFormat : 1;
    unsigned __int32 Driver : 1;
    unsigned __int32 Reserved2 : 25;
};

/* 895 */
union _WHEA_EVENT_LOG_ENTRY_FLAGS
{
    $26E95845B33B84F42665E352BF23E268 __s0;
    unsigned int AsULONG;
};

/* 896 */
struct _WHEA_EVENT_LOG_ENTRY_HEADER
{
    unsigned int Signature;
    unsigned int Version;
    unsigned int Length;
    _WHEA_EVENT_LOG_ENTRY_TYPE Type;
    unsigned int OwnerTag;
    _WHEA_EVENT_LOG_ENTRY_ID Id;
    _WHEA_EVENT_LOG_ENTRY_FLAGS Flags;
    unsigned int PayloadLength;
};

/* 897 */
struct _WHEA_EVENT_LOG_ENTRY
{
    _WHEA_EVENT_LOG_ENTRY_HEADER Header;
};

/* 898 */
struct $6925146DDFB4E1181EC8A69EB67289F4
{
    unsigned __int32 PreviousError : 1;
    unsigned __int32 CriticalEvent : 1;
    unsigned __int32 HypervisorError : 1;
    unsigned __int32 Simulated : 1;
    unsigned __int32 PlatformPfaControl : 1;
    unsigned __int32 PlatformDirectedOffline : 1;
    unsigned __int32 AddressTranslationRequired : 1;
    unsigned __int32 AddressTranslationCompleted : 1;
    unsigned __int32 Reserved2 : 24;
};

/* 899 */
union _WHEA_ERROR_PACKET_FLAGS
{
    $6925146DDFB4E1181EC8A69EB67289F4 __s0;
    unsigned int AsULONG;
};

/* 900 */
struct _WHEA_ERROR_PACKET_V2
{
    unsigned int Signature;
    unsigned int Version;
    unsigned int Length;
    _WHEA_ERROR_PACKET_FLAGS Flags;
    _WHEA_ERROR_TYPE ErrorType;
    _WHEA_ERROR_SEVERITY ErrorSeverity;
    unsigned int ErrorSourceId;
    _WHEA_ERROR_SOURCE_TYPE ErrorSourceType;
    _GUID NotifyType;
    unsigned __int64 Context;
    _WHEA_ERROR_PACKET_DATA_FORMAT DataFormat;
    unsigned int Reserved1;
    unsigned int DataOffset;
    unsigned int DataLength;
    unsigned int PshedDataOffset;
    unsigned int PshedDataLength;
};

/* 901 */
struct $093851A5671CCE5957B5EAEAC4F608A2
{
    unsigned __int8 MinorRevision;
    unsigned __int8 MajorRevision;
};

/* 902 */
union _WHEA_REVISION
{
    $093851A5671CCE5957B5EAEAC4F608A2 __s0;
    unsigned __int16 AsUSHORT;
};

/* 903 */
struct $303239889594314C554CBA593C88201B
{
    unsigned __int32 PlatformId : 1;
    unsigned __int32 Timestamp : 1;
    unsigned __int32 PartitionId : 1;
    unsigned __int32 Reserved : 29;
};

/* 904 */
union _WHEA_ERROR_RECORD_HEADER_VALIDBITS
{
    $303239889594314C554CBA593C88201B __s0;
    unsigned int AsULONG;
};

/* 905 */
struct $0E69AD184FCFEB7998E3B897182A8ACD
{
    unsigned __int64 Seconds : 8;
    unsigned __int64 Minutes : 8;
    unsigned __int64 Hours : 8;
    unsigned __int64 Precise : 1;
    unsigned __int64 Reserved : 7;
    unsigned __int64 Day : 8;
    unsigned __int64 Month : 8;
    unsigned __int64 Year : 8;
    unsigned __int64 Century : 8;
};

/* 906 */
union _WHEA_TIMESTAMP
{
    $0E69AD184FCFEB7998E3B897182A8ACD __s0;
    _LARGE_INTEGER AsLARGE_INTEGER;
};

/* 907 */
struct $9E46E3073B5FFFFC8430EEE7126B55BF
{
    unsigned __int32 Recovered : 1;
    unsigned __int32 PreviousError : 1;
    unsigned __int32 Simulated : 1;
    unsigned __int32 DeviceDriver : 1;
    unsigned __int32 CriticalEvent : 1;
    unsigned __int32 PersistPfn : 1;
    unsigned __int32 Reserved : 26;
};

/* 908 */
union _WHEA_ERROR_RECORD_HEADER_FLAGS
{
    $9E46E3073B5FFFFC8430EEE7126B55BF __s0;
    unsigned int AsULONG;
};

/* 909 */
struct $7AB0461A727F28B9D4873A511C9F9EFB
{
    unsigned __int64 Signature : 16;
    unsigned __int64 Length : 24;
    unsigned __int64 Identifier : 16;
    unsigned __int64 Attributes : 2;
    unsigned __int64 DoNotLog : 1;
    unsigned __int64 Reserved : 5;
};

/* 910 */
union _WHEA_PERSISTENCE_INFO
{
    $7AB0461A727F28B9D4873A511C9F9EFB __s0;
    unsigned __int64 AsULONGLONG;
};

/* 911 */
struct _WHEA_ERROR_RECORD_HEADER
{
    unsigned int Signature;
    _WHEA_REVISION Revision;
    __unaligned __declspec(align(1)) unsigned int SignatureEnd;
    unsigned __int16 SectionCount;
    _WHEA_ERROR_SEVERITY Severity;
    _WHEA_ERROR_RECORD_HEADER_VALIDBITS ValidBits;
    unsigned int Length;
    _WHEA_TIMESTAMP Timestamp;
    _GUID PlatformId;
    _GUID PartitionId;
    _GUID CreatorId;
    _GUID NotifyType;
    unsigned __int64 RecordId;
    _WHEA_ERROR_RECORD_HEADER_FLAGS Flags;
    __unaligned __declspec(align(1)) _WHEA_PERSISTENCE_INFO PersistenceInfo;
    unsigned __int8 Reserved[12];
};

/* 912 */
struct $6811685E9C9CDE140128703EAAAFCDFF
{
    unsigned __int8 FRUId : 1;
    unsigned __int8 FRUText : 1;
    unsigned __int8 Reserved : 6;
};

/* 913 */
union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS
{
    $6811685E9C9CDE140128703EAAAFCDFF __s0;
    unsigned __int8 AsUCHAR;
};

/* 914 */
struct $04FC3C63FA6AFA10A09BBCBE2A6159E4
{
    unsigned __int32 Primary : 1;
    unsigned __int32 ContainmentWarning : 1;
    unsigned __int32 Reset : 1;
    unsigned __int32 ThresholdExceeded : 1;
    unsigned __int32 ResourceNotAvailable : 1;
    unsigned __int32 LatentError : 1;
    unsigned __int32 Propagated : 1;
    unsigned __int32 Reserved : 25;
};

/* 915 */
union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS
{
    $04FC3C63FA6AFA10A09BBCBE2A6159E4 __s0;
    unsigned int AsULONG;
};

/* 916 */
struct _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR
{
    unsigned int SectionOffset;
    unsigned int SectionLength;
    _WHEA_REVISION Revision;
    _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS ValidBits;
    unsigned __int8 Reserved;
    _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags;
    _GUID SectionType;
    _GUID FRUId;
    _WHEA_ERROR_SEVERITY SectionSeverity;
    char FRUText[20];
};

/* 917 */
struct _WHEA_ERROR_RECORD
{
    _WHEA_ERROR_RECORD_HEADER Header;
    _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR SectionDescriptor[1];
};

/* 918 */
struct _HEAP_SUBALLOCATOR_CALLBACKS
{
    unsigned __int64 Allocate;
    unsigned __int64 Free;
    unsigned __int64 Commit;
    unsigned __int64 Decommit;
    unsigned __int64 ExtendContext;
};

/* 919 */
struct _SEGMENT_HEAP_EXTRA
{
    unsigned __int16 AllocationTag;
    unsigned __int8 InterceptorIndex : 4;
    unsigned __int8 UserFlags : 4;
    unsigned __int8 ExtraSizeInUnits;
    void* Settable;
};

/* 920 */
struct _RTL_CSPARSE_BITMAP
{
    unsigned __int64* CommitBitmap;
    unsigned __int64* UserBitmap;
    unsigned __int64 BitCount;
    unsigned __int64 BitmapLock;
    unsigned __int64 DecommitPageIndex;
    unsigned __int64 RtlpCSparseBitmapWakeLock;
    unsigned __int8 LockType;
    unsigned __int8 AddressSpace;
    unsigned __int8 MemType;
    unsigned __int8 AllocAlignment;
    unsigned int CommitDirectoryMaxSize;
    unsigned __int64 CommitDirectory[1];
};

/* 921 */
struct _RTL_SPARSE_ARRAY
{
    unsigned __int64 ElementCount;
    unsigned int ElementSizeShift;
    _RTL_CSPARSE_BITMAP Bitmap;
};

/* 922 */
union $5B1815099F1E147BE6CBBE3988019D6C
{
    _RTL_SPARSE_ARRAY VaRangeArray;
    unsigned __int8 VaRangeArrayBuffer[2128];
};

/* 923 */
struct _HEAP_VAMGR_VASPACE
{
    _RTLP_HP_ADDRESS_SPACE_TYPE AddressSpaceType;
    unsigned __int64 BaseAddress;
    $5B1815099F1E147BE6CBBE3988019D6C ___u2;
};

/* 924 */
struct _HEAP_VAMGR_ALLOCATOR
{
    unsigned __int64 TreeLock;
    _RTL_RB_TREE FreeRanges;
    _HEAP_VAMGR_VASPACE* VaSpace;
    void* PartitionHandle;
    unsigned __int16 ChunksPerRegion;
    unsigned __int16 RefCount;
    unsigned __int8 AllocatorIndex;
    unsigned __int8 NumaNode;
    unsigned __int8 LockType : 1;
    unsigned __int8 MemoryType : 2;
    unsigned __int8 ConstrainedVA : 1;
    unsigned __int8 AllowFreeHead : 1;
    unsigned __int8 Spare0 : 3;
    unsigned __int8 Spare1;
};

/* 925 */
struct $6307F61D7822C585A343A6FE20F6F237
{
    _SINGLE_LIST_ENTRY Next;
    unsigned __int64 OwnerCtx[2];
};

/* 926 */
struct $CF02C9340489EAFAAFAC5A8E5C818F63
{
    unsigned __int8 Allocated : 1;
    unsigned __int8 Internal : 1;
    unsigned __int8 Standalone : 1;
    unsigned __int8 Spare0 : 5;
    unsigned __int8 AllocatorIndex;
};

/* 927 */
union $AFBB918C16D52A46BF0E10A23B86EE31
{
    _RTL_BALANCED_NODE RbNode;
    $6307F61D7822C585A343A6FE20F6F237 __s1;
    $CF02C9340489EAFAAFAC5A8E5C818F63 __s2;
};

/* 928 */
struct $D2CE516EE272FD42AF61263D5E806FB1
{
    unsigned __int16 ChunkCount;
    unsigned __int16 PrevChunkCount;
};

/* 929 */
union $4396730910BF976D93962EDA078B813F
{
    unsigned __int64 SizeInChunks;
    $D2CE516EE272FD42AF61263D5E806FB1 __s1;
    unsigned __int64 Signature;
};

/* 930 */
struct _HEAP_VAMGR_RANGE
{
    $AFBB918C16D52A46BF0E10A23B86EE31 ___u0;
    $4396730910BF976D93962EDA078B813F ___u1;
};

/* 931 */
union $FDDE613BDDAC9DC04F602BE8653C6A5A
{
    _RTL_CSPARSE_BITMAP AllocTrackerBitmap;
    unsigned __int8 AllocTrackerBitmapBuffer[72];
};

/* 932 */
struct _RTLP_HP_ALLOC_TRACKER
{
    unsigned __int64 BaseAddress;
    $FDDE613BDDAC9DC04F602BE8653C6A5A ___u1;
};

/* 933 */
struct _FAKE_HEAP_ENTRY
{
    unsigned __int64 Size;
    unsigned __int64 PreviousSize;
};

/* 934 */
struct _HEAP_FAILURE_INFORMATION
{
    unsigned int Version;
    unsigned int StructureSize;
    _HEAP_FAILURE_TYPE FailureType;
    void* HeapAddress;
    void* Address;
    void* Param1;
    void* Param2;
    void* Param3;
    void* PreviousBlock;
    void* NextBlock;
    _FAKE_HEAP_ENTRY ExpectedDecodedEntry;
    void* StackTrace[32];
    unsigned __int8 HeapMajorVersion;
    unsigned __int8 HeapMinorVersion;
    _EXCEPTION_RECORD ExceptionRecord;
    _CONTEXT ContextRecord;
};

/* 935 */
struct _RTL_HEAP_MEMORY_LIMIT_DATA
{
    unsigned __int64 CommitLimitBytes;
    unsigned __int64 CommitLimitFailureCode;
    unsigned __int64 MaxAllocationSizeBytes;
    unsigned __int64 AllocationLimitFailureCode;
};

/* 936 */
struct _RTLP_HP_HEAP_GLOBALS
{
    unsigned __int64 HeapKey;
    unsigned __int64 LfhKey;
    _HEAP_FAILURE_INFORMATION* FailureInfo;
    _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
};

/* 937 */
struct _HEAP_VAMGR_CTX
{
    _HEAP_VAMGR_VASPACE VaSpace;
    unsigned __int64 AllocatorLock;
    unsigned int AllocatorCount;
    _HEAP_VAMGR_ALLOCATOR Allocators[255];
};

/* 938 */
struct RTL_HP_ENV_HANDLE
{
    void* h[2];
};

/* 939 */
struct $8E288E94E66B1B910FE30A14EC5FDF27
{
    unsigned __int64 State : 2;
};

/* 940 */
union _RTL_RUN_ONCE
{
    void* Ptr;
    unsigned __int64 Value;
    $8E288E94E66B1B910FE30A14EC5FDF27 __s2;
};

/* 941 */
struct _HEAP_OPPORTUNISTIC_LARGE_PAGE_STATS
{
    volatile unsigned __int64 SmallPagesInUseWithinLarge;
    volatile unsigned __int64 OpportunisticLargePageCount;
};

/* 942 */
struct __declspec(align(8)) _RTL_HP_SEG_ALLOC_POLICY
{
    unsigned __int64 MinLargePages;
    unsigned __int64 MaxLargePages;
    unsigned __int8 MinUtilization;
};

/* 943 */
struct _HEAP_RUNTIME_MEMORY_STATS
{
    volatile unsigned __int64 TotalReservedPages;
    volatile unsigned __int64 TotalCommittedPages;
    unsigned __int64 FreeCommittedPages;
    unsigned __int64 LfhFreeCommittedPages;
    _HEAP_OPPORTUNISTIC_LARGE_PAGE_STATS LargePageStats[2];
    _RTL_HP_SEG_ALLOC_POLICY LargePageUtilizationPolicy;
};

/* 944 */
struct $33876C956F3137A9916A7F28A2A81153
{
    unsigned __int8 LargePagePolicy : 3;
    unsigned __int8 FullDecommit : 1;
    unsigned __int8 ReleaseEmptySegments : 1;
};

/* 946 */
union $B1D2941913CB2E4AD911CE08050C73BE
{
    $33876C956F3137A9916A7F28A2A81153 __s0;
    unsigned __int8 AllFlags;
};

/* 945 */
struct __declspec(align(64)) _HEAP_SEG_CONTEXT
{
    unsigned __int64 SegmentMask;
    unsigned __int8 UnitShift;
    unsigned __int8 PagesPerUnitShift;
    unsigned __int8 FirstDescriptorIndex;
    unsigned __int8 CachedCommitSoftShift;
    unsigned __int8 CachedCommitHighShift;
    $B1D2941913CB2E4AD911CE08050C73BE Flags;
    unsigned int MaxAllocationSize;
    __int16 OlpStatsOffset;
    __int16 MemStatsOffset;
    void* LfhContext;
    void* VsContext;
    RTL_HP_ENV_HANDLE EnvHandle;
    void* Heap;
    unsigned __int64 SegmentLock;
    _LIST_ENTRY SegmentListHead;
    unsigned __int64 SegmentCount;
    _RTL_RB_TREE FreePageRanges;
    unsigned __int64 FreeSegmentListLock;
    _SINGLE_LIST_ENTRY FreeSegmentList[2];
};

/* 947 */
struct _HEAP_VS_DELAY_FREE_CONTEXT
{
    _SLIST_HEADER ListHead;
};

/* 949 */
struct $6A45FF63D66E3C002CA27ED53B178FDD
{
    unsigned __int32 PageAlignLargeAllocs : 1;
    unsigned __int32 FullDecommit : 1;
    unsigned __int32 EnableDelayFree : 1;
};

/* 948 */
struct _RTL_HP_VS_CONFIG
{
    $6A45FF63D66E3C002CA27ED53B178FDD Flags;
};

/* 950 */
struct _HEAP_VS_CONTEXT
{
    unsigned __int64 Lock;
    _RTLP_HP_LOCK_TYPE LockType;
    _RTL_RB_TREE FreeChunkTree;
    _LIST_ENTRY SubsegmentList;
    unsigned __int64 TotalCommittedUnits;
    unsigned __int64 FreeCommittedUnits;
    _HEAP_VS_DELAY_FREE_CONTEXT DelayFreeContext;
    __declspec(align(64)) void* BackendCtx;
    _HEAP_SUBALLOCATOR_CALLBACKS Callbacks;
    _RTL_HP_VS_CONFIG Config;
    unsigned int Flags;
};

/* 951 */
struct _RTL_HP_LFH_CONFIG
{
    unsigned __int16 MaxBlockSize;
    unsigned __int16 WitholdPageCrossingBlocks : 1;
    unsigned __int16 DisableRandomization : 1;
};

/* 952 */
struct _HEAP_LFH_SUBSEGMENT_STAT
{
    unsigned __int8 Index;
    unsigned __int8 Count;
};

/* 953 */
union _HEAP_LFH_SUBSEGMENT_STATS
{
    _HEAP_LFH_SUBSEGMENT_STAT Buckets[4];
    void* AllStats;
};

/* 954 */
union $D283FD200F436B7746EF06B7621258B1
{
    unsigned __int8 SlotCount;
    unsigned __int8 SlotIndex;
};

/* 955 */
struct _HEAP_LFH_SUBSEGMENT_OWNER
{
    unsigned __int8 IsBucket : 1;
    unsigned __int8 Spare0 : 7;
    unsigned __int8 BucketIndex;
    $D283FD200F436B7746EF06B7621258B1 ___u3;
    unsigned __int8 Spare1;
    unsigned __int64 AvailableSubsegmentCount;
    unsigned __int64 Lock;
    _LIST_ENTRY AvailableSubsegmentList;
    _LIST_ENTRY FullSubsegmentList;
};

/* 956 */
struct $C7BAA91C6BAC0FE42BF4CC4987B8DD55
{
    unsigned __int64 RefCount : 12;
};

/* 957 */
union $532F7324787FCDF885AB862FB43D9B53
{
    void* Target;
    unsigned __int64 Value;
    $C7BAA91C6BAC0FE42BF4CC4987B8DD55 __s2;
};

/* 958 */
struct _HEAP_LFH_FAST_REF
{
    $532F7324787FCDF885AB862FB43D9B53 ___u0;
};

/* 959 */
struct _HEAP_LFH_AFFINITY_SLOT
{
    _HEAP_LFH_SUBSEGMENT_OWNER State;
    _HEAP_LFH_FAST_REF ActiveSubsegment;
};

/* 960 */
struct _HEAP_LFH_BUCKET
{
    _HEAP_LFH_SUBSEGMENT_OWNER State;
    unsigned __int64 TotalBlockCount;
    unsigned __int64 TotalSubsegmentCount;
    unsigned int ReciprocalBlockSize;
    unsigned __int8 Shift;
    unsigned __int8 ContentionCount;
    unsigned __int64 AffinityMappingLock;
    unsigned __int8* ProcAffinityMapping;
    _HEAP_LFH_AFFINITY_SLOT** AffinitySlots;
};

/* 961 */
struct _HEAP_LFH_CONTEXT
{
    void* BackendCtx;
    _HEAP_SUBALLOCATOR_CALLBACKS Callbacks;
    const unsigned __int8* AffinityModArray;
    unsigned __int8 MaxAffinity;
    unsigned __int8 LockType;
    __int16 MemStatsOffset;
    _RTL_HP_LFH_CONFIG Config;
    _HEAP_LFH_SUBSEGMENT_STATS BucketStats;
    unsigned __int64 SubsegmentCreationLock;
    __declspec(align(64)) _HEAP_LFH_BUCKET* Buckets[129];
};

/* 962 */
struct $E5189DAA72EA6578606897BD71B7A0C0
{
    unsigned __int64 ReservedMustBeZero1;
    void* UserContext;
    unsigned __int64 ReservedMustBeZero2;
    void* Spare;
};

/* 963 */
union $216CE68FF85F0B4A97677F2504C3BA49
{
    _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
    $E5189DAA72EA6578606897BD71B7A0C0 __s1;
};

/* 964 */
struct _SEGMENT_HEAP
{
    RTL_HP_ENV_HANDLE EnvHandle;
    unsigned int Signature;
    unsigned int GlobalFlags;
    unsigned int Interceptor;
    unsigned __int16 ProcessHeapListIndex;
    unsigned __int16 AllocatedFromMetadata : 1;
    $216CE68FF85F0B4A97677F2504C3BA49 ___u6;
    unsigned __int64 LargeMetadataLock;
    _RTL_RB_TREE LargeAllocMetadata;
    volatile unsigned __int64 LargeReservedPages;
    volatile unsigned __int64 LargeCommittedPages;
    _RTL_RUN_ONCE StackTraceInitVar;
    __declspec(align(32)) _HEAP_RUNTIME_MEMORY_STATS MemStats;
    unsigned __int16 GlobalLockCount;
    unsigned int GlobalLockOwner;
    unsigned __int64 ContextExtendLock;
    unsigned __int8* AllocatedBase;
    unsigned __int8* UncommittedBase;
    unsigned __int8* ReservedLimit;
    _HEAP_SEG_CONTEXT SegContexts[2];
    _HEAP_VS_CONTEXT VsContext;
    _HEAP_LFH_CONTEXT LfhContext;
};

/* 965 */
struct _RTLP_HP_METADATA_HEAP_CTX
{
    _SEGMENT_HEAP* Heap;
    _RTL_RUN_ONCE InitOnce;
};

/* 966 */
struct _RTL_HP_SUB_ALLOCATOR_CONFIGS
{
    _RTL_HP_LFH_CONFIG LfhConfigs;
    _RTL_HP_VS_CONFIG VsConfigs;
};

/* 967 */
struct _RTLP_HP_HEAP_MANAGER
{
    _RTLP_HP_HEAP_GLOBALS* Globals;
    _RTLP_HP_ALLOC_TRACKER AllocTracker;
    _HEAP_VAMGR_CTX VaMgr;
    _RTLP_HP_METADATA_HEAP_CTX MetadataHeaps[3];
    _RTL_HP_SUB_ALLOCATOR_CONFIGS SubAllocConfigs;
};

/* 968 */
struct _HEAP_LIST_LOOKUP
{
    _HEAP_LIST_LOOKUP* ExtendedLookup;
    unsigned int ArraySize;
    unsigned int ExtraItem;
    unsigned int ItemCount;
    unsigned int OutOfRangeItems;
    unsigned int BaseIndex;
    _LIST_ENTRY* ListHead;
    unsigned int* ListsInUseUlong;
    _LIST_ENTRY** ListHints;
};

/* 969 */
struct $C0BE8CF8EEC0746F3E432DC5811435AA
{
    unsigned __int16 Size;
    unsigned __int8 Flags;
    unsigned __int8 SmallTagIndex;
    unsigned __int16 PreviousSize;
    unsigned __int8 SegmentOffset;
    unsigned __int8 UnusedBytes;
};

/* 970 */
#pragma pack(push, 1)
struct $5C466DDA03AA46E631DB56798E26FDF1
{
    unsigned int SubSegmentCode;
    _BYTE gap4[2];
    unsigned __int8 LFHFlags;
};
#pragma pack(pop)

/* 971 */
union $F1A5FD203919791557406403C2E195D9
{
    $C0BE8CF8EEC0746F3E432DC5811435AA __s0;
    $5C466DDA03AA46E631DB56798E26FDF1 __s1;
    unsigned __int64 CompactHeader;
};

/* 972 */
struct _HEAP_UNPACKED_ENTRY
{
    void* PreviousBlockPrivateData;
    $F1A5FD203919791557406403C2E195D9 ___u1;
};

/* 973 */
struct $189410402A8C196D49CE26743A8A266F
{
    unsigned __int16 FunctionIndex;
    unsigned __int16 ContextValue;
};

/* 974 */
union $6BFAD30994F9603B21CA6807B2A53FA3
{
    $189410402A8C196D49CE26743A8A266F __s0;
    unsigned int InterceptorValue;
};

/* 975 */
struct _HEAP_EXTENDED_ENTRY
{
    void* Reserved;
    $6BFAD30994F9603B21CA6807B2A53FA3 ___u1;
    unsigned __int16 UnusedBytesLength;
    unsigned __int8 EntryOffset;
    unsigned __int8 ExtendedBlockSignature;
};

/* 976 */
struct $DC27582AECFCC0D570DBD37341C7E94D
{
    void* PreviousBlockPrivateData;
    unsigned __int16 Size;
    unsigned __int8 Flags;
    unsigned __int8 SmallTagIndex;
    unsigned __int16 PreviousSize;
    unsigned __int8 SegmentOffset;
    unsigned __int8 UnusedBytes;
};

/* 977 */
struct $4F9D3E36EC8354BE47722F6F3D1A84C9
{
    void* Reserved;
    unsigned int SubSegmentCode;
    unsigned __int16 UnusedBytesLength;
    unsigned __int8 LFHFlags;
    unsigned __int8 ExtendedBlockSignature;
};

/* 978 */
struct $DC1F6F3298AF766ABCF39BC5A4A93084
{
    void* ReservedForAlignment;
    unsigned __int64 CompactHeader;
};

/* 979 */
struct $3BA36395014B95F8E05F0144397EBC17
{
    _BYTE gap0[8];
    unsigned __int16 FunctionIndex;
    unsigned __int16 ContextValue;
    unsigned __int16 Code2;
    unsigned __int8 EntryOffset;
    unsigned __int8 Code4;
};

/* 980 */
struct $B2B8823496CC59E77F0E9A850749EC38
{
    _BYTE gap0[8];
    unsigned int InterceptorValue;
    unsigned int Code234;
};

/* 981 */
#pragma pack(push, 1)
struct $AFDB5D28FC37D59E71FD1BAE81CA5641
{
    _BYTE gap0[8];
    unsigned int Code1;
    _BYTE gapC[2];
    unsigned __int8 Code3;
};
#pragma pack(pop)
/* 982 */
struct $0941606B8DC76F9F37A36911ABE84D92
{
    _BYTE gap0[8];
    unsigned __int64 AgregateCode;
};

/* 983 */
union $8C2DBE588F677130C75C2F2872072FC7
{
    _HEAP_UNPACKED_ENTRY UnpackedEntry;
    $DC27582AECFCC0D570DBD37341C7E94D __s1;
    _HEAP_EXTENDED_ENTRY ExtendedEntry;
    $4F9D3E36EC8354BE47722F6F3D1A84C9 __s3;
    $DC1F6F3298AF766ABCF39BC5A4A93084 __s4;
    $3BA36395014B95F8E05F0144397EBC17 __s5;
    $B2B8823496CC59E77F0E9A850749EC38 __s6;
    $AFDB5D28FC37D59E71FD1BAE81CA5641 __s7;
    $0941606B8DC76F9F37A36911ABE84D92 __s8;
};

/* 984 */
struct _HEAP_ENTRY
{
    $8C2DBE588F677130C75C2F2872072FC7 ___u0;
};

/* 986 */
struct _HEAP_SEGMENT
{
    _HEAP_ENTRY Entry;
    unsigned int SegmentSignature;
    unsigned int SegmentFlags;
    _LIST_ENTRY SegmentListEntry;
    _HEAP* Heap;
    void* BaseAddress;
    unsigned int NumberOfPages;
    _HEAP_ENTRY* FirstEntry;
    _HEAP_ENTRY* LastValidEntry;
    unsigned int NumberOfUnCommittedPages;
    unsigned int NumberOfUnCommittedRanges;
    unsigned __int16 SegmentAllocatorBackTraceIndex;
    unsigned __int16 Reserved;
    _LIST_ENTRY UCRSegmentList;
};

/* 993 */
struct $0B13458B5D0A72055B4650F2A9C444EB
{
    _HEAP_ENTRY Entry;
    unsigned int SegmentSignature;
    unsigned int SegmentFlags;
    _LIST_ENTRY SegmentListEntry;
    _HEAP* Heap;
    void* BaseAddress;
    unsigned int NumberOfPages;
    _HEAP_ENTRY* FirstEntry;
    _HEAP_ENTRY* LastValidEntry;
    unsigned int NumberOfUnCommittedPages;
    unsigned int NumberOfUnCommittedRanges;
    unsigned __int16 SegmentAllocatorBackTraceIndex;
    unsigned __int16 Reserved;
    _LIST_ENTRY UCRSegmentList;
};

/* 994 */
union $644B0D0C64BB8C5D8A105BC22BF5A347
{
    _HEAP_SEGMENT Segment;
    $0B13458B5D0A72055B4650F2A9C444EB __s1;
};

/* 991 */
struct _HEAP_COUNTERS
{
    unsigned __int64 TotalMemoryReserved;
    unsigned __int64 TotalMemoryCommitted;
    unsigned __int64 TotalMemoryLargeUCR;
    unsigned __int64 TotalSizeInVirtualBlocks;
    unsigned int TotalSegments;
    unsigned int TotalUCRs;
    unsigned int CommittOps;
    unsigned int DeCommitOps;
    unsigned int LockAcquires;
    unsigned int LockCollisions;
    unsigned int CommitRate;
    unsigned int DecommittRate;
    unsigned int CommitFailures;
    unsigned int InBlockCommitFailures;
    unsigned int PollIntervalCounter;
    unsigned int DecommitsSinceLastCheck;
    unsigned int HeapPollInterval;
    unsigned int AllocAndFreeOps;
    unsigned int AllocationIndicesActive;
    unsigned int InBlockDeccommits;
    unsigned __int64 InBlockDeccomitSize;
    unsigned __int64 HighWatermarkSize;
    unsigned __int64 LastPolledSize;
};

/* 992 */
struct _HEAP_TUNING_PARAMETERS
{
    unsigned int CommittThresholdShift;
    unsigned __int64 MaxPreCommittThreshold;
};

/* 985 */
struct _HEAP
{
    $644B0D0C64BB8C5D8A105BC22BF5A347 ___u0;
    unsigned int Flags;
    unsigned int ForceFlags;
    unsigned int CompatibilityFlags;
    unsigned int EncodeFlagMask;
    _HEAP_ENTRY Encoding;
    unsigned int Interceptor;
    unsigned int VirtualMemoryThreshold;
    unsigned int Signature;
    unsigned __int64 SegmentReserve;
    unsigned __int64 SegmentCommit;
    unsigned __int64 DeCommitFreeBlockThreshold;
    unsigned __int64 DeCommitTotalFreeThreshold;
    unsigned __int64 TotalFreeSize;
    unsigned __int64 MaximumAllocationSize;
    unsigned __int16 ProcessHeapsListIndex;
    unsigned __int16 HeaderValidateLength;
    void* HeaderValidateCopy;
    unsigned __int16 NextAvailableTagIndex;
    unsigned __int16 MaximumTagIndex;
    _HEAP_TAG_ENTRY* TagEntries;
    _LIST_ENTRY UCRList;
    unsigned __int64 AlignRound;
    unsigned __int64 AlignMask;
    _LIST_ENTRY VirtualAllocdBlocks;
    _LIST_ENTRY SegmentList;
    unsigned __int16 AllocatorBackTraceIndex;
    unsigned int NonDedicatedListLength;
    void* BlocksIndex;
    void* UCRIndex;
    _HEAP_PSEUDO_TAG_ENTRY* PseudoTagEntries;
    _LIST_ENTRY FreeLists;
    _HEAP_LOCK* LockVariable;
    int(__fastcall* CommitRoutine)(void*, void**, unsigned __int64*);
    _RTL_RUN_ONCE StackTraceInitVar;
    _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
    void* FrontEndHeap;
    unsigned __int16 FrontHeapLockCount;
    unsigned __int8 FrontEndHeapType;
    unsigned __int8 RequestedFrontEndHeapType;
    wchar_t* FrontEndHeapUsageData;
    unsigned __int16 FrontEndHeapMaximumIndex;
    volatile unsigned __int8 FrontEndHeapStatusBitmap[129];
    _HEAP_COUNTERS Counters;
    _HEAP_TUNING_PARAMETERS TuningParameters;
};

/* 987 */
struct __declspec(align(8)) _HEAP_TAG_ENTRY
{
    unsigned int Allocs;
    unsigned int Frees;
    unsigned __int64 Size;
    unsigned __int16 TagIndex;
    unsigned __int16 CreatorBackTraceIndex;
    wchar_t TagName[24];
};

/* 988 */
struct _HEAP_PSEUDO_TAG_ENTRY
{
    unsigned int Allocs;
    unsigned int Frees;
    unsigned __int64 Size;
};

/* 990 */
union $4D5A25198CE8A5EB3A10F3056387B73B
{
    _RTL_CRITICAL_SECTION CriticalSection;
};

/* 989 */
struct _HEAP_LOCK
{
    $4D5A25198CE8A5EB3A10F3056387B73B Lock;
};

/* 995 */
struct $26A5638A1693B25BBF4C11BCEB01F8A1
{
    unsigned __int16 AllocatorBackTraceIndex;
    unsigned __int16 TagIndex;
};

/* 996 */
union $410C3FAA9AD5E9E1ED15B29C39B94FF8
{
    $26A5638A1693B25BBF4C11BCEB01F8A1 __s0;
    unsigned __int64 ZeroInit;
};

/* 997 */
union $1E642C03C1BFD29D0589278A1E2E81B2
{
    unsigned __int64 Settable;
    unsigned __int64 ZeroInit1;
};

/* 998 */
struct _HEAP_ENTRY_EXTRA
{
    $410C3FAA9AD5E9E1ED15B29C39B94FF8 ___u0;
    $1E642C03C1BFD29D0589278A1E2E81B2 ___u1;
};

/* 999 */
struct _HEAP_VIRTUAL_ALLOC_ENTRY
{
    _LIST_ENTRY Entry;
    _HEAP_ENTRY_EXTRA ExtraStuff;
    unsigned __int64 CommitSize;
    unsigned __int64 ReserveSize;
    _HEAP_ENTRY BusyBlock;
};

/* 1000 */
union $ED57393F4273BA0680A88B9883C8672E
{
    _HEAP_ENTRY HeapEntry;
    _HEAP_UNPACKED_ENTRY UnpackedEntry;
    $DC27582AECFCC0D570DBD37341C7E94D __s2;
    _HEAP_EXTENDED_ENTRY ExtendedEntry;
    $4F9D3E36EC8354BE47722F6F3D1A84C9 __s4;
    $DC1F6F3298AF766ABCF39BC5A4A93084 __s5;
    $3BA36395014B95F8E05F0144397EBC17 __s6;
    $B2B8823496CC59E77F0E9A850749EC38 __s7;
    $AFDB5D28FC37D59E71FD1BAE81CA5641 __s8;
    $0941606B8DC76F9F37A36911ABE84D92 __s9;
};

/* 1001 */
struct _HEAP_FREE_ENTRY
{
    $ED57393F4273BA0680A88B9883C8672E ___u0;
    _LIST_ENTRY FreeList;
};

/* 1002 */
struct __declspec(align(8)) _LDR_SERVICE_TAG_RECORD
{
    _LDR_SERVICE_TAG_RECORD* Next;
    unsigned int ServiceTag;
};

/* 1003 */
struct _LDRP_CSLIST
{
    _SINGLE_LIST_ENTRY* Tail;
};

/* 1004 */
struct __declspec(align(8)) _LDR_DDAG_NODE
{
    _LIST_ENTRY Modules;
    _LDR_SERVICE_TAG_RECORD* ServiceTagList;
    unsigned int LoadCount;
    unsigned int LoadWhileUnloadingCount;
    unsigned int LowestLink;
    _LDRP_CSLIST Dependencies;
    _LDRP_CSLIST IncomingDependencies;
    _LDR_DDAG_STATE State;
    _SINGLE_LIST_ENTRY CondenseLink;
    unsigned int PreorderNumber;
};

/* 1005 */
struct $58E50F58879EA8525E4DE9709914EC13
{
    unsigned __int32 PackagedBinary : 1;
    unsigned __int32 MarkedForRemoval : 1;
    unsigned __int32 ImageDll : 1;
    unsigned __int32 LoadNotificationsSent : 1;
    unsigned __int32 TelemetryEntryProcessed : 1;
    unsigned __int32 ProcessStaticImport : 1;
    unsigned __int32 InLegacyLists : 1;
    unsigned __int32 InIndexes : 1;
    unsigned __int32 ShimDll : 1;
    unsigned __int32 InExceptionTable : 1;
    unsigned __int32 ReservedFlags1 : 2;
    unsigned __int32 LoadInProgress : 1;
    unsigned __int32 LoadConfigProcessed : 1;
    unsigned __int32 EntryProcessed : 1;
    unsigned __int32 ProtectDelayLoad : 1;
    unsigned __int32 ReservedFlags3 : 2;
    unsigned __int32 DontCallForThreads : 1;
    unsigned __int32 ProcessAttachCalled : 1;
    unsigned __int32 ProcessAttachFailed : 1;
    unsigned __int32 CorDeferredValidate : 1;
    unsigned __int32 CorImage : 1;
    unsigned __int32 DontRelocate : 1;
    unsigned __int32 CorILOnly : 1;
    unsigned __int32 ChpeImage : 1;
    unsigned __int32 ReservedFlags5 : 2;
    unsigned __int32 Redirected : 1;
    unsigned __int32 ReservedFlags6 : 2;
    unsigned __int32 CompatDatabaseProcessed : 1;
};

/* 1006 */
union $6527A87D3631213BD1CA55B541893180
{
    unsigned __int8 FlagGroup[4];
    unsigned int Flags;
    $58E50F58879EA8525E4DE9709914EC13 __s2;
};

/* 1007 */
struct __declspec(align(4)) _LDR_DATA_TABLE_ENTRY
{
    _LIST_ENTRY InLoadOrderLinks;
    _LIST_ENTRY InMemoryOrderLinks;
    _LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    unsigned int SizeOfImage;
    _UNICODE_STRING FullDllName;
    _UNICODE_STRING BaseDllName;
    $6527A87D3631213BD1CA55B541893180 ___u8;
    unsigned __int16 ObsoleteLoadCount;
    unsigned __int16 TlsIndex;
    _LIST_ENTRY HashLinks;
    unsigned int TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    void* Lock;
    _LDR_DDAG_NODE* DdagNode;
    _LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    void* ParentDllBase;
    void* SwitchBackContext;
    _RTL_BALANCED_NODE BaseAddressIndexNode;
    _RTL_BALANCED_NODE MappingInfoIndexNode;
    unsigned __int64 OriginalBase;
    _LARGE_INTEGER LoadTime;
    unsigned int BaseNameHashValue;
    _LDR_DLL_LOAD_REASON LoadReason;
    unsigned int ImplicitPathOptions;
    unsigned int ReferenceCount;
    unsigned int DependentLoadFlags;
    unsigned __int8 SigningLevel;
};

/* 1008 */
struct __declspec(align(8)) _LFH_BLOCK_ZONE
{
    _LIST_ENTRY ListEntry;
    volatile int NextIndex;
};

/* 1009 */
struct _RTL_SRWLOCK
{
    $67516065B9352D64FC65CE98DA8F0107 ___u0;
};

/* 1010 */
struct $F1036A4CB9DCC2AD7C0B590C3AD12EFD
{
    unsigned int Bucket;
    unsigned int RunLength;
};

/* 1011 */
volatile union _HEAP_BUCKET_RUN_INFO
{
    $F1036A4CB9DCC2AD7C0B590C3AD12EFD __s0;
    __int64 Aggregate64;
};

/* 1012 */
struct __declspec(align(16)) _USER_MEMORY_CACHE_ENTRY
{
    _SLIST_HEADER UserBlocks;
    volatile unsigned int AvailableBlocks;
    volatile unsigned int MinimumDepth;
    volatile unsigned int CacheShiftThreshold;
    volatile unsigned __int16 Allocations;
    volatile unsigned __int16 Frees;
    volatile unsigned __int16 CacheHits;
};

/* 1013 */
struct $17E296EE3EA277E9BA9D262678A22FC4
{
    unsigned __int32 DisableAffinity : 1;
    unsigned __int32 SlowSubsegmentGrowth : 1;
    unsigned __int32 Spare : 30;
};

/* 1014 */
union $7234C9D30AC8BDE81B01A2115BA23A53
{
    $17E296EE3EA277E9BA9D262678A22FC4 __s0;
    unsigned int AllPolicies;
};

/* 1015 */
struct _HEAP_LFH_MEM_POLICIES
{
    $7234C9D30AC8BDE81B01A2115BA23A53 ___u0;
};

/* 1016 */
struct $3AFA02ABC058CE6994C49FEE4643BE6B
{
    unsigned __int8 UseAffinity : 1;
    unsigned __int8 DebugFlags : 2;
};

/* 1017 */
union $99A1C5D48C80186A33BC058478BAC68D
{
    $3AFA02ABC058CE6994C49FEE4643BE6B __s0;
    volatile unsigned __int8 Flags;
};

/* 1018 */
struct _HEAP_BUCKET
{
    unsigned __int16 BlockUnits;
    unsigned __int8 SizeIndex;
    $99A1C5D48C80186A33BC058478BAC68D ___u2;
};

/* 1023 */
struct $08ACFD39CC47AD0B0254FEB9A9222334
{
    unsigned int TotalBlocks;
    unsigned int SubSegmentCounts;
};

/* 1024 */
volatile union _HEAP_BUCKET_COUNTERS
{
    $08ACFD39CC47AD0B0254FEB9A9222334 __s0;
    __int64 Aggregate64;
};

/* 1019 */
struct __declspec(align(16)) _HEAP_LOCAL_SEGMENT_INFO
{
    _HEAP_LOCAL_DATA* LocalData;
    _HEAP_SUBSEGMENT* volatile ActiveSubsegment;
    _HEAP_SUBSEGMENT* volatile CachedItems[16];
    _SLIST_HEADER SListHeader;
    volatile _HEAP_BUCKET_COUNTERS Counters;
    unsigned int LastOpSequence;
    unsigned __int16 BucketIndex;
    unsigned __int16 LastUsed;
    unsigned __int16 NoThrashCount;
};

/* 1020 */
struct __declspec(align(16)) _HEAP_LOCAL_DATA
{
    _SLIST_HEADER DeletedSubSegments;
    _LFH_BLOCK_ZONE* volatile CrtZone;
    _LFH_HEAP* LowFragHeap;
    unsigned int Sequence;
    unsigned int DeleteRateThreshold;
};

/* 1033 */
struct $D254233C6C3C5B99CDD0FB4FC6D8F105
{
    unsigned __int16 Depth;
    unsigned __int16 Hint : 15;
    unsigned __int16 Lock : 1;
};

/* 1034 */
struct $46B2D33C8C39A4E2343250701D785E4F
{
    _BYTE gap0[2];
    unsigned __int16 Hint16;
};

/* 1035 */
union $490808B4B6CE8CC2A0650B1281851654
{
    $D254233C6C3C5B99CDD0FB4FC6D8F105 __s0;
    int Exchg;
    $46B2D33C8C39A4E2343250701D785E4F __s2;
};

/* 1036 */
volatile struct _INTERLOCK_SEQ
{
    $490808B4B6CE8CC2A0650B1281851654 ___u0;
};

/* 1037 */
struct $4185AF31254CEFA3B266CCE8C82F2B6C
{
    volatile unsigned __int16 BlockSize;
    unsigned __int16 Flags;
    unsigned __int16 BlockCount;
    unsigned __int8 SizeIndex;
    unsigned __int8 AffinityIndex;
};

/* 1038 */
union $DB84D140BA3C7D89D009BB3059E4D257
{
    $4185AF31254CEFA3B266CCE8C82F2B6C __s0;
    unsigned int Alignment[2];
};

/* 1022 */
struct __declspec(align(16)) _HEAP_SUBSEGMENT
{
    _HEAP_LOCAL_SEGMENT_INFO* LocalInfo;
    _HEAP_USERDATA_HEADER* UserBlocks;
    _SLIST_HEADER DelayFreeList;
    volatile _INTERLOCK_SEQ AggregateExchg;
    $DB84D140BA3C7D89D009BB3059E4D257 ___u4;
    volatile unsigned int Lock;
    _SINGLE_LIST_ENTRY SFreeListEntry;
};

/* 1021 */
struct _LFH_HEAP
{
    _RTL_SRWLOCK Lock;
    _LIST_ENTRY SubSegmentZones;
    void* Heap;
    void* NextSegmentInfoArrayAddress;
    void* FirstUncommittedAddress;
    void* ReservedAddressLimit;
    unsigned int SegmentCreate;
    unsigned int SegmentDelete;
    volatile unsigned int MinimumCacheDepth;
    volatile unsigned int CacheShiftThreshold;
    volatile unsigned __int64 SizeInCache;
    volatile _HEAP_BUCKET_RUN_INFO RunInfo;
    _USER_MEMORY_CACHE_ENTRY UserBlockCache[12];
    _HEAP_LFH_MEM_POLICIES MemoryPolicies;
    _HEAP_BUCKET Buckets[129];
    _HEAP_LOCAL_SEGMENT_INFO* SegmentInfoArrays[129];
    _HEAP_LOCAL_SEGMENT_INFO* AffinitizedInfoArrays[129];
    _SEGMENT_HEAP* SegmentAllocator;
    _HEAP_LOCAL_DATA LocalData[1];
};

/* 1029 */
union $8E0C13FD17DB43238E7A7FED793C7B37
{
    _SINGLE_LIST_ENTRY SFreeListEntry;
    _HEAP_SUBSEGMENT* SubSegment;
};

/* 1030 */
struct $E367653ADAF4F1831A3A9250F7A5ABC9
{
    unsigned __int8 SizeIndex;
    unsigned __int8 GuardPagePresent;
    unsigned __int16 PaddingBytes;
};

/* 1031 */
union $A42A0645EA9A4E5240FBF938C9B7C153
{
    unsigned int SizeIndexAndPadding;
    $E367653ADAF4F1831A3A9250F7A5ABC9 __s1;
};

/* 1025 */
struct $BF06F7CA9D265EB4072E42422A41E649
{
    unsigned __int16 FirstAllocationOffset;
    unsigned __int16 BlockStride;
};

/* 1026 */
union $B1ACC3FB1D3D4A763DDCA32A2089CD93
{
    $BF06F7CA9D265EB4072E42422A41E649 __s0;
    unsigned int StrideAndOffset;
};

/* 1027 */
struct _HEAP_USERDATA_OFFSETS
{
    $B1ACC3FB1D3D4A763DDCA32A2089CD93 ___u0;
};

/* 1028 */
struct _RTL_BITMAP_EX
{
    unsigned __int64 SizeOfBitMap;
    unsigned __int64* Buffer;
};

/* 1032 */
struct _HEAP_USERDATA_HEADER
{
    $8E0C13FD17DB43238E7A7FED793C7B37 ___u0;
    void* Reserved;
    $A42A0645EA9A4E5240FBF938C9B7C153 ___u2;
    unsigned int Signature;
    _HEAP_USERDATA_OFFSETS EncodedOffsets;
    _RTL_BITMAP_EX BusyBitmap;
    unsigned __int64 BitmapData[1];
};

/* 1039 */
struct _RTLP_HP_PADDING_HEADER
{
    unsigned __int64 PaddingSize;
    unsigned __int64 Spare;
};

/* 1040 */
struct _RTL_HASH_ENTRY
{
    _SINGLE_LIST_ENTRY BucketLink;
    unsigned __int64 Key;
};

/* 1041 */
struct _RTL_HASH_TABLE_ITERATOR
{
    _RTL_HASH_TABLE* Hash;
    _RTL_HASH_ENTRY* HashEntry;
    _SINGLE_LIST_ENTRY* Bucket;
};

/* 1042 */
struct _RTL_CHASH_ENTRY
{
    unsigned __int64 Key;
};

/* 1043 */
struct __declspec(align(8)) _RTL_CHASH_TABLE
{
    _RTL_CHASH_ENTRY* Table;
    unsigned int EntrySizeShift;
    unsigned int EntryMax;
    unsigned int EntryCount;
};

/* 1044 */
struct _RTL_STACKDB_CONTEXT
{
    _RTL_HASH_TABLE StackSegmentTable;
    _RTL_HASH_TABLE StackEntryTable;
    _RTL_SRWLOCK StackEntryTableLock;
    _RTL_SRWLOCK SegmentTableLock;
    void* (__fastcall* Allocate)(unsigned __int64, void*);
    void(__fastcall* Free)(void*, void*);
    void* AllocatorContext;
};

/* 1045 */
struct $14BFD61B91AEA9B3DA01004FA84BA49D
{
    unsigned __int16 Invalid : 1;
    unsigned __int16 AllocationInProgress : 1;
    unsigned __int16 Spare0 : 14;
    unsigned __int16 UsageData;
};

/* 1046 */
union _HEAP_LFH_ONDEMAND_POINTER
{
    $14BFD61B91AEA9B3DA01004FA84BA49D __s0;
    void* AllBits;
};

/* 1047 */
struct $99ECDAF0AE5E531537C6BCF9484E9C61
{
    unsigned __int16 BlockSize;
    unsigned __int16 FirstBlockOffset;
};

/* 1048 */
union $9175A2AFDFBD1A995534473C8EEC453F
{
    $99ECDAF0AE5E531537C6BCF9484E9C61 __s0;
    unsigned int EncodedData;
};

/* 1049 */
struct _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS
{
    $9175A2AFDFBD1A995534473C8EEC453F ___u0;
};

/* 1050 */
struct $1669CDF5D3E40BA891F6CC2C98BD426A
{
    unsigned __int64 DelayFree : 1;
    unsigned __int64 Count : 63;
};

/* 1051 */
union _HEAP_LFH_SUBSEGMENT_DELAY_FREE
{
    $1669CDF5D3E40BA891F6CC2C98BD426A __s0;
    void* AllBits;
};

/* 1052 */
union $1477501EF1A41C5A92D7606E96B6D996
{
    _HEAP_LFH_SUBSEGMENT_OWNER* Owner;
    _HEAP_LFH_SUBSEGMENT_DELAY_FREE DelayFree;
};

/* 1053 */
struct $9D16ED5BE0B4F3791B768C7824D4DD7A
{
    unsigned __int16 FreeCount;
    unsigned __int16 BlockCount;
};

/* 1054 */
union $96BC5AF9C001A7E68A92230EBF96A334
{
    $9D16ED5BE0B4F3791B768C7824D4DD7A __s0;
    volatile __int16 InterlockedShort;
    volatile int InterlockedLong;
};

/* 1055 */
struct _HEAP_LFH_SUBSEGMENT
{
    _LIST_ENTRY ListEntry;
    $1477501EF1A41C5A92D7606E96B6D996 ___u1;
    unsigned __int64 CommitLock;
    $96BC5AF9C001A7E68A92230EBF96A334 ___u3;
    unsigned __int16 FreeHint;
    unsigned __int8 Location;
    unsigned __int8 WitheldBlockCount;
    _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS BlockOffsets;
    unsigned __int8 CommitUnitShift;
    unsigned __int8 CommitUnitCount;
    unsigned __int16 CommitStateOffset;
    unsigned __int64 BlockBitmap[1];
};

/* 1056 */
struct $5AE0D95AF6E86ED4F94BB591CE303C37
{
    unsigned __int16 UnusedBytes : 14;
    unsigned __int16 ExtraPresent : 1;
    unsigned __int16 OneByteUnused : 1;
};

/* 1057 */
union $8BD2E4949E29AE90C74A35C25A2D68CE
{
    $5AE0D95AF6E86ED4F94BB591CE303C37 __s0;
    unsigned __int8 Bytes[2];
};

/* 1058 */
struct _HEAP_LFH_UNUSED_BYTES_INFO
{
    $8BD2E4949E29AE90C74A35C25A2D68CE ___u0;
};

/* 1059 */
struct _RTLP_HP_QUEUE_LOCK_HANDLE
{
    unsigned __int64 Reserved1;
    unsigned __int64 LockPtr;
    unsigned __int64 HandleData;
};

/* 1060 */
struct $ABFFD62BDF225577D7022740E18A12B6
{
    unsigned __int32 MemoryCost : 16;
    unsigned __int32 UnsafeSize : 16;
    unsigned __int32 UnsafePrevSize : 16;
    unsigned __int32 Allocated : 8;
};

/* 1061 */
union _HEAP_VS_CHUNK_HEADER_SIZE
{
    $ABFFD62BDF225577D7022740E18A12B6 __s0;
    unsigned __int16 KeyUShort;
    unsigned int KeyULong;
    unsigned __int64 HeaderBits;
};

/* 1062 */
struct $73F6626B528671F876887BEAAC485C97
{
    unsigned __int32 EncodedSegmentPageOffset : 8;
    unsigned __int32 UnusedBytes : 1;
    unsigned __int32 SkipDuringWalk : 1;
    unsigned __int32 Spare : 22;
};

/* 1063 */
union $39F4AB3C65C6EC6D103F7B0E5EC3B077
{
    $73F6626B528671F876887BEAAC485C97 __s0;
    unsigned int AllocatedChunkBits;
};

/* 1064 */
struct __declspec(align(8)) _HEAP_VS_CHUNK_HEADER
{
    _HEAP_VS_CHUNK_HEADER_SIZE Sizes;
    $39F4AB3C65C6EC6D103F7B0E5EC3B077 ___u1;
};

/* 1065 */
struct $C9D60C9817C591E19847868BF4FF23B0
{
    unsigned __int64 OverlapsHeader;
    _RTL_BALANCED_NODE Node;
};

/* 1066 */
union $BA89908ADE6823D468242160FAC6F821
{
    _HEAP_VS_CHUNK_HEADER Header;
    $C9D60C9817C591E19847868BF4FF23B0 __s1;
};

/* 1067 */
struct _HEAP_VS_CHUNK_FREE_HEADER
{
    $BA89908ADE6823D468242160FAC6F821 ___u0;
};

/* 1068 */
struct __declspec(align(8)) _HEAP_VS_SUBSEGMENT
{
    _LIST_ENTRY ListEntry;
    unsigned __int64 CommitBitmap;
    unsigned __int64 CommitLock;
    unsigned __int16 Size;
    unsigned __int16 Signature : 15;
    unsigned __int16 FullCommit : 1;
};

/* 1069 */
struct $005BB1F77B1CBD49DAF66888B6F6D0BF
{
    unsigned __int16 UnusedBytes : 13;
    unsigned __int16 LfhSubsegment : 1;
    unsigned __int16 ExtraPresent : 1;
    unsigned __int16 OneByteUnused : 1;
};

/* 1070 */
union $096A19F1756659A4B3FB0EBC355EF7A4
{
    $005BB1F77B1CBD49DAF66888B6F6D0BF __s0;
    unsigned __int8 Bytes[2];
};

/* 1071 */
struct _HEAP_VS_UNUSED_BYTES_INFO
{
    $096A19F1756659A4B3FB0EBC355EF7A4 ___u0;
};

/* 1072 */
struct $33098CF8CB20EC7D15C56394852F3E63
{
    unsigned __int32 EncodedCommittedPageCount : 16;
    unsigned __int32 LargePageCost : 8;
    unsigned __int32 UnitCount : 8;
};

/* 1073 */
union $D7734AE5AA2460F0BC2B857BAB0D0549
{
    unsigned int Key;
    $33098CF8CB20EC7D15C56394852F3E63 __s1;
};

/* 1074 */
struct _HEAP_DESCRIPTOR_KEY
{
    $D7734AE5AA2460F0BC2B857BAB0D0549 ___u0;
};

/* 1075 */
#pragma pack(push, 1)
struct $9F42C86B823BDE74A8D87832C99461B6
{
    unsigned int TreeSignature;
    unsigned int UnusedBytes;
    unsigned __int16 ExtraPresent : 1;
    unsigned __int16 Spare0 : 15;
};
#pragma pack(pop)

/* 1076 */
union $95F42D30CD796E9F58C28B0B441BE4D2
{
    _RTL_BALANCED_NODE TreeNode;
    $9F42C86B823BDE74A8D87832C99461B6 __s1;
};

/* 1077 */
struct $E4E7481012A647B3751AFFEDCF7D651F
{
    unsigned __int8 Align[3];
    unsigned __int8 UnitOffset;
};

/* 1078 */
struct $60748A5D42F9629E9D44EDDA5AC4FCBA
{
    _BYTE gap0[3];
    unsigned __int8 UnitSize;
};

/* 1079 */
union $233D4882C42F724A2687179EC087E0BB
{
    _HEAP_DESCRIPTOR_KEY Key;
    $E4E7481012A647B3751AFFEDCF7D651F __s1;
    $60748A5D42F9629E9D44EDDA5AC4FCBA __s2;
};

/* 1080 */
struct _HEAP_PAGE_RANGE_DESCRIPTOR
{
    $95F42D30CD796E9F58C28B0B441BE4D2 ___u0;
    volatile unsigned __int8 RangeFlags;
    unsigned __int8 CommittedPageCount;
    unsigned __int16 Spare;
    $233D4882C42F724A2687179EC087E0BB ___u4;
};

/* 1081 */
struct $81F3EF0645CADC9C120743C0E0198FB7
{
    unsigned __int16 CommittedPageCount : 11;
    unsigned __int16 Spare : 3;
    unsigned __int16 LargePageOperationInProgress : 1;
    unsigned __int16 LargePageCommit : 1;
};

/* 1082 */
union _HEAP_SEGMENT_MGR_COMMIT_STATE
{
    $81F3EF0645CADC9C120743C0E0198FB7 __s0;
    volatile unsigned __int16 EntireUShortV;
    unsigned __int16 EntireUShort;
};

/* 1083 */
#pragma pack(push, 1)
struct $514608933746EEF8DF28E7F8663DA4DB
{
    _LIST_ENTRY ListEntry;
    unsigned __int64 Signature;
    _HEAP_SEGMENT_MGR_COMMIT_STATE* SegmentCommitState;
    unsigned __int8 UnusedWatermark;
};
#pragma pack(pop)

/* 1084 */
union _HEAP_PAGE_SEGMENT
{
    $514608933746EEF8DF28E7F8663DA4DB __s0;
    _HEAP_PAGE_RANGE_DESCRIPTOR DescArray[256];
};

/* 1085 */
struct $EC4079333DBBD0FBE055A85948E48C1E
{
    unsigned __int64 VirtualAddress;
    unsigned __int64 ExtraPresent : 1;
    unsigned __int64 GuardPageCount : 1;
    unsigned __int64 GuardPageAlignment : 6;
    unsigned __int64 Spare : 4;
    unsigned __int64 AllocatedPages : 52;
};

/* 1086 */
struct $0A905A40753AD49327997F958CAD6577
{
    unsigned __int64 UnusedBytes : 16;
};

/* 1087 */
union $61CDEB73538FBBD78DEA7DE7F9257A2B
{
    $EC4079333DBBD0FBE055A85948E48C1E __s0;
    $0A905A40753AD49327997F958CAD6577 __s1;
};

/* 1088 */
struct _HEAP_LARGE_ALLOC_DATA
{
    _RTL_BALANCED_NODE TreeNode;
    $61CDEB73538FBBD78DEA7DE7F9257A2B ___u1;
};

/* 1089 */
union $E38888FFFF2E8047BDBD55C921E86469
{
    unsigned int FiberData;
    unsigned int Version;
};

/* 1090 */
struct _NT_TIB32
{
    unsigned int ExceptionList;
    unsigned int StackBase;
    unsigned int StackLimit;
    unsigned int SubSystemTib;
    $E38888FFFF2E8047BDBD55C921E86469 ___u4;
    unsigned int ArbitraryUserPointer;
    unsigned int Self;
};

/* 1091 */
struct _CLIENT_ID32
{
    unsigned int UniqueProcess;
    unsigned int UniqueThread;
};

/* 1092 */
struct _ACTIVATION_CONTEXT_STACK32
{
    unsigned int ActiveFrame;
    LIST_ENTRY32 FrameListCache;
    unsigned int Flags;
    unsigned int NextCookieSequenceNumber;
    unsigned int StackId;
};

/* 1093 */
struct _GDI_TEB_BATCH32
{
    unsigned __int32 Offset : 31;
    unsigned __int32 HasRenderingCommand : 1;
    unsigned int HDC;
    unsigned int Buffer[310];
};

/* 1094 */
struct _STRING32
{
    unsigned __int16 Length;
    unsigned __int16 MaximumLength;
    unsigned int Buffer;
};

/* 1095 */
struct _TEB32
{
    _NT_TIB32 NtTib;
    unsigned int EnvironmentPointer;
    _CLIENT_ID32 ClientId;
    unsigned int ActiveRpcHandle;
    unsigned int ThreadLocalStoragePointer;
    unsigned int ProcessEnvironmentBlock;
    unsigned int LastErrorValue;
    unsigned int CountOfOwnedCriticalSections;
    unsigned int CsrClientThread;
    unsigned int Win32ThreadInfo;
    unsigned int User32Reserved[26];
    unsigned int UserReserved[5];
    unsigned int WOW32Reserved;
    unsigned int CurrentLocale;
    unsigned int FpSoftwareStatusRegister;
    unsigned int ReservedForDebuggerInstrumentation[16];
    unsigned int SystemReserved1[26];
    char PlaceholderCompatibilityMode;
    unsigned __int8 PlaceholderHydrationAlwaysExplicit;
    char PlaceholderReserved[10];
    unsigned int ProxiedProcessId;
    _ACTIVATION_CONTEXT_STACK32 _ActivationStack;
    unsigned __int8 WorkingOnBehalfTicket[8];
    int ExceptionCode;
    unsigned int ActivationContextStackPointer;
    unsigned int InstrumentationCallbackSp;
    unsigned int InstrumentationCallbackPreviousPc;
    unsigned int InstrumentationCallbackPreviousSp;
    unsigned __int8 InstrumentationCallbackDisabled;
    unsigned __int8 SpareBytes[23];
    unsigned int TxFsContext;
    _GDI_TEB_BATCH32 GdiTebBatch;
    _CLIENT_ID32 RealClientId;
    unsigned int GdiCachedProcessHandle;
    unsigned int GdiClientPID;
    unsigned int GdiClientTID;
    unsigned int GdiThreadLocalInfo;
    unsigned int Win32ClientInfo[62];
    unsigned int glDispatchTable[233];
    unsigned int glReserved1[29];
    unsigned int glReserved2;
    unsigned int glSectionInfo;
    unsigned int glSection;
    unsigned int glTable;
    unsigned int glCurrentRC;
    unsigned int glContext;
    unsigned int LastStatusValue;
    _STRING32 StaticUnicodeString;
    wchar_t StaticUnicodeBuffer[261];
    unsigned int DeallocationStack;
    unsigned int TlsSlots[64];
    LIST_ENTRY32 TlsLinks;
    unsigned int Vdm;
    unsigned int ReservedForNtRpc;
    unsigned int DbgSsReserved[2];
    unsigned int HardErrorMode;
    unsigned int Instrumentation[9];
    _GUID ActivityId;
    unsigned int SubProcessTag;
    unsigned int PerflibData;
    unsigned int EtwTraceData;
    unsigned int WinSockData;
    unsigned int GdiBatchCount;
    $D9EBF87819411078EEC96304C6F97E47 ___u63;
    unsigned int GuaranteedStackBytes;
    unsigned int ReservedForPerf;
    unsigned int ReservedForOle;
    unsigned int WaitingOnLoaderLock;
    unsigned int SavedPriorityState;
    unsigned int ReservedForCodeCoverage;
    unsigned int ThreadPoolData;
    unsigned int TlsExpansionSlots;
    unsigned int MuiGeneration;
    unsigned int IsImpersonating;
    unsigned int NlsCache;
    unsigned int pShimData;
    unsigned int HeapData;
    unsigned int CurrentTransactionHandle;
    unsigned int ActiveFrame;
    unsigned int FlsData;
    unsigned int PreferredLanguages;
    unsigned int UserPrefLanguages;
    unsigned int MergedPrefLanguages;
    unsigned int MuiImpersonation;
    $8ABCD40CDBD167328241B217BDB144A7 ___u84;
    $3FCCE8508B160B5CC5A7BB6A6352584C ___u85;
    unsigned int TxnScopeEnterCallback;
    unsigned int TxnScopeExitCallback;
    unsigned int TxnScopeContext;
    unsigned int LockCount;
    int WowTebOffset;
    unsigned int ResourceRetValue;
    unsigned int ReservedForWdf;
    unsigned __int64 ReservedForCrt;
    _GUID EffectiveContainerId;
};

/* 1096 */
union $8662F439D215AAEDBB1F787C8B649648
{
    unsigned __int64 FiberData;
    unsigned int Version;
};

/* 1097 */
struct _NT_TIB64
{
    unsigned __int64 ExceptionList;
    unsigned __int64 StackBase;
    unsigned __int64 StackLimit;
    unsigned __int64 SubSystemTib;
    $8662F439D215AAEDBB1F787C8B649648 ___u4;
    unsigned __int64 ArbitraryUserPointer;
    unsigned __int64 Self;
};

/* 1098 */
struct _CLIENT_ID64
{
    unsigned __int64 UniqueProcess;
    unsigned __int64 UniqueThread;
};

/* 1099 */
struct __declspec(align(8)) _ACTIVATION_CONTEXT_STACK64
{
    unsigned __int64 ActiveFrame;
    LIST_ENTRY64 FrameListCache;
    unsigned int Flags;
    unsigned int NextCookieSequenceNumber;
    unsigned int StackId;
};

/* 1100 */
struct _GDI_TEB_BATCH64
{
    unsigned __int32 Offset : 31;
    unsigned __int32 HasRenderingCommand : 1;
    unsigned __int64 HDC;
    unsigned int Buffer[310];
};

/* 1101 */
struct _STRING64
{
    unsigned __int16 Length;
    unsigned __int16 MaximumLength;
    unsigned __int64 Buffer;
};

/* 1102 */
struct _TEB64
{
    _NT_TIB64 NtTib;
    unsigned __int64 EnvironmentPointer;
    _CLIENT_ID64 ClientId;
    unsigned __int64 ActiveRpcHandle;
    unsigned __int64 ThreadLocalStoragePointer;
    unsigned __int64 ProcessEnvironmentBlock;
    unsigned int LastErrorValue;
    unsigned int CountOfOwnedCriticalSections;
    unsigned __int64 CsrClientThread;
    unsigned __int64 Win32ThreadInfo;
    unsigned int User32Reserved[26];
    unsigned int UserReserved[5];
    unsigned __int64 WOW32Reserved;
    unsigned int CurrentLocale;
    unsigned int FpSoftwareStatusRegister;
    unsigned __int64 ReservedForDebuggerInstrumentation[16];
    unsigned __int64 SystemReserved1[30];
    char PlaceholderCompatibilityMode;
    unsigned __int8 PlaceholderHydrationAlwaysExplicit;
    char PlaceholderReserved[10];
    unsigned int ProxiedProcessId;
    _ACTIVATION_CONTEXT_STACK64 _ActivationStack;
    unsigned __int8 WorkingOnBehalfTicket[8];
    int ExceptionCode;
    unsigned __int8 Padding0[4];
    unsigned __int64 ActivationContextStackPointer;
    unsigned __int64 InstrumentationCallbackSp;
    unsigned __int64 InstrumentationCallbackPreviousPc;
    unsigned __int64 InstrumentationCallbackPreviousSp;
    unsigned int TxFsContext;
    unsigned __int8 InstrumentationCallbackDisabled;
    unsigned __int8 UnalignedLoadStoreExceptions;
    unsigned __int8 Padding1[2];
    _GDI_TEB_BATCH64 GdiTebBatch;
    _CLIENT_ID64 RealClientId;
    unsigned __int64 GdiCachedProcessHandle;
    unsigned int GdiClientPID;
    unsigned int GdiClientTID;
    unsigned __int64 GdiThreadLocalInfo;
    unsigned __int64 Win32ClientInfo[62];
    unsigned __int64 glDispatchTable[233];
    unsigned __int64 glReserved1[29];
    unsigned __int64 glReserved2;
    unsigned __int64 glSectionInfo;
    unsigned __int64 glSection;
    unsigned __int64 glTable;
    unsigned __int64 glCurrentRC;
    unsigned __int64 glContext;
    unsigned int LastStatusValue;
    unsigned __int8 Padding2[4];
    _STRING64 StaticUnicodeString;
    wchar_t StaticUnicodeBuffer[261];
    unsigned __int8 Padding3[6];
    unsigned __int64 DeallocationStack;
    unsigned __int64 TlsSlots[64];
    LIST_ENTRY64 TlsLinks;
    unsigned __int64 Vdm;
    unsigned __int64 ReservedForNtRpc;
    unsigned __int64 DbgSsReserved[2];
    unsigned int HardErrorMode;
    unsigned __int8 Padding4[4];
    unsigned __int64 Instrumentation[11];
    _GUID ActivityId;
    unsigned __int64 SubProcessTag;
    unsigned __int64 PerflibData;
    unsigned __int64 EtwTraceData;
    unsigned __int64 WinSockData;
    unsigned int GdiBatchCount;
    $D9EBF87819411078EEC96304C6F97E47 ___u68;
    unsigned int GuaranteedStackBytes;
    unsigned __int8 Padding5[4];
    unsigned __int64 ReservedForPerf;
    unsigned __int64 ReservedForOle;
    unsigned int WaitingOnLoaderLock;
    unsigned __int8 Padding6[4];
    unsigned __int64 SavedPriorityState;
    unsigned __int64 ReservedForCodeCoverage;
    unsigned __int64 ThreadPoolData;
    unsigned __int64 TlsExpansionSlots;
    unsigned __int64 DeallocationBStore;
    unsigned __int64 BStoreLimit;
    unsigned int MuiGeneration;
    unsigned int IsImpersonating;
    unsigned __int64 NlsCache;
    unsigned __int64 pShimData;
    unsigned int HeapData;
    unsigned __int8 Padding7[4];
    unsigned __int64 CurrentTransactionHandle;
    unsigned __int64 ActiveFrame;
    unsigned __int64 FlsData;
    unsigned __int64 PreferredLanguages;
    unsigned __int64 UserPrefLanguages;
    unsigned __int64 MergedPrefLanguages;
    unsigned int MuiImpersonation;
    $8ABCD40CDBD167328241B217BDB144A7 ___u94;
    $3FCCE8508B160B5CC5A7BB6A6352584C ___u95;
    unsigned __int64 TxnScopeEnterCallback;
    unsigned __int64 TxnScopeExitCallback;
    unsigned __int64 TxnScopeContext;
    unsigned int LockCount;
    int WowTebOffset;
    unsigned __int64 ResourceRetValue;
    unsigned __int64 ReservedForWdf;
    unsigned __int64 ReservedForCrt;
    _GUID EffectiveContainerId;
};

/* 1103 */
struct _RTL_TRACE_DATABASE
{
    unsigned int Magic;
    unsigned int Flags;
    unsigned int Tag;
    _RTL_TRACE_SEGMENT* SegmentList;
    unsigned __int64 MaximumSize;
    unsigned __int64 CurrentSize;
    void* Owner;
    _RTL_CRITICAL_SECTION Lock;
    unsigned int NoOfBuckets;
    _RTL_TRACE_BLOCK** Buckets;
    unsigned int(__fastcall* HashFunction)(unsigned int, void**);
    unsigned __int64 NoOfTraces;
    unsigned __int64 NoOfHits;
    unsigned int HashCounter[16];
};

/* 1104 */
struct _RTL_TRACE_SEGMENT
{
    unsigned int Magic;
    _RTL_TRACE_DATABASE* Database;
    _RTL_TRACE_SEGMENT* NextSegment;
    unsigned __int64 TotalSize;
    char* SegmentStart;
    char* SegmentEnd;
    char* SegmentFree;
};

/* 1105 */
struct _RTL_TRACE_BLOCK
{
    unsigned int Magic;
    unsigned int Count;
    unsigned int Size;
    unsigned __int64 UserCount;
    unsigned __int64 UserSize;
    void* UserContext;
    _RTL_TRACE_BLOCK* Next;
    void** Trace;
};

/* 1106 */
struct _ACL
{
    unsigned __int8 AclRevision;
    unsigned __int8 Sbz1;
    unsigned __int16 AclSize;
    unsigned __int16 AceCount;
    unsigned __int16 Sbz2;
};

/* 1107 */
struct _SECURITY_DESCRIPTOR
{
    unsigned __int8 Revision;
    unsigned __int8 Sbz1;
    unsigned __int16 Control;
    void* Owner;
    void* Group;
    _ACL* Sacl;
    _ACL* Dacl;
};

/* 1108 */
struct _RTL_STACK_DATABASE_LOCK
{
    _RTL_SRWLOCK Lock;
};

/* 1109 */
struct _RTL_STD_LIST_ENTRY
{
    _RTL_STD_LIST_ENTRY* Next;
};

/* 1110 */
union $42BBF344CF12888B830CC4972C4A83D3
{
    void* BackTrace[32];
    _SLIST_ENTRY FreeChain;
};

/* 1111 */
struct _RTL_STACK_TRACE_ENTRY
{
    _RTL_STD_LIST_ENTRY HashChain;
    unsigned __int16 TraceCount : 11;
    unsigned __int16 BlockDepth : 5;
    unsigned __int16 IndexHigh;
    unsigned __int16 Index;
    unsigned __int16 Depth;
    $42BBF344CF12888B830CC4972C4A83D3 ___u6;
};

/* 1112 */
struct _RTL_STD_LIST_HEAD
{
    _RTL_STD_LIST_ENTRY* Next;
    _RTL_STACK_DATABASE_LOCK Lock;
};

/* 1113 */
union $CB5E6BFF70C24CB67668EF974CF7B770
{
    char Reserved[104];
    _RTL_STACK_DATABASE_LOCK Lock;
};

/* 1114 */
struct __declspec(align(16)) _STACK_TRACE_DATABASE
{
    $CB5E6BFF70C24CB67668EF974CF7B770 ___u0;
    void* Reserved2;
    unsigned __int64 PeakHashCollisionListLength;
    void* LowerMemoryStart;
    unsigned __int8 PreCommitted;
    unsigned __int8 DumpInProgress;
    void* CommitBase;
    void* CurrentLowerCommitLimit;
    void* CurrentUpperCommitLimit;
    char* NextFreeLowerMemory;
    char* NextFreeUpperMemory;
    unsigned int NumberOfEntriesLookedUp;
    unsigned int NumberOfEntriesAdded;
    _RTL_STACK_TRACE_ENTRY** EntryIndexArray;
    unsigned int NumberOfEntriesAllocated;
    unsigned int NumberOfEntriesAvailable;
    unsigned int NumberOfAllocationFailures;
    _SLIST_HEADER FreeLists[32];
    unsigned int NumberOfBuckets;
    _RTL_STD_LIST_HEAD Buckets[1];
};

/* 1116 */
struct __declspec(align(8)) _RTL_BALANCED_LINKS
{
    _RTL_BALANCED_LINKS* Parent;
    _RTL_BALANCED_LINKS* LeftChild;
    _RTL_BALANCED_LINKS* RightChild;
    char Balance;
    unsigned __int8 Reserved[3];
};

/* 1117 */
union $561801943614B542B6544BF145AFD116
{
    _DPH_HEAP_BLOCK* pNextAlloc;
    _LIST_ENTRY AvailableEntry;
    _RTL_BALANCED_LINKS TableLinks;
};

/* 1115 */
struct _DPH_HEAP_BLOCK
{
    $561801943614B542B6544BF145AFD116 ___u0;
    unsigned __int8* pUserAllocation;
    unsigned __int8* pVirtualBlock;
    unsigned __int64 nVirtualBlockSize;
    unsigned __int64 nVirtualAccessSize;
    unsigned __int64 nUserRequestedSize;
    unsigned __int64 nUserActualSize;
    void* UserValue;
    unsigned int UserFlags;
    _RTL_TRACE_BLOCK* StackTrace;
    _LIST_ENTRY AdjacencyEntry;
    unsigned __int8* pVirtualRegion;
};

/* 1118 */
union _LFH_RANDOM_DATA
{
    unsigned __int8 Bytes[256];
    unsigned __int16 Words[128];
    unsigned __int64 Quadwords[32];
};

/* 1119 */
struct _PS_TRUSTLET_TKSESSION_ID
{
    unsigned __int64 SessionId[4];
};

/* 1120 */
struct _HEAP_GLOBAL_APPCOMPAT_FLAGS
{
    unsigned __int32 SafeInputValidation : 1;
    unsigned __int32 Padding : 1;
    unsigned __int32 CommitLFHSubsegments : 1;
    unsigned __int32 AllocateHeapFromEnv : 1;
};

/* 1121 */
struct _RTL_AVL_TABLE
{
    _RTL_BALANCED_LINKS BalancedRoot;
    void* OrderedPointer;
    unsigned int WhichOrderedElement;
    unsigned int NumberGenericTableElements;
    unsigned int DepthOfTree;
    _RTL_BALANCED_LINKS* RestartKey;
    unsigned int DeleteCount;
    _RTL_GENERIC_COMPARE_RESULTS(__fastcall* CompareRoutine)(_RTL_AVL_TABLE*, void*, void*);
    void* (__fastcall* AllocateRoutine)(_RTL_AVL_TABLE*, unsigned int);
    void(__fastcall* FreeRoutine)(_RTL_AVL_TABLE*, void*);
    void* TableContext;
};

/* 1122 */
struct _DPH_HEAP_ROOT
{
    unsigned int Signature;
    unsigned int HeapFlags;
    _RTL_CRITICAL_SECTION* HeapCritSect;
    unsigned int nRemoteLockAcquired;
    _DPH_HEAP_BLOCK* pVirtualStorageListHead;
    _DPH_HEAP_BLOCK* pVirtualStorageListTail;
    unsigned int nVirtualStorageRanges;
    unsigned __int64 nVirtualStorageBytes;
    _RTL_AVL_TABLE BusyNodesTable;
    _DPH_HEAP_BLOCK* NodeToAllocate;
    unsigned int nBusyAllocations;
    unsigned __int64 nBusyAllocationBytesCommitted;
    _DPH_HEAP_BLOCK* pFreeAllocationListHead;
    _DPH_HEAP_BLOCK* pFreeAllocationListTail;
    unsigned int nFreeAllocations;
    unsigned __int64 nFreeAllocationBytesCommitted;
    _LIST_ENTRY AvailableAllocationHead;
    unsigned int nAvailableAllocations;
    unsigned __int64 nAvailableAllocationBytesCommitted;
    _DPH_HEAP_BLOCK* pUnusedNodeListHead;
    _DPH_HEAP_BLOCK* pUnusedNodeListTail;
    unsigned int nUnusedNodes;
    unsigned __int64 nBusyAllocationBytesAccessible;
    _DPH_HEAP_BLOCK* pNodePoolListHead;
    _DPH_HEAP_BLOCK* pNodePoolListTail;
    unsigned int nNodePools;
    unsigned __int64 nNodePoolBytes;
    _LIST_ENTRY NextHeap;
    unsigned int ExtraFlags;
    unsigned int Seed;
    void* NormalHeap;
    _RTL_TRACE_BLOCK* CreateStackTrace;
    void* FirstThread;
};

/* 1123 */
struct BATTERY_REPORTING_SCALE
{
    unsigned int Granularity;
    unsigned int Capacity;
};

/* 1124 */
struct SYSTEM_POWER_CAPABILITIES
{
    unsigned __int8 PowerButtonPresent;
    unsigned __int8 SleepButtonPresent;
    unsigned __int8 LidPresent;
    unsigned __int8 SystemS1;
    unsigned __int8 SystemS2;
    unsigned __int8 SystemS3;
    unsigned __int8 SystemS4;
    unsigned __int8 SystemS5;
    unsigned __int8 HiberFilePresent;
    unsigned __int8 FullWake;
    unsigned __int8 VideoDimPresent;
    unsigned __int8 ApmPresent;
    unsigned __int8 UpsPresent;
    unsigned __int8 ThermalControl;
    unsigned __int8 ProcessorThrottle;
    unsigned __int8 ProcessorMinThrottle;
    unsigned __int8 ProcessorMaxThrottle;
    unsigned __int8 FastSystemS4;
    unsigned __int8 Hiberboot;
    unsigned __int8 WakeAlarmPresent;
    unsigned __int8 AoAc;
    unsigned __int8 DiskSpinDown;
    unsigned __int8 HiberFileType;
    unsigned __int8 AoAcConnectivitySupported;
    unsigned __int8 spare3[6];
    unsigned __int8 SystemBatteriesPresent;
    unsigned __int8 BatteriesAreShortTerm;
    BATTERY_REPORTING_SCALE BatteryScale[3];
    _SYSTEM_POWER_STATE AcOnLineWake;
    _SYSTEM_POWER_STATE SoftLidWake;
    _SYSTEM_POWER_STATE RtcWake;
    _SYSTEM_POWER_STATE MinDeviceWakeState;
    _SYSTEM_POWER_STATE DefaultLowLatencyWake;
};

/* 1125 */
struct $626BA0261C0CE970D353C60914498C98
{
    unsigned __int32 HotspotDetection : 1;
    unsigned __int32 HotspotFullCommit : 1;
    unsigned __int32 ActiveSubsegment : 1;
    unsigned __int32 SmallerSubsegment : 1;
    unsigned __int32 SingleAffinitySlot : 1;
    unsigned __int32 ApplyLfhDecommitPolicy : 1;
    unsigned __int32 EnableGarbageCollection : 1;
    unsigned __int32 LargePagePreCommit : 1;
    unsigned __int32 OpportunisticLargePreCommit : 1;
    unsigned __int32 LfhForcedAffinity : 1;
    unsigned __int32 LfhCachelinePadding : 1;
};

/* 1126 */
union RTLP_HP_LFH_PERF_FLAGS
{
    $626BA0261C0CE970D353C60914498C98 __s0;
    unsigned int AllFlags;
};

/* 1127 */
union $BDC6E403F2C6538AF4EEB80D78D0598E
{
    _LIST_ENTRY FreeQueue;
    _SLIST_ENTRY FreePushList;
    unsigned __int16 TraceIndex;
};

/* 1128 */
struct _DPH_BLOCK_INFORMATION
{
    unsigned int StartStamp;
    void* Heap;
    unsigned __int64 RequestedSize;
    unsigned __int64 ActualSize;
    $BDC6E403F2C6538AF4EEB80D78D0598E ___u4;
    void* StackTrace;
    unsigned int Padding;
    unsigned int EndStamp;
};

/* 1129 */
struct _MM_DRIVER_VERIFIER_DATA
{
    unsigned int Level;
    volatile unsigned int RaiseIrqls;
    volatile unsigned int AcquireSpinLocks;
    volatile unsigned int SynchronizeExecutions;
    volatile unsigned int AllocationsAttempted;
    volatile unsigned int AllocationsSucceeded;
    volatile unsigned int AllocationsSucceededSpecialPool;
    unsigned int AllocationsWithNoTag;
    unsigned int TrimRequests;
    unsigned int Trims;
    unsigned int AllocationsFailed;
    volatile unsigned int AllocationsFailedDeliberately;
    volatile unsigned int Loads;
    volatile unsigned int Unloads;
    unsigned int UnTrackedPool;
    unsigned int UserTrims;
    volatile unsigned int CurrentPagedPoolAllocations;
    volatile unsigned int CurrentNonPagedPoolAllocations;
    unsigned int PeakPagedPoolAllocations;
    unsigned int PeakNonPagedPoolAllocations;
    volatile unsigned __int64 PagedBytes;
    volatile unsigned __int64 NonPagedBytes;
    unsigned __int64 PeakPagedBytes;
    unsigned __int64 PeakNonPagedBytes;
    volatile unsigned int BurstAllocationsFailedDeliberately;
    unsigned int SessionTrims;
    volatile unsigned int OptionChanges;
    volatile unsigned int VerifyMode;
    _UNICODE_STRING PreviousBucketName;
    volatile unsigned int ExecutePoolTypes;
    volatile unsigned int ExecutePageProtections;
    volatile unsigned int ExecutePageMappings;
    volatile unsigned int ExecuteWriteSections;
    volatile unsigned int SectionAlignmentFailures;
    volatile unsigned int IATInExecutableSection;
};

/* 1131 */
struct $88EF95604601DC1E382F5DDE62E218B1
{
    unsigned __int16 McaErrorCode;
    unsigned __int16 ModelErrorCode;
    unsigned __int32 OtherInformation : 25;
    unsigned __int32 ContextCorrupt : 1;
    unsigned __int32 AddressValid : 1;
    unsigned __int32 MiscValid : 1;
    unsigned __int32 ErrorEnabled : 1;
    unsigned __int32 UncorrectedError : 1;
    unsigned __int32 StatusOverFlow : 1;
    unsigned __int32 Valid : 1;
};

/* 1130 */
union _MCI_STATS
{
    $88EF95604601DC1E382F5DDE62E218B1 MciStatus;
    unsigned __int64 QuadPart;
};

/* 1132 */
struct $BA59627BC8B5536852A492364D85709E
{
    unsigned int Address;
    unsigned int Reserved;
};

/* 1133 */
union _MCI_ADDR
{
    $BA59627BC8B5536852A492364D85709E __s0;
    unsigned __int64 QuadPart;
};

/* 1135 */
struct $75D79C36C850B442CFDA0BC5EC6F4621
{
    unsigned __int8 BankNumber;
    unsigned __int8 Reserved2[7];
    _MCI_STATS Status;
    _MCI_ADDR Address;
    unsigned __int64 Misc;
};

/* 1136 */
struct $70165B6E78F810616385FBD346A208DB
{
    unsigned __int64 Address;
    unsigned __int64 Type;
};

/* 1137 */
union $C65412E4F549A8FDE1BEFF3AD7BCD8DC
{
    $75D79C36C850B442CFDA0BC5EC6F4621 Mca;
    $70165B6E78F810616385FBD346A208DB Mce;
};

/* 1134 */
struct _MCA_EXCEPTION
{
    unsigned int VersionNumber;
    MCA_EXCEPTION_TYPE ExceptionType;
    _LARGE_INTEGER TimeStamp;
    unsigned int ProcessorNumber;
    unsigned int Reserved1;
    $C65412E4F549A8FDE1BEFF3AD7BCD8DC u;
    unsigned int ExtCnt;
    unsigned int Reserved3;
    unsigned __int64 ExtReg[24];
};

/* 1138 */
struct _HEAP_UCR_DESCRIPTOR
{
    _LIST_ENTRY ListEntry;
    _LIST_ENTRY SegmentEntry;
    void* Address;
    unsigned __int64 Size;
};

/* 1139 */
union $43D821CA8B0277AAE1B557C3A7CB22EA
{
    unsigned int KernelCallbackTable;
    unsigned int UserSharedInfoPtr;
};

/* 1140 */
struct __declspec(align(8)) _PEB32
{
    unsigned __int8 InheritedAddressSpace;
    unsigned __int8 ReadImageFileExecOptions;
    unsigned __int8 BeingDebugged;
    $51D2FE860E3D24CBB5D18A66F92CBB3C ___u3;
    unsigned int Mutant;
    unsigned int ImageBaseAddress;
    unsigned int Ldr;
    unsigned int ProcessParameters;
    unsigned int SubSystemData;
    unsigned int ProcessHeap;
    unsigned int FastPebLock;
    unsigned int AtlThunkSListPtr;
    unsigned int IFEOKey;
    $EBE42E673971247D518EE0952A24D91C ___u13;
    $43D821CA8B0277AAE1B557C3A7CB22EA ___u14;
    unsigned int SystemReserved;
    unsigned int AtlThunkSListPtr32;
    unsigned int ApiSetMap;
    unsigned int TlsExpansionCounter;
    unsigned int TlsBitmap;
    unsigned int TlsBitmapBits[2];
    unsigned int ReadOnlySharedMemoryBase;
    unsigned int SharedData;
    unsigned int ReadOnlyStaticServerData;
    unsigned int AnsiCodePageData;
    unsigned int OemCodePageData;
    unsigned int UnicodeCaseTableData;
    unsigned int NumberOfProcessors;
    unsigned int NtGlobalFlag;
    _LARGE_INTEGER CriticalSectionTimeout;
    unsigned int HeapSegmentReserve;
    unsigned int HeapSegmentCommit;
    unsigned int HeapDeCommitTotalFreeThreshold;
    unsigned int HeapDeCommitFreeBlockThreshold;
    unsigned int NumberOfHeaps;
    unsigned int MaximumNumberOfHeaps;
    unsigned int ProcessHeaps;
    unsigned int GdiSharedHandleTable;
    unsigned int ProcessStarterHelper;
    unsigned int GdiDCAttributeList;
    unsigned int LoaderLock;
    unsigned int OSMajorVersion;
    unsigned int OSMinorVersion;
    unsigned __int16 OSBuildNumber;
    unsigned __int16 OSCSDVersion;
    unsigned int OSPlatformId;
    unsigned int ImageSubsystem;
    unsigned int ImageSubsystemMajorVersion;
    unsigned int ImageSubsystemMinorVersion;
    unsigned int ActiveProcessAffinityMask;
    unsigned int GdiHandleBuffer[34];
    unsigned int PostProcessInitRoutine;
    unsigned int TlsExpansionBitmap;
    unsigned int TlsExpansionBitmapBits[32];
    unsigned int SessionId;
    _ULARGE_INTEGER AppCompatFlags;
    _ULARGE_INTEGER AppCompatFlagsUser;
    unsigned int pShimData;
    unsigned int AppCompatInfo;
    _STRING32 CSDVersion;
    unsigned int ActivationContextData;
    unsigned int ProcessAssemblyStorageMap;
    unsigned int SystemDefaultActivationContextData;
    unsigned int SystemAssemblyStorageMap;
    unsigned int MinimumStackCommit;
    unsigned int SparePointers[4];
    unsigned int SpareUlongs[5];
    unsigned int WerRegistrationData;
    unsigned int WerShipAssertPtr;
    unsigned int pUnused;
    unsigned int pImageHeaderHash;
    $98BE1D9D1AB68706920100E8ED516A55 ___u71;
    unsigned __int64 CsrServerReadOnlySharedMemoryBase;
    unsigned int TppWorkerpListLock;
    LIST_ENTRY32 TppWorkerpList;
    unsigned int WaitOnAddressHashTable[128];
    unsigned int TelemetryCoverageHeader;
    unsigned int CloudFileFlags;
    unsigned int CloudFileDiagFlags;
    char PlaceholderCompatibilityMode;
    char PlaceholderCompatibilityModeReserved[7];
    unsigned int LeapSecondData;
    $4A45994A7603896D317AA01724198593 ___u82;
    unsigned int NtGlobalFlag2;
};

/* 1141 */
struct _PF_KERNEL_GLOBALS
{
    unsigned __int64 AccessBufferAgeThreshold;
    _EX_RUNDOWN_REF AccessBufferRef;
    _KEVENT AccessBufferExistsEvent;
    unsigned int AccessBufferMax;
    __declspec(align(32)) _SLIST_HEADER AccessBufferList;
    int StreamSequenceNumber;
    unsigned int Flags;
    int ScenarioPrefetchCount;
};

/* 1142 */
typedef __crt_locale_pointers* _locale_t;

/* 1143 */
#pragma pack(push, 8)
struct __crt_locale_pointers
{
    struct __crt_locale_data* locinfo;
    struct __crt_multibyte_data* mbcinfo;
};
#pragma pack(pop)

/* 1144 */
typedef struct _GUID GUID;

/* 1146 */
typedef unsigned int UINT32;

/* 1147 */
typedef unsigned __int16 UINT16;

/* 1148 */
typedef unsigned __int8 UINT8;

/* 1149 */
typedef unsigned __int64 UINT64;

/* 1145 */
struct _TraceLoggingMetadata_t
{
    UINT32 Signature;
    UINT16 Size;
    UINT8 Version;
    UINT8 Flags;
    UINT64 Magic;
};

/* 1150 */
struct RUNTIME_FUNCTION
{
    void* __ptr32 FunctionStart;
    void* __ptr32 FunctionEnd;
    void* __ptr32 UnwindInfo;
};

/* 1151 */
struct UNWIND_INFO_HDR
{
    unsigned __int8 Version : 3;
    unsigned __int8 Flags : 5;
    unsigned __int8 PrologSize;
    unsigned __int8 CntUnwindCodes;
    unsigned __int8 FrameRegister : 4;
    unsigned __int8 FrameOffset : 4;
};

/* 1152 */
struct UNWIND_CODE
{
    char PrologOff;
    unsigned __int8 UnwindOp : 4;
    unsigned __int8 OpInfo : 4;
};

/* 1153 */
struct C_SCOPE_TABLE
{
    void* __ptr32 Begin;
    void* __ptr32 End;
    void* __ptr32 Handler;
    void* __ptr32 Target;
};

/* 1154 */
typedef struct _STRING STRING;

/* 1155 */
typedef struct _UNICODE_STRING UNICODE_STRING;

/* 1156 */
typedef void* HANDLE;

/* 1159 */
typedef unsigned __int8 UCHAR;

/* 1160 */
typedef unsigned __int16 USHORT;

/* 1158 */
union $6F0816B860EA11CA8E788AEE35731DB2
{
    UCHAR Byte[16];
    USHORT Word[8];
};

/* 1157 */
struct in6_addr
{
    union $6F0816B860EA11CA8E788AEE35731DB2 u;
};

/* 1161 */
typedef union _SLIST_HEADER* PSLIST_HEADER;

/* 1162 */
typedef unsigned __int64 ULONG64;

/* 1163 */
typedef PVOID PSID;

/* 1164 */
typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES;

/* 1166 */
typedef UNICODE_STRING* PUNICODE_STRING;

/* 1165 */
#pragma pack(push, 8)
struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};
#pragma pack(pop)

/* 1167 */
typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

/* 1168 */
typedef union _LARGE_INTEGER LARGE_INTEGER;

/* 1169 */
typedef char CHAR;

/* 1170 */
typedef struct _iobuf FILE;

/* 1171 */
struct _iobuf
{
    char* _ptr;
    int _cnt;
    char* _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char* _tmpfname;
};

/* 1172 */
#pragma pack(push, 8)
struct _exception
{
    int type;
    char* name;
    double arg1;
    double arg2;
    double retval;
};
#pragma pack(pop)

/* 1173 */
typedef unsigned __int64 ULONG_PTR;

/* 1174 */
typedef struct _IO_STATUS_BLOCK* PIO_STATUS_BLOCK;

/* 1175 */
typedef void(__stdcall* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

/* 1176 */
typedef BYTE BOOLEAN;

/* 1177 */
typedef wchar_t* STRSAFE_LPWSTR;

enum MACRO_STATUS : __int64
{
    STATUS_SEVERITY_WARNING = 0x2LL,
    STATUS_SEVERITY_INFORMATIONAL = 0x1LL,
    STATUS_SEVERITY_ERROR = 0x3LL,
    STATUS_SUCCESS = 0x0LL,
    STATUS_INVALID_INFO_CLASS = 0xFFFFFFFFC0000003LL,
    STATUS_NO_SUCH_USER = 0xFFFFFFFFC0000064LL,
    STATUS_WRONG_PASSWORD = 0xFFFFFFFFC000006ALL,
    STATUS_PASSWORD_RESTRICTION = 0xFFFFFFFFC000006CLL,
    STATUS_LOGON_FAILURE = 0xFFFFFFFFC000006DLL,
    STATUS_ACCOUNT_RESTRICTION = 0xFFFFFFFFC000006ELL,
    STATUS_INVALID_LOGON_HOURS = 0xFFFFFFFFC000006FLL,
    STATUS_INVALID_WORKSTATION = 0xFFFFFFFFC0000070LL,
    STATUS_PASSWORD_EXPIRED = 0xFFFFFFFFC0000071LL,
    STATUS_ACCOUNT_DISABLED = 0xFFFFFFFFC0000072LL,
    STATUS_INSUFFICIENT_RESOURCES = 0xFFFFFFFFC000009ALL,
    STATUS_ACCOUNT_EXPIRED = 0xFFFFFFFFC0000193LL,
    STATUS_PASSWORD_MUST_CHANGE = 0xFFFFFFFFC0000224LL,
    STATUS_ACCOUNT_LOCKED_OUT = 0xFFFFFFFFC0000234LL,
    STATUS_ACCESS_DENIED = 0xFFFFFFFFC0000022LL,
    STATUS_DOWNGRADE_DETECTED = 0xFFFFFFFFC0000388LL,
    STATUS_AUTHENTICATION_FIREWALL_FAILED = 0xFFFFFFFFC0000413LL,
    STATUS_LOGON_TYPE_NOT_GRANTED = 0xFFFFFFFFC000015BLL,
    STATUS_NO_SUCH_LOGON_SESSION = 0xFFFFFFFFC000005FLL,
    STATUS_WDF_PAUSED = 0xFFFFFFFFC0200203LL,
    STATUS_WDF_BUSY = 0xFFFFFFFFC0200204LL,
    IO_ERR_INSUFFICIENT_RESOURCES = 0xFFFFFFFFC0040002LL,
    IO_ERR_DRIVER_ERROR = 0xFFFFFFFFC0040004LL,
    IO_ERR_SEEK_ERROR = 0xFFFFFFFFC0040006LL,
    IO_ERR_BAD_BLOCK = 0xFFFFFFFFC0040007LL,
    IO_ERR_TIMEOUT = 0xFFFFFFFFC0040009LL,
    IO_ERR_CONTROLLER_ERROR = 0xFFFFFFFFC004000BLL,
    IO_ERR_NOT_READY = 0xFFFFFFFFC004000FLL,
    IO_ERR_INVALID_REQUEST = 0xFFFFFFFFC0040010LL,
    IO_ERR_RESET = 0xFFFFFFFFC0040013LL,
    IO_ERR_BAD_FIRMWARE = 0xFFFFFFFFC0040019LL,
    IO_WRN_BAD_FIRMWARE = 0xFFFFFFFF8004001ALL,
    IO_WRITE_CACHE_ENABLED = 0xFFFFFFFF80040020LL,
    IO_RECOVERED_VIA_ECC = 0xFFFFFFFF80040021LL,
    IO_WRITE_CACHE_DISABLED = 0xFFFFFFFF80040022LL,
    IO_WARNING_PAGING_FAILURE = 0xFFFFFFFF80040033LL,
    IO_WRN_FAILURE_PREDICTED = 0xFFFFFFFF80040034LL,
    IO_WARNING_ALLOCATION_FAILED = 0xFFFFFFFF80040038LL,
    IO_WARNING_DUPLICATE_SIGNATURE = 0xFFFFFFFF8004003ALL,
    IO_WARNING_DUPLICATE_PATH = 0xFFFFFFFF8004003BLL,
    IO_WARNING_WRITE_FUA_PROBLEM = 0xFFFFFFFF80040084LL,
    IO_WARNING_VOLUME_LOST_DISK_EXTENT = 0xFFFFFFFF8004008ELL,
    IO_WARNING_DEVICE_HAS_INTERNAL_DUMP = 0xFFFFFFFF8004008FLL,
    IO_WARNING_SOFT_THRESHOLD_REACHED = 0xFFFFFFFF80040090LL,
    IO_WARNING_SOFT_THRESHOLD_REACHED_EX = 0xFFFFFFFF80040091LL,
    IO_WARNING_SOFT_THRESHOLD_REACHED_EX_LUN_LUN = 0xFFFFFFFF80040092LL,
    IO_WARNING_SOFT_THRESHOLD_REACHED_EX_LUN_POOL = 0xFFFFFFFF80040093LL,
    IO_WARNING_SOFT_THRESHOLD_REACHED_EX_POOL_LUN = 0xFFFFFFFF80040094LL,
    IO_WARNING_SOFT_THRESHOLD_REACHED_EX_POOL_POOL = 0xFFFFFFFF80040095LL,
    IO_ERROR_DISK_RESOURCES_EXHAUSTED = 0xFFFFFFFFC0040096LL,
    IO_WARNING_DISK_CAPACITY_CHANGED = 0xFFFFFFFF80040097LL,
    IO_WARNING_DISK_PROVISIONING_TYPE_CHANGED = 0xFFFFFFFF80040098LL,
    IO_WARNING_IO_OPERATION_RETRIED = 0xFFFFFFFF80040099LL,
    IO_ERROR_IO_HARDWARE_ERROR = 0xFFFFFFFFC004009ALL,
    IO_WARNING_COMPLETION_TIME = 0xFFFFFFFF8004009BLL,
    IO_WARNING_DISK_SURPRISE_REMOVED = 0xFFFFFFFF8004009DLL,
    IO_WARNING_REPEATED_DISK_GUID = 0xFFFFFFFF8004009ELL,
    IO_WARNING_DISK_FIRMWARE_UPDATED = 0x4004009FLL,
    IO_ERR_RETRY_SUCCEEDED = 0x40001LL,
    IO_ERR_CONFIGURATION_ERROR = 0xFFFFFFFFC0040003LL,
    IO_ERR_PARITY = 0xFFFFFFFFC0040005LL,
    IO_ERR_OVERRUN_ERROR = 0xFFFFFFFFC0040008LL,
    IO_ERR_SEQUENCE = 0xFFFFFFFFC004000ALL,
    IO_ERR_INTERNAL_ERROR = 0xFFFFFFFFC004000CLL,
    IO_ERR_INCORRECT_IRQL = 0xFFFFFFFFC004000DLL,
    IO_ERR_INVALID_IOBASE = 0xFFFFFFFFC004000ELL,
    IO_ERR_VERSION = 0xFFFFFFFFC0040011LL,
    IO_ERR_LAYERED_FAILURE = 0xFFFFFFFFC0040012LL,
    IO_ERR_PROTOCOL = 0xFFFFFFFFC0040014LL,
    IO_ERR_MEMORY_CONFLICT_DETECTED = 0xFFFFFFFFC0040015LL,
    IO_ERR_PORT_CONFLICT_DETECTED = 0xFFFFFFFFC0040016LL,
    IO_ERR_DMA_CONFLICT_DETECTED = 0xFFFFFFFFC0040017LL,
    IO_ERR_IRQ_CONFLICT_DETECTED = 0xFFFFFFFFC0040018LL,
    IO_ERR_DMA_RESOURCE_CONFLICT = 0xFFFFFFFFC004001BLL,
    IO_ERR_INTERRUPT_RESOURCE_CONFLICT = 0xFFFFFFFFC004001CLL,
    IO_ERR_MEMORY_RESOURCE_CONFLICT = 0xFFFFFFFFC004001DLL,
    IO_ERR_PORT_RESOURCE_CONFLICT = 0xFFFFFFFFC004001ELL,
    IO_BAD_BLOCK_WITH_NAME = 0xFFFFFFFFC004001FLL,
    IO_FILE_QUOTA_THRESHOLD = 0x40040024LL,
    IO_FILE_QUOTA_LIMIT = 0x40040025LL,
    IO_FILE_QUOTA_STARTED = 0x40040026LL,
    IO_FILE_QUOTA_SUCCEEDED = 0x40040027LL,
    IO_FILE_QUOTA_FAILED = 0xFFFFFFFF80040028LL,
    IO_FILE_SYSTEM_CORRUPT = 0xFFFFFFFFC0040029LL,
    IO_FILE_QUOTA_CORRUPT = 0xFFFFFFFFC004002ALL,
    IO_SYSTEM_SLEEP_FAILED = 0xFFFFFFFFC004002BLL,
    IO_DUMP_POINTER_FAILURE = 0xFFFFFFFFC004002CLL,
    IO_DUMP_DRIVER_LOAD_FAILURE = 0xFFFFFFFFC004002DLL,
    IO_DUMP_INITIALIZATION_FAILURE = 0xFFFFFFFFC004002ELL,
    IO_DUMP_DUMPFILE_CONFLICT = 0xFFFFFFFFC004002FLL,
    IO_DUMP_DIRECT_CONFIG_FAILED = 0xFFFFFFFFC0040030LL,
    IO_DUMP_PAGE_CONFIG_FAILED = 0xFFFFFFFFC0040031LL,
    IO_LOST_DELAYED_WRITE = 0xFFFFFFFF80040032LL,
    IO_WARNING_INTERRUPT_STILL_PENDING = 0xFFFFFFFF80040035LL,
    IO_DRIVER_CANCEL_TIMEOUT = 0xFFFFFFFF80040036LL,
    IO_FILE_SYSTEM_CORRUPT_WITH_NAME = 0xFFFFFFFFC0040037LL,
    IO_WARNING_LOG_FLUSH_FAILED = 0xFFFFFFFF80040039LL,
    MCA_WARNING_CACHE = 0xFFFFFFFF8005003CLL,
    MCA_ERROR_CACHE = 0xFFFFFFFFC005003DLL,
    MCA_WARNING_TLB = 0xFFFFFFFF8005003ELL,
    MCA_ERROR_TLB = 0xFFFFFFFFC005003FLL,
    MCA_WARNING_CPU_BUS = 0xFFFFFFFF80050040LL,
    MCA_ERROR_CPU_BUS = 0xFFFFFFFFC0050041LL,
    MCA_WARNING_REGISTER_FILE = 0xFFFFFFFF80050042LL,
    MCA_ERROR_REGISTER_FILE = 0xFFFFFFFFC0050043LL,
    MCA_WARNING_MAS = 0xFFFFFFFF80050044LL,
    MCA_ERROR_MAS = 0xFFFFFFFFC0050045LL,
    MCA_WARNING_MEM_UNKNOWN = 0xFFFFFFFF80050046LL,
    MCA_ERROR_MEM_UNKNOWN = 0xFFFFFFFFC0050047LL,
    MCA_WARNING_MEM_1_2 = 0xFFFFFFFF80050048LL,
    MCA_ERROR_MEM_1_2 = 0xFFFFFFFFC0050049LL,
    MCA_WARNING_MEM_1_2_5 = 0xFFFFFFFF8005004ALL,
    MCA_ERROR_MEM_1_2_5 = 0xFFFFFFFFC005004BLL,
    MCA_WARNING_MEM_1_2_5_4 = 0xFFFFFFFF8005004CLL,
    MCA_ERROR_MEM_1_2_5_4 = 0xFFFFFFFFC005004DLL,
    MCA_WARNING_SYSTEM_EVENT = 0xFFFFFFFF8005004ELL,
    MCA_ERROR_SYSTEM_EVENT = 0xFFFFFFFFC005004FLL,
    MCA_WARNING_PCI_BUS_PARITY = 0xFFFFFFFF80050050LL,
    MCA_ERROR_PCI_BUS_PARITY = 0xFFFFFFFFC0050051LL,
    MCA_WARNING_PCI_BUS_PARITY_NO_INFO = 0xFFFFFFFF80050052LL,
    MCA_ERROR_PCI_BUS_PARITY_NO_INFO = 0xFFFFFFFFC0050053LL,
    MCA_WARNING_PCI_BUS_SERR = 0xFFFFFFFF80050054LL,
    MCA_ERROR_PCI_BUS_SERR = 0xFFFFFFFFC0050055LL,
    MCA_WARNING_PCI_BUS_SERR_NO_INFO = 0xFFFFFFFF80050056LL,
    MCA_ERROR_PCI_BUS_SERR_NO_INFO = 0xFFFFFFFFC0050057LL,
    MCA_WARNING_PCI_BUS_MASTER_ABORT = 0xFFFFFFFF80050058LL,
    MCA_ERROR_PCI_BUS_MASTER_ABORT = 0xFFFFFFFFC0050059LL,
    MCA_WARNING_PCI_BUS_MASTER_ABORT_NO_INFO = 0xFFFFFFFF8005005ALL,
    MCA_ERROR_PCI_BUS_MASTER_ABORT_NO_INFO = 0xFFFFFFFFC005005BLL,
    MCA_WARNING_PCI_BUS_TIMEOUT = 0xFFFFFFFF8005005CLL,
    MCA_ERROR_PCI_BUS_TIMEOUT = 0xFFFFFFFFC005005DLL,
    MCA_WARNING_PCI_BUS_TIMEOUT_NO_INFO = 0xFFFFFFFF8005005ELL,
    MCA_ERROR_PCI_BUS_TIMEOUT_NO_INFO = 0xFFFFFFFFC005005FLL,
    MCA_WARNING_PCI_BUS_UNKNOWN = 0xFFFFFFFF80050060LL,
    MCA_ERROR_PCI_BUS_UNKNOWN = 0xFFFFFFFFC0050061LL,
    MCA_WARNING_PCI_DEVICE = 0xFFFFFFFF80050062LL,
    MCA_ERROR_PCI_DEVICE = 0xFFFFFFFFC0050063LL,
    MCA_WARNING_SMBIOS = 0xFFFFFFFF80050064LL,
    MCA_ERROR_SMBIOS = 0xFFFFFFFFC0050065LL,
    MCA_WARNING_PLATFORM_SPECIFIC = 0xFFFFFFFF80050066LL,
    MCA_ERROR_PLATFORM_SPECIFIC = 0xFFFFFFFFC0050067LL,
    MCA_WARNING_UNKNOWN = 0xFFFFFFFF80050068LL,
    MCA_ERROR_UNKNOWN = 0xFFFFFFFFC0050069LL,
    MCA_WARNING_UNKNOWN_NO_CPU = 0xFFFFFFFF8005006ALL,
    MCA_ERROR_UNKNOWN_NO_CPU = 0xFFFFFFFFC005006BLL,
    IO_ERR_THREAD_STUCK_IN_DEVICE_DRIVER = 0xFFFFFFFFC004006CLL,
    MCA_WARNING_CMC_THRESHOLD_EXCEEDED = 0xFFFFFFFF8005006DLL,
    MCA_WARNING_CPE_THRESHOLD_EXCEEDED = 0xFFFFFFFF8005006ELL,
    MCA_WARNING_CPU_THERMAL_THROTTLED = 0xFFFFFFFF8005006FLL,
    MCA_INFO_CPU_THERMAL_THROTTLING_REMOVED = 0x40050070LL,
    MCA_WARNING_CPU = 0xFFFFFFFF80050071LL,
    MCA_ERROR_CPU = 0xFFFFFFFFC0050072LL,
    MCA_INFO_NO_MORE_CORRECTED_ERROR_LOGS = 0x40050073LL,
    MCA_INFO_MEMORY_PAGE_MARKED_BAD = 0x40050074LL,
    IO_ERR_PORT_TIMEOUT = 0xFFFFFFFFC0040075LL,
    IO_WARNING_BUS_RESET = 0xFFFFFFFF80040076LL,
    IO_INFO_THROTTLE_COMPLETE = 0x40040077LL,
    MCA_MEMORYHIERARCHY_ERROR = 0xFFFFFFFFC0050078LL,
    MCA_TLB_ERROR = 0xFFFFFFFFC0050079LL,
    MCA_BUS_ERROR = 0xFFFFFFFFC005007ALL,
    MCA_BUS_TIMEOUT_ERROR = 0xFFFFFFFFC005007BLL,
    MCA_INTERNALTIMER_ERROR = 0xFFFFFFFFC005007CLL,
    MCA_MICROCODE_ROM_PARITY_ERROR = 0xFFFFFFFFC005007ELL,
    MCA_EXTERNAL_ERROR = 0xFFFFFFFFC005007FLL,
    MCA_FRC_ERROR = 0xFFFFFFFFC0050080LL,
    IO_WARNING_RESET = 0xFFFFFFFF80040081LL,
    IO_CDROM_EXCLUSIVE_LOCK = 0x40040085LL,
    IO_LOST_DELAYED_WRITE_NETWORK_DISCONNECTED = 0xFFFFFFFF8004008BLL,
    IO_LOST_DELAYED_WRITE_NETWORK_SERVER_ERROR = 0xFFFFFFFF8004008CLL,
    IO_LOST_DELAYED_WRITE_NETWORK_LOCAL_DISK_ERROR = 0xFFFFFFFF8004008DLL,
    IO_WARNING_DUMP_DISABLED_DEVICE_GONE = 0xFFFFFFFF8004009CLL,
    IO_WARNING_ADAPTER_FIRMWARE_UPDATED = 0x400400A0LL,
    IO_ERROR_DUMP_CREATION_ERROR = 0xFFFFFFFFC00400A1LL,
    STATUS_WAIT_0 = 0x0LL,
    STATUS_WAIT_1 = 0x1LL,
    STATUS_WAIT_2 = 0x2LL,
    STATUS_WAIT_3 = 0x3LL,
    STATUS_WAIT_63 = 0x3FLL,
    STATUS_ABANDONED = 0x80LL,
    STATUS_ABANDONED_WAIT_0 = 0x80LL,
    STATUS_ABANDONED_WAIT_63 = 0xBFLL,
    STATUS_USER_APC = 0xC0LL,
    STATUS_ALREADY_COMPLETE = 0xFFLL,
    STATUS_KERNEL_APC = 0x100LL,
    STATUS_ALERTED = 0x101LL,
    STATUS_TIMEOUT = 0x102LL,
    STATUS_PENDING = 0x103LL,
    STATUS_REPARSE = 0x104LL,
    STATUS_MORE_ENTRIES = 0x105LL,
    STATUS_NOT_ALL_ASSIGNED = 0x106LL,
    STATUS_SOME_NOT_MAPPED = 0x107LL,
    STATUS_OPLOCK_BREAK_IN_PROGRESS = 0x108LL,
    STATUS_VOLUME_MOUNTED = 0x109LL,
    STATUS_RXACT_COMMITTED = 0x10ALL,
    STATUS_NOTIFY_CLEANUP = 0x10BLL,
    STATUS_NOTIFY_ENUM_DIR = 0x10CLL,
    STATUS_NO_QUOTAS_FOR_ACCOUNT = 0x10DLL,
    STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED = 0x10ELL,
    STATUS_PAGE_FAULT_TRANSITION = 0x110LL,
    STATUS_PAGE_FAULT_DEMAND_ZERO = 0x111LL,
    STATUS_PAGE_FAULT_COPY_ON_WRITE = 0x112LL,
    STATUS_PAGE_FAULT_GUARD_PAGE = 0x113LL,
    STATUS_PAGE_FAULT_PAGING_FILE = 0x114LL,
    STATUS_CACHE_PAGE_LOCKED = 0x115LL,
    STATUS_CRASH_DUMP = 0x116LL,
    STATUS_BUFFER_ALL_ZEROS = 0x117LL,
    STATUS_REPARSE_OBJECT = 0x118LL,
    STATUS_RESOURCE_REQUIREMENTS_CHANGED = 0x119LL,
    STATUS_TRANSLATION_COMPLETE = 0x120LL,
    STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY = 0x121LL,
    STATUS_NOTHING_TO_TERMINATE = 0x122LL,
    STATUS_PROCESS_NOT_IN_JOB = 0x123LL,
    STATUS_PROCESS_IN_JOB = 0x124LL,
    STATUS_VOLSNAP_HIBERNATE_READY = 0x125LL,
    STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY = 0x126LL,
    STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED = 0x127LL,
    STATUS_INTERRUPT_STILL_CONNECTED = 0x128LL,
    STATUS_PROCESS_CLONED = 0x129LL,
    STATUS_FILE_LOCKED_WITH_ONLY_READERS = 0x12ALL,
    STATUS_FILE_LOCKED_WITH_WRITERS = 0x12BLL,
    STATUS_VALID_IMAGE_HASH = 0x12CLL,
    STATUS_VALID_CATALOG_HASH = 0x12DLL,
    STATUS_VALID_STRONG_CODE_HASH = 0x12ELL,
    STATUS_GHOSTED = 0x12FLL,
    STATUS_DATA_OVERWRITTEN = 0x130LL,
    STATUS_RESOURCEMANAGER_READ_ONLY = 0x202LL,
    STATUS_RING_PREVIOUSLY_EMPTY = 0x210LL,
    STATUS_RING_PREVIOUSLY_FULL = 0x211LL,
    STATUS_RING_PREVIOUSLY_ABOVE_QUOTA = 0x212LL,
    STATUS_RING_NEWLY_EMPTY = 0x213LL,
    STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT = 0x214LL,
    STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE = 0x215LL,
    STATUS_OPLOCK_HANDLE_CLOSED = 0x216LL,
    STATUS_WAIT_FOR_OPLOCK = 0x367LL,
    STATUS_REPARSE_GLOBAL = 0x368LL,
    DBG_EXCEPTION_HANDLED = 0x10001LL,
    DBG_CONTINUE = 0x10002LL,
    STATUS_FLT_IO_COMPLETE = 0x1C0001LL,
    STATUS_OBJECT_NAME_EXISTS = 0x40000000LL,
    STATUS_THREAD_WAS_SUSPENDED = 0x40000001LL,
    STATUS_WORKING_SET_LIMIT_RANGE = 0x40000002LL,
    STATUS_IMAGE_NOT_AT_BASE = 0x40000003LL,
    STATUS_RXACT_STATE_CREATED = 0x40000004LL,
    STATUS_SEGMENT_NOTIFICATION = 0x40000005LL,
    STATUS_LOCAL_USER_SESSION_KEY = 0x40000006LL,
    STATUS_BAD_CURRENT_DIRECTORY = 0x40000007LL,
    STATUS_SERIAL_MORE_WRITES = 0x40000008LL,
    STATUS_REGISTRY_RECOVERED = 0x40000009LL,
    STATUS_FT_READ_RECOVERY_FROM_BACKUP = 0x4000000ALL,
    STATUS_FT_WRITE_RECOVERY = 0x4000000BLL,
    STATUS_SERIAL_COUNTER_TIMEOUT = 0x4000000CLL,
    STATUS_NULL_LM_PASSWORD = 0x4000000DLL,
    STATUS_IMAGE_MACHINE_TYPE_MISMATCH = 0x4000000ELL,
    STATUS_RECEIVE_PARTIAL = 0x4000000FLL,
    STATUS_RECEIVE_EXPEDITED = 0x40000010LL,
    STATUS_RECEIVE_PARTIAL_EXPEDITED = 0x40000011LL,
    STATUS_EVENT_DONE = 0x40000012LL,
    STATUS_EVENT_PENDING = 0x40000013LL,
    STATUS_CHECKING_FILE_SYSTEM = 0x40000014LL,
    STATUS_FATAL_APP_EXIT = 0x40000015LL,
    STATUS_PREDEFINED_HANDLE = 0x40000016LL,
    STATUS_WAS_UNLOCKED = 0x40000017LL,
    STATUS_SERVICE_NOTIFICATION = 0x40000018LL,
    STATUS_WAS_LOCKED = 0x40000019LL,
    STATUS_LOG_HARD_ERROR = 0x4000001ALL,
    STATUS_ALREADY_WIN32 = 0x4000001BLL,
    STATUS_WX86_UNSIMULATE = 0x4000001CLL,
    STATUS_WX86_CONTINUE = 0x4000001DLL,
    STATUS_WX86_SINGLE_STEP = 0x4000001ELL,
    STATUS_WX86_BREAKPOINT = 0x4000001FLL,
    STATUS_WX86_EXCEPTION_CONTINUE = 0x40000020LL,
    STATUS_WX86_EXCEPTION_LASTCHANCE = 0x40000021LL,
    STATUS_WX86_EXCEPTION_CHAIN = 0x40000022LL,
    STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE = 0x40000023LL,
    STATUS_NO_YIELD_PERFORMED = 0x40000024LL,
    STATUS_TIMER_RESUME_IGNORED = 0x40000025LL,
    STATUS_ARBITRATION_UNHANDLED = 0x40000026LL,
    STATUS_CARDBUS_NOT_SUPPORTED = 0x40000027LL,
    STATUS_WX86_CREATEWX86TIB = 0x40000028LL,
    STATUS_MP_PROCESSOR_MISMATCH = 0x40000029LL,
    STATUS_HIBERNATED = 0x4000002ALL,
    STATUS_RESUME_HIBERNATION = 0x4000002BLL,
    STATUS_FIRMWARE_UPDATED = 0x4000002CLL,
    STATUS_DRIVERS_LEAKING_LOCKED_PAGES = 0x4000002DLL,
    STATUS_MESSAGE_RETRIEVED = 0x4000002ELL,
    STATUS_SYSTEM_POWERSTATE_TRANSITION = 0x4000002FLL,
    STATUS_ALPC_CHECK_COMPLETION_LIST = 0x40000030LL,
    STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION = 0x40000031LL,
    STATUS_ACCESS_AUDIT_BY_POLICY = 0x40000032LL,
    STATUS_ABANDON_HIBERFILE = 0x40000033LL,
    STATUS_BIZRULES_NOT_ENABLED = 0x40000034LL,
    STATUS_FT_READ_FROM_COPY = 0x40000035LL,
    STATUS_IMAGE_AT_DIFFERENT_BASE = 0x40000036LL,
    STATUS_PATCH_DEFERRED = 0x40000037LL,
    DBG_REPLY_LATER = 0x40010001LL,
    DBG_UNABLE_TO_PROVIDE_HANDLE = 0x40010002LL,
    DBG_TERMINATE_THREAD = 0x40010003LL,
    DBG_TERMINATE_PROCESS = 0x40010004LL,
    DBG_CONTROL_C = 0x40010005LL,
    DBG_PRINTEXCEPTION_C = 0x40010006LL,
    DBG_RIPEXCEPTION = 0x40010007LL,
    DBG_CONTROL_BREAK = 0x40010008LL,
    DBG_COMMAND_EXCEPTION = 0x40010009LL,
    DBG_PRINTEXCEPTION_WIDE_C = 0x4001000ALL,
    STATUS_HEURISTIC_DAMAGE_POSSIBLE = 0x40190001LL,
    STATUS_GUARD_PAGE_VIOLATION = 0x80000001LL,
    STATUS_DATATYPE_MISALIGNMENT = 0x80000002LL,
    STATUS_BREAKPOINT = 0x80000003LL,
    STATUS_SINGLE_STEP = 0x80000004LL,
    STATUS_BUFFER_OVERFLOW = 0xFFFFFFFF80000005LL,
    STATUS_NO_MORE_FILES = 0xFFFFFFFF80000006LL,
    STATUS_WAKE_SYSTEM_DEBUGGER = 0xFFFFFFFF80000007LL,
    STATUS_HANDLES_CLOSED = 0xFFFFFFFF8000000ALL,
    STATUS_NO_INHERITANCE = 0xFFFFFFFF8000000BLL,
    STATUS_GUID_SUBSTITUTION_MADE = 0xFFFFFFFF8000000CLL,
    STATUS_PARTIAL_COPY = 0xFFFFFFFF8000000DLL,
    STATUS_DEVICE_PAPER_EMPTY = 0xFFFFFFFF8000000ELL,
    STATUS_DEVICE_POWERED_OFF = 0xFFFFFFFF8000000FLL,
    STATUS_DEVICE_OFF_LINE = 0xFFFFFFFF80000010LL,
    STATUS_DEVICE_BUSY = 0xFFFFFFFF80000011LL,
    STATUS_NO_MORE_EAS = 0xFFFFFFFF80000012LL,
    STATUS_INVALID_EA_NAME = 0xFFFFFFFF80000013LL,
    STATUS_EA_LIST_INCONSISTENT = 0xFFFFFFFF80000014LL,
    STATUS_INVALID_EA_FLAG = 0xFFFFFFFF80000015LL,
    STATUS_VERIFY_REQUIRED = 0xFFFFFFFF80000016LL,
    STATUS_EXTRANEOUS_INFORMATION = 0xFFFFFFFF80000017LL,
    STATUS_RXACT_COMMIT_NECESSARY = 0xFFFFFFFF80000018LL,
    STATUS_NO_MORE_ENTRIES = 0xFFFFFFFF8000001ALL,
    STATUS_FILEMARK_DETECTED = 0xFFFFFFFF8000001BLL,
    STATUS_MEDIA_CHANGED = 0xFFFFFFFF8000001CLL,
    STATUS_BUS_RESET = 0xFFFFFFFF8000001DLL,
    STATUS_END_OF_MEDIA = 0xFFFFFFFF8000001ELL,
    STATUS_BEGINNING_OF_MEDIA = 0xFFFFFFFF8000001FLL,
    STATUS_MEDIA_CHECK = 0xFFFFFFFF80000020LL,
    STATUS_SETMARK_DETECTED = 0xFFFFFFFF80000021LL,
    STATUS_NO_DATA_DETECTED = 0xFFFFFFFF80000022LL,
    STATUS_REDIRECTOR_HAS_OPEN_HANDLES = 0xFFFFFFFF80000023LL,
    STATUS_SERVER_HAS_OPEN_HANDLES = 0xFFFFFFFF80000024LL,
    STATUS_ALREADY_DISCONNECTED = 0xFFFFFFFF80000025LL,
    STATUS_LONGJUMP = 0x80000026LL,
    STATUS_CLEANER_CARTRIDGE_INSTALLED = 0xFFFFFFFF80000027LL,
    STATUS_PLUGPLAY_QUERY_VETOED = 0xFFFFFFFF80000028LL,
    STATUS_UNWIND_CONSOLIDATE = 0x80000029LL,
    STATUS_REGISTRY_HIVE_RECOVERED = 0xFFFFFFFF8000002ALL,
    STATUS_DLL_MIGHT_BE_INSECURE = 0xFFFFFFFF8000002BLL,
    STATUS_DLL_MIGHT_BE_INCOMPATIBLE = 0xFFFFFFFF8000002CLL,
    STATUS_STOPPED_ON_SYMLINK = 0xFFFFFFFF8000002DLL,
    STATUS_CANNOT_GRANT_REQUESTED_OPLOCK = 0xFFFFFFFF8000002ELL,
    STATUS_NO_ACE_CONDITION = 0xFFFFFFFF8000002FLL,
    STATUS_DEVICE_SUPPORT_IN_PROGRESS = 0xFFFFFFFF80000030LL,
    STATUS_DEVICE_POWER_CYCLE_REQUIRED = 0xFFFFFFFF80000031LL,
    STATUS_NO_WORK_DONE = 0xFFFFFFFF80000032LL,
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001LL,
    STATUS_CLUSTER_NODE_ALREADY_UP = 0xFFFFFFFF80130001LL,
    STATUS_CLUSTER_NODE_ALREADY_DOWN = 0xFFFFFFFF80130002LL,
    STATUS_CLUSTER_NETWORK_ALREADY_ONLINE = 0xFFFFFFFF80130003LL,
    STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE = 0xFFFFFFFF80130004LL,
    STATUS_CLUSTER_NODE_ALREADY_MEMBER = 0xFFFFFFFF80130005LL,
    STATUS_FLT_BUFFER_TOO_SMALL = 0xFFFFFFFF801C0001LL,
    STATUS_FVE_PARTIAL_METADATA = 0xFFFFFFFF80210001LL,
    STATUS_FVE_TRANSIENT_STATE = 0xFFFFFFFF80210002LL,
    STATUS_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH = 0xFFFFFFFF8000CF00LL,
    STATUS_UNSUCCESSFUL = 0xFFFFFFFFC0000001LL,
    STATUS_NOT_IMPLEMENTED = 0xFFFFFFFFC0000002LL,
    STATUS_INFO_LENGTH_MISMATCH = 0xFFFFFFFFC0000004LL,
    STATUS_ACCESS_VIOLATION = 0xC0000005LL,
    STATUS_IN_PAGE_ERROR = 0xC0000006LL,
    STATUS_PAGEFILE_QUOTA = 0xFFFFFFFFC0000007LL,
    STATUS_INVALID_HANDLE = 0xC0000008LL,
    STATUS_BAD_INITIAL_STACK = 0xFFFFFFFFC0000009LL,
    STATUS_BAD_INITIAL_PC = 0xFFFFFFFFC000000ALL,
    STATUS_INVALID_CID = 0xFFFFFFFFC000000BLL,
    STATUS_TIMER_NOT_CANCELED = 0xFFFFFFFFC000000CLL,
    STATUS_INVALID_PARAMETER = 0xC000000DLL,
    STATUS_NO_SUCH_DEVICE = 0xFFFFFFFFC000000ELL,
    STATUS_NO_SUCH_FILE = 0xFFFFFFFFC000000FLL,
    STATUS_INVALID_DEVICE_REQUEST = 0xFFFFFFFFC0000010LL,
    STATUS_END_OF_FILE = 0xFFFFFFFFC0000011LL,
    STATUS_WRONG_VOLUME = 0xFFFFFFFFC0000012LL,
    STATUS_NO_MEDIA_IN_DEVICE = 0xFFFFFFFFC0000013LL,
    STATUS_UNRECOGNIZED_MEDIA = 0xFFFFFFFFC0000014LL,
    STATUS_NONEXISTENT_SECTOR = 0xFFFFFFFFC0000015LL,
    STATUS_MORE_PROCESSING_REQUIRED = 0xFFFFFFFFC0000016LL,
    STATUS_NO_MEMORY = 0xC0000017LL,
    STATUS_CONFLICTING_ADDRESSES = 0xFFFFFFFFC0000018LL,
    STATUS_NOT_MAPPED_VIEW = 0xFFFFFFFFC0000019LL,
    STATUS_UNABLE_TO_FREE_VM = 0xFFFFFFFFC000001ALL,
    STATUS_UNABLE_TO_DELETE_SECTION = 0xFFFFFFFFC000001BLL,
    STATUS_INVALID_SYSTEM_SERVICE = 0xFFFFFFFFC000001CLL,
    STATUS_ILLEGAL_INSTRUCTION = 0xC000001DLL,
    STATUS_INVALID_LOCK_SEQUENCE = 0xFFFFFFFFC000001ELL,
    STATUS_INVALID_VIEW_SIZE = 0xFFFFFFFFC000001FLL,
    STATUS_INVALID_FILE_FOR_SECTION = 0xFFFFFFFFC0000020LL,
    STATUS_ALREADY_COMMITTED = 0xFFFFFFFFC0000021LL,
    STATUS_BUFFER_TOO_SMALL = 0xFFFFFFFFC0000023LL,
    STATUS_OBJECT_TYPE_MISMATCH = 0xFFFFFFFFC0000024LL,
    STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025LL,
    STATUS_INVALID_DISPOSITION = 0xC0000026LL,
    STATUS_UNWIND = 0xFFFFFFFFC0000027LL,
    STATUS_BAD_STACK = 0xFFFFFFFFC0000028LL,
    STATUS_INVALID_UNWIND_TARGET = 0xFFFFFFFFC0000029LL,
    STATUS_NOT_LOCKED = 0xFFFFFFFFC000002ALL,
    STATUS_PARITY_ERROR = 0xFFFFFFFFC000002BLL,
    STATUS_UNABLE_TO_DECOMMIT_VM = 0xFFFFFFFFC000002CLL,
    STATUS_NOT_COMMITTED = 0xFFFFFFFFC000002DLL,
    STATUS_INVALID_PORT_ATTRIBUTES = 0xFFFFFFFFC000002ELL,
    STATUS_PORT_MESSAGE_TOO_LONG = 0xFFFFFFFFC000002FLL,
    STATUS_INVALID_PARAMETER_MIX = 0xFFFFFFFFC0000030LL,
    STATUS_INVALID_QUOTA_LOWER = 0xFFFFFFFFC0000031LL,
    STATUS_DISK_CORRUPT_ERROR = 0xFFFFFFFFC0000032LL,
    STATUS_OBJECT_NAME_INVALID = 0xFFFFFFFFC0000033LL,
    STATUS_OBJECT_NAME_NOT_FOUND = 0xFFFFFFFFC0000034LL,
    STATUS_OBJECT_NAME_COLLISION = 0xFFFFFFFFC0000035LL,
    STATUS_PORT_DO_NOT_DISTURB = 0xFFFFFFFFC0000036LL,
    STATUS_PORT_DISCONNECTED = 0xFFFFFFFFC0000037LL,
    STATUS_DEVICE_ALREADY_ATTACHED = 0xFFFFFFFFC0000038LL,
    STATUS_OBJECT_PATH_INVALID = 0xFFFFFFFFC0000039LL,
    STATUS_OBJECT_PATH_NOT_FOUND = 0xFFFFFFFFC000003ALL,
    STATUS_OBJECT_PATH_SYNTAX_BAD = 0xFFFFFFFFC000003BLL,
    STATUS_DATA_OVERRUN = 0xFFFFFFFFC000003CLL,
    STATUS_DATA_LATE_ERROR = 0xFFFFFFFFC000003DLL,
    STATUS_DATA_ERROR = 0xFFFFFFFFC000003ELL,
    STATUS_CRC_ERROR = 0xFFFFFFFFC000003FLL,
    STATUS_SECTION_TOO_BIG = 0xFFFFFFFFC0000040LL,
    STATUS_PORT_CONNECTION_REFUSED = 0xFFFFFFFFC0000041LL,
    STATUS_INVALID_PORT_HANDLE = 0xFFFFFFFFC0000042LL,
    STATUS_SHARING_VIOLATION = 0xFFFFFFFFC0000043LL,
    STATUS_QUOTA_EXCEEDED = 0xFFFFFFFFC0000044LL,
    STATUS_INVALID_PAGE_PROTECTION = 0xFFFFFFFFC0000045LL,
    STATUS_MUTANT_NOT_OWNED = 0xFFFFFFFFC0000046LL,
    STATUS_SEMAPHORE_LIMIT_EXCEEDED = 0xFFFFFFFFC0000047LL,
    STATUS_PORT_ALREADY_SET = 0xFFFFFFFFC0000048LL,
    STATUS_SECTION_NOT_IMAGE = 0xFFFFFFFFC0000049LL,
    STATUS_SUSPEND_COUNT_EXCEEDED = 0xFFFFFFFFC000004ALL,
    STATUS_THREAD_IS_TERMINATING = 0xFFFFFFFFC000004BLL,
    STATUS_BAD_WORKING_SET_LIMIT = 0xFFFFFFFFC000004CLL,
    STATUS_INCOMPATIBLE_FILE_MAP = 0xFFFFFFFFC000004DLL,
    STATUS_SECTION_PROTECTION = 0xFFFFFFFFC000004ELL,
    STATUS_EAS_NOT_SUPPORTED = 0xFFFFFFFFC000004FLL,
    STATUS_EA_TOO_LARGE = 0xFFFFFFFFC0000050LL,
    STATUS_NONEXISTENT_EA_ENTRY = 0xFFFFFFFFC0000051LL,
    STATUS_NO_EAS_ON_FILE = 0xFFFFFFFFC0000052LL,
    STATUS_EA_CORRUPT_ERROR = 0xFFFFFFFFC0000053LL,
    STATUS_FILE_LOCK_CONFLICT = 0xFFFFFFFFC0000054LL,
    STATUS_LOCK_NOT_GRANTED = 0xFFFFFFFFC0000055LL,
    STATUS_DELETE_PENDING = 0xFFFFFFFFC0000056LL,
    STATUS_CTL_FILE_NOT_SUPPORTED = 0xFFFFFFFFC0000057LL,
    STATUS_UNKNOWN_REVISION = 0xFFFFFFFFC0000058LL,
    STATUS_REVISION_MISMATCH = 0xFFFFFFFFC0000059LL,
    STATUS_INVALID_OWNER = 0xFFFFFFFFC000005ALL,
    STATUS_INVALID_PRIMARY_GROUP = 0xFFFFFFFFC000005BLL,
    STATUS_NO_IMPERSONATION_TOKEN = 0xFFFFFFFFC000005CLL,
    STATUS_CANT_DISABLE_MANDATORY = 0xFFFFFFFFC000005DLL,
    STATUS_NO_LOGON_SERVERS = 0xFFFFFFFFC000005ELL,
    STATUS_NO_SUCH_PRIVILEGE = 0xFFFFFFFFC0000060LL,
    STATUS_PRIVILEGE_NOT_HELD = 0xFFFFFFFFC0000061LL,
    STATUS_INVALID_ACCOUNT_NAME = 0xFFFFFFFFC0000062LL,
    STATUS_USER_EXISTS = 0xFFFFFFFFC0000063LL,
    STATUS_GROUP_EXISTS = 0xFFFFFFFFC0000065LL,
    STATUS_NO_SUCH_GROUP = 0xFFFFFFFFC0000066LL,
    STATUS_MEMBER_IN_GROUP = 0xFFFFFFFFC0000067LL,
    STATUS_MEMBER_NOT_IN_GROUP = 0xFFFFFFFFC0000068LL,
    STATUS_LAST_ADMIN = 0xFFFFFFFFC0000069LL,
    STATUS_ILL_FORMED_PASSWORD = 0xFFFFFFFFC000006BLL,
    STATUS_NONE_MAPPED = 0xFFFFFFFFC0000073LL,
    STATUS_TOO_MANY_LUIDS_REQUESTED = 0xFFFFFFFFC0000074LL,
    STATUS_LUIDS_EXHAUSTED = 0xFFFFFFFFC0000075LL,
    STATUS_INVALID_SUB_AUTHORITY = 0xFFFFFFFFC0000076LL,
    STATUS_INVALID_ACL = 0xFFFFFFFFC0000077LL,
    STATUS_INVALID_SID = 0xFFFFFFFFC0000078LL,
    STATUS_INVALID_SECURITY_DESCR = 0xFFFFFFFFC0000079LL,
    STATUS_PROCEDURE_NOT_FOUND = 0xFFFFFFFFC000007ALL,
    STATUS_INVALID_IMAGE_FORMAT = 0xFFFFFFFFC000007BLL,
    STATUS_NO_TOKEN = 0xFFFFFFFFC000007CLL,
    STATUS_BAD_INHERITANCE_ACL = 0xFFFFFFFFC000007DLL,
    STATUS_RANGE_NOT_LOCKED = 0xFFFFFFFFC000007ELL,
    STATUS_DISK_FULL = 0xFFFFFFFFC000007FLL,
    STATUS_SERVER_DISABLED = 0xFFFFFFFFC0000080LL,
    STATUS_SERVER_NOT_DISABLED = 0xFFFFFFFFC0000081LL,
    STATUS_TOO_MANY_GUIDS_REQUESTED = 0xFFFFFFFFC0000082LL,
    STATUS_GUIDS_EXHAUSTED = 0xFFFFFFFFC0000083LL,
    STATUS_INVALID_ID_AUTHORITY = 0xFFFFFFFFC0000084LL,
    STATUS_AGENTS_EXHAUSTED = 0xFFFFFFFFC0000085LL,
    STATUS_INVALID_VOLUME_LABEL = 0xFFFFFFFFC0000086LL,
    STATUS_SECTION_NOT_EXTENDED = 0xFFFFFFFFC0000087LL,
    STATUS_NOT_MAPPED_DATA = 0xFFFFFFFFC0000088LL,
    STATUS_RESOURCE_DATA_NOT_FOUND = 0xFFFFFFFFC0000089LL,
    STATUS_RESOURCE_TYPE_NOT_FOUND = 0xFFFFFFFFC000008ALL,
    STATUS_RESOURCE_NAME_NOT_FOUND = 0xFFFFFFFFC000008BLL,
    STATUS_ARRAY_BOUNDS_EXCEEDED = 0xC000008CLL,
    STATUS_FLOAT_DENORMAL_OPERAND = 0xC000008DLL,
    STATUS_FLOAT_DIVIDE_BY_ZERO = 0xC000008ELL,
    STATUS_FLOAT_INEXACT_RESULT = 0xC000008FLL,
    STATUS_FLOAT_INVALID_OPERATION = 0xC0000090LL,
    STATUS_FLOAT_OVERFLOW = 0xC0000091LL,
    STATUS_FLOAT_STACK_CHECK = 0xC0000092LL,
    STATUS_FLOAT_UNDERFLOW = 0xC0000093LL,
    STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094LL,
    STATUS_INTEGER_OVERFLOW = 0xC0000095LL,
    STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096LL,
    STATUS_TOO_MANY_PAGING_FILES = 0xFFFFFFFFC0000097LL,
    STATUS_FILE_INVALID = 0xFFFFFFFFC0000098LL,
    STATUS_ALLOTTED_SPACE_EXCEEDED = 0xFFFFFFFFC0000099LL,
    STATUS_DFS_EXIT_PATH_FOUND = 0xFFFFFFFFC000009BLL,
    STATUS_DEVICE_DATA_ERROR = 0xFFFFFFFFC000009CLL,
    STATUS_DEVICE_NOT_CONNECTED = 0xFFFFFFFFC000009DLL,
    STATUS_DEVICE_POWER_FAILURE = 0xFFFFFFFFC000009ELL,
    STATUS_FREE_VM_NOT_AT_BASE = 0xFFFFFFFFC000009FLL,
    STATUS_MEMORY_NOT_ALLOCATED = 0xFFFFFFFFC00000A0LL,
    STATUS_WORKING_SET_QUOTA = 0xFFFFFFFFC00000A1LL,
    STATUS_MEDIA_WRITE_PROTECTED = 0xFFFFFFFFC00000A2LL,
    STATUS_DEVICE_NOT_READY = 0xFFFFFFFFC00000A3LL,
    STATUS_INVALID_GROUP_ATTRIBUTES = 0xFFFFFFFFC00000A4LL,
    STATUS_BAD_IMPERSONATION_LEVEL = 0xFFFFFFFFC00000A5LL,
    STATUS_CANT_OPEN_ANONYMOUS = 0xFFFFFFFFC00000A6LL,
    STATUS_BAD_VALIDATION_CLASS = 0xFFFFFFFFC00000A7LL,
    STATUS_BAD_TOKEN_TYPE = 0xFFFFFFFFC00000A8LL,
    STATUS_BAD_MASTER_BOOT_RECORD = 0xFFFFFFFFC00000A9LL,
    STATUS_INSTRUCTION_MISALIGNMENT = 0xFFFFFFFFC00000AALL,
    STATUS_INSTANCE_NOT_AVAILABLE = 0xFFFFFFFFC00000ABLL,
    STATUS_PIPE_NOT_AVAILABLE = 0xFFFFFFFFC00000ACLL,
    STATUS_INVALID_PIPE_STATE = 0xFFFFFFFFC00000ADLL,
    STATUS_PIPE_BUSY = 0xFFFFFFFFC00000AELL,
    STATUS_ILLEGAL_FUNCTION = 0xFFFFFFFFC00000AFLL,
    STATUS_PIPE_DISCONNECTED = 0xFFFFFFFFC00000B0LL,
    STATUS_PIPE_CLOSING = 0xFFFFFFFFC00000B1LL,
    STATUS_PIPE_CONNECTED = 0xFFFFFFFFC00000B2LL,
    STATUS_PIPE_LISTENING = 0xFFFFFFFFC00000B3LL,
    STATUS_INVALID_READ_MODE = 0xFFFFFFFFC00000B4LL,
    STATUS_IO_TIMEOUT = 0xFFFFFFFFC00000B5LL,
    STATUS_FILE_FORCED_CLOSED = 0xFFFFFFFFC00000B6LL,
    STATUS_PROFILING_NOT_STARTED = 0xFFFFFFFFC00000B7LL,
    STATUS_PROFILING_NOT_STOPPED = 0xFFFFFFFFC00000B8LL,
    STATUS_COULD_NOT_INTERPRET = 0xFFFFFFFFC00000B9LL,
    STATUS_FILE_IS_A_DIRECTORY = 0xFFFFFFFFC00000BALL,
    STATUS_NOT_SUPPORTED = 0xFFFFFFFFC00000BBLL,
    STATUS_REMOTE_NOT_LISTENING = 0xFFFFFFFFC00000BCLL,
    STATUS_DUPLICATE_NAME = 0xFFFFFFFFC00000BDLL,
    STATUS_BAD_NETWORK_PATH = 0xFFFFFFFFC00000BELL,
    STATUS_NETWORK_BUSY = 0xFFFFFFFFC00000BFLL,
    STATUS_DEVICE_DOES_NOT_EXIST = 0xFFFFFFFFC00000C0LL,
    STATUS_TOO_MANY_COMMANDS = 0xFFFFFFFFC00000C1LL,
    STATUS_ADAPTER_HARDWARE_ERROR = 0xFFFFFFFFC00000C2LL,
    STATUS_INVALID_NETWORK_RESPONSE = 0xFFFFFFFFC00000C3LL,
    STATUS_UNEXPECTED_NETWORK_ERROR = 0xFFFFFFFFC00000C4LL,
    STATUS_BAD_REMOTE_ADAPTER = 0xFFFFFFFFC00000C5LL,
    STATUS_PRINT_QUEUE_FULL = 0xFFFFFFFFC00000C6LL,
    STATUS_NO_SPOOL_SPACE = 0xFFFFFFFFC00000C7LL,
    STATUS_PRINT_CANCELLED = 0xFFFFFFFFC00000C8LL,
    STATUS_NETWORK_NAME_DELETED = 0xFFFFFFFFC00000C9LL,
    STATUS_NETWORK_ACCESS_DENIED = 0xFFFFFFFFC00000CALL,
    STATUS_BAD_DEVICE_TYPE = 0xFFFFFFFFC00000CBLL,
    STATUS_BAD_NETWORK_NAME = 0xFFFFFFFFC00000CCLL,
    STATUS_TOO_MANY_NAMES = 0xFFFFFFFFC00000CDLL,
    STATUS_TOO_MANY_SESSIONS = 0xFFFFFFFFC00000CELL,
    STATUS_SHARING_PAUSED = 0xFFFFFFFFC00000CFLL,
    STATUS_REQUEST_NOT_ACCEPTED = 0xFFFFFFFFC00000D0LL,
    STATUS_REDIRECTOR_PAUSED = 0xFFFFFFFFC00000D1LL,
    STATUS_NET_WRITE_FAULT = 0xFFFFFFFFC00000D2LL,
    STATUS_PROFILING_AT_LIMIT = 0xFFFFFFFFC00000D3LL,
    STATUS_NOT_SAME_DEVICE = 0xFFFFFFFFC00000D4LL,
    STATUS_FILE_RENAMED = 0xFFFFFFFFC00000D5LL,
    STATUS_VIRTUAL_CIRCUIT_CLOSED = 0xFFFFFFFFC00000D6LL,
    STATUS_NO_SECURITY_ON_OBJECT = 0xFFFFFFFFC00000D7LL,
    STATUS_CANT_WAIT = 0xFFFFFFFFC00000D8LL,
    STATUS_PIPE_EMPTY = 0xFFFFFFFFC00000D9LL,
    STATUS_CANT_ACCESS_DOMAIN_INFO = 0xFFFFFFFFC00000DALL,
    STATUS_CANT_TERMINATE_SELF = 0xFFFFFFFFC00000DBLL,
    STATUS_INVALID_SERVER_STATE = 0xFFFFFFFFC00000DCLL,
    STATUS_INVALID_DOMAIN_STATE = 0xFFFFFFFFC00000DDLL,
    STATUS_INVALID_DOMAIN_ROLE = 0xFFFFFFFFC00000DELL,
    STATUS_NO_SUCH_DOMAIN = 0xFFFFFFFFC00000DFLL,
    STATUS_DOMAIN_EXISTS = 0xFFFFFFFFC00000E0LL,
    STATUS_DOMAIN_LIMIT_EXCEEDED = 0xFFFFFFFFC00000E1LL,
    STATUS_OPLOCK_NOT_GRANTED = 0xFFFFFFFFC00000E2LL,
    STATUS_INVALID_OPLOCK_PROTOCOL = 0xFFFFFFFFC00000E3LL,
    STATUS_INTERNAL_DB_CORRUPTION = 0xFFFFFFFFC00000E4LL,
    STATUS_INTERNAL_ERROR = 0xFFFFFFFFC00000E5LL,
    STATUS_GENERIC_NOT_MAPPED = 0xFFFFFFFFC00000E6LL,
    STATUS_BAD_DESCRIPTOR_FORMAT = 0xFFFFFFFFC00000E7LL,
    STATUS_INVALID_USER_BUFFER = 0xFFFFFFFFC00000E8LL,
    STATUS_UNEXPECTED_IO_ERROR = 0xFFFFFFFFC00000E9LL,
    STATUS_UNEXPECTED_MM_CREATE_ERR = 0xFFFFFFFFC00000EALL,
    STATUS_UNEXPECTED_MM_MAP_ERROR = 0xFFFFFFFFC00000EBLL,
    STATUS_UNEXPECTED_MM_EXTEND_ERR = 0xFFFFFFFFC00000ECLL,
    STATUS_NOT_LOGON_PROCESS = 0xFFFFFFFFC00000EDLL,
    STATUS_LOGON_SESSION_EXISTS = 0xFFFFFFFFC00000EELL,
    STATUS_INVALID_PARAMETER_1 = 0xFFFFFFFFC00000EFLL,
    STATUS_INVALID_PARAMETER_2 = 0xFFFFFFFFC00000F0LL,
    STATUS_INVALID_PARAMETER_3 = 0xFFFFFFFFC00000F1LL,
    STATUS_INVALID_PARAMETER_4 = 0xFFFFFFFFC00000F2LL,
    STATUS_INVALID_PARAMETER_5 = 0xFFFFFFFFC00000F3LL,
    STATUS_INVALID_PARAMETER_6 = 0xFFFFFFFFC00000F4LL,
    STATUS_INVALID_PARAMETER_7 = 0xFFFFFFFFC00000F5LL,
    STATUS_INVALID_PARAMETER_8 = 0xFFFFFFFFC00000F6LL,
    STATUS_INVALID_PARAMETER_9 = 0xFFFFFFFFC00000F7LL,
    STATUS_INVALID_PARAMETER_10 = 0xFFFFFFFFC00000F8LL,
    STATUS_INVALID_PARAMETER_11 = 0xFFFFFFFFC00000F9LL,
    STATUS_INVALID_PARAMETER_12 = 0xFFFFFFFFC00000FALL,
    STATUS_REDIRECTOR_NOT_STARTED = 0xFFFFFFFFC00000FBLL,
    STATUS_REDIRECTOR_STARTED = 0xFFFFFFFFC00000FCLL,
    STATUS_STACK_OVERFLOW = 0xC00000FDLL,
    STATUS_NO_SUCH_PACKAGE = 0xFFFFFFFFC00000FELL,
    STATUS_BAD_FUNCTION_TABLE = 0xFFFFFFFFC00000FFLL,
    STATUS_VARIABLE_NOT_FOUND = 0xFFFFFFFFC0000100LL,
    STATUS_DIRECTORY_NOT_EMPTY = 0xFFFFFFFFC0000101LL,
    STATUS_FILE_CORRUPT_ERROR = 0xFFFFFFFFC0000102LL,
    STATUS_NOT_A_DIRECTORY = 0xFFFFFFFFC0000103LL,
    STATUS_BAD_LOGON_SESSION_STATE = 0xFFFFFFFFC0000104LL,
    STATUS_LOGON_SESSION_COLLISION = 0xFFFFFFFFC0000105LL,
    STATUS_NAME_TOO_LONG = 0xFFFFFFFFC0000106LL,
    STATUS_FILES_OPEN = 0xFFFFFFFFC0000107LL,
    STATUS_CONNECTION_IN_USE = 0xFFFFFFFFC0000108LL,
    STATUS_MESSAGE_NOT_FOUND = 0xFFFFFFFFC0000109LL,
    STATUS_PROCESS_IS_TERMINATING = 0xFFFFFFFFC000010ALL,
    STATUS_INVALID_LOGON_TYPE = 0xFFFFFFFFC000010BLL,
    STATUS_NO_GUID_TRANSLATION = 0xFFFFFFFFC000010CLL,
    STATUS_CANNOT_IMPERSONATE = 0xFFFFFFFFC000010DLL,
    STATUS_IMAGE_ALREADY_LOADED = 0xFFFFFFFFC000010ELL,
    STATUS_ABIOS_NOT_PRESENT = 0xFFFFFFFFC000010FLL,
    STATUS_ABIOS_LID_NOT_EXIST = 0xFFFFFFFFC0000110LL,
    STATUS_ABIOS_LID_ALREADY_OWNED = 0xFFFFFFFFC0000111LL,
    STATUS_ABIOS_NOT_LID_OWNER = 0xFFFFFFFFC0000112LL,
    STATUS_ABIOS_INVALID_COMMAND = 0xFFFFFFFFC0000113LL,
    STATUS_ABIOS_INVALID_LID = 0xFFFFFFFFC0000114LL,
    STATUS_ABIOS_SELECTOR_NOT_AVAILABLE = 0xFFFFFFFFC0000115LL,
    STATUS_ABIOS_INVALID_SELECTOR = 0xFFFFFFFFC0000116LL,
    STATUS_NO_LDT = 0xFFFFFFFFC0000117LL,
    STATUS_INVALID_LDT_SIZE = 0xFFFFFFFFC0000118LL,
    STATUS_INVALID_LDT_OFFSET = 0xFFFFFFFFC0000119LL,
    STATUS_INVALID_LDT_DESCRIPTOR = 0xFFFFFFFFC000011ALL,
    STATUS_INVALID_IMAGE_NE_FORMAT = 0xFFFFFFFFC000011BLL,
    STATUS_RXACT_INVALID_STATE = 0xFFFFFFFFC000011CLL,
    STATUS_RXACT_COMMIT_FAILURE = 0xFFFFFFFFC000011DLL,
    STATUS_MAPPED_FILE_SIZE_ZERO = 0xFFFFFFFFC000011ELL,
    STATUS_TOO_MANY_OPENED_FILES = 0xFFFFFFFFC000011FLL,
    STATUS_CANCELLED = 0xFFFFFFFFC0000120LL,
    STATUS_CANNOT_DELETE = 0xFFFFFFFFC0000121LL,
    STATUS_INVALID_COMPUTER_NAME = 0xFFFFFFFFC0000122LL,
    STATUS_FILE_DELETED = 0xFFFFFFFFC0000123LL,
    STATUS_SPECIAL_ACCOUNT = 0xFFFFFFFFC0000124LL,
    STATUS_SPECIAL_GROUP = 0xFFFFFFFFC0000125LL,
    STATUS_SPECIAL_USER = 0xFFFFFFFFC0000126LL,
    STATUS_MEMBERS_PRIMARY_GROUP = 0xFFFFFFFFC0000127LL,
    STATUS_FILE_CLOSED = 0xFFFFFFFFC0000128LL,
    STATUS_TOO_MANY_THREADS = 0xFFFFFFFFC0000129LL,
    STATUS_THREAD_NOT_IN_PROCESS = 0xFFFFFFFFC000012ALL,
    STATUS_TOKEN_ALREADY_IN_USE = 0xFFFFFFFFC000012BLL,
    STATUS_PAGEFILE_QUOTA_EXCEEDED = 0xFFFFFFFFC000012CLL,
    STATUS_COMMITMENT_LIMIT = 0xFFFFFFFFC000012DLL,
    STATUS_INVALID_IMAGE_LE_FORMAT = 0xFFFFFFFFC000012ELL,
    STATUS_INVALID_IMAGE_NOT_MZ = 0xFFFFFFFFC000012FLL,
    STATUS_INVALID_IMAGE_PROTECT = 0xFFFFFFFFC0000130LL,
    STATUS_INVALID_IMAGE_WIN_16 = 0xFFFFFFFFC0000131LL,
    STATUS_LOGON_SERVER_CONFLICT = 0xFFFFFFFFC0000132LL,
    STATUS_TIME_DIFFERENCE_AT_DC = 0xFFFFFFFFC0000133LL,
    STATUS_SYNCHRONIZATION_REQUIRED = 0xFFFFFFFFC0000134LL,
    STATUS_DLL_NOT_FOUND = 0xC0000135LL,
    STATUS_OPEN_FAILED = 0xFFFFFFFFC0000136LL,
    STATUS_IO_PRIVILEGE_FAILED = 0xFFFFFFFFC0000137LL,
    STATUS_ORDINAL_NOT_FOUND = 0xC0000138LL,
    STATUS_ENTRYPOINT_NOT_FOUND = 0xC0000139LL,
    STATUS_CONTROL_C_EXIT = 0xC000013ALL,
    STATUS_LOCAL_DISCONNECT = 0xFFFFFFFFC000013BLL,
    STATUS_REMOTE_DISCONNECT = 0xFFFFFFFFC000013CLL,
    STATUS_REMOTE_RESOURCES = 0xFFFFFFFFC000013DLL,
    STATUS_LINK_FAILED = 0xFFFFFFFFC000013ELL,
    STATUS_LINK_TIMEOUT = 0xFFFFFFFFC000013FLL,
    STATUS_INVALID_CONNECTION = 0xFFFFFFFFC0000140LL,
    STATUS_INVALID_ADDRESS = 0xFFFFFFFFC0000141LL,
    STATUS_DLL_INIT_FAILED = 0xC0000142LL,
    STATUS_MISSING_SYSTEMFILE = 0xFFFFFFFFC0000143LL,
    STATUS_UNHANDLED_EXCEPTION = 0xFFFFFFFFC0000144LL,
    STATUS_APP_INIT_FAILURE = 0xFFFFFFFFC0000145LL,
    STATUS_PAGEFILE_CREATE_FAILED = 0xFFFFFFFFC0000146LL,
    STATUS_NO_PAGEFILE = 0xFFFFFFFFC0000147LL,
    STATUS_INVALID_LEVEL = 0xFFFFFFFFC0000148LL,
    STATUS_WRONG_PASSWORD_CORE = 0xFFFFFFFFC0000149LL,
    STATUS_ILLEGAL_FLOAT_CONTEXT = 0xFFFFFFFFC000014ALL,
    STATUS_PIPE_BROKEN = 0xFFFFFFFFC000014BLL,
    STATUS_REGISTRY_CORRUPT = 0xFFFFFFFFC000014CLL,
    STATUS_REGISTRY_IO_FAILED = 0xFFFFFFFFC000014DLL,
    STATUS_NO_EVENT_PAIR = 0xFFFFFFFFC000014ELL,
    STATUS_UNRECOGNIZED_VOLUME = 0xFFFFFFFFC000014FLL,
    STATUS_SERIAL_NO_DEVICE_INITED = 0xFFFFFFFFC0000150LL,
    STATUS_NO_SUCH_ALIAS = 0xFFFFFFFFC0000151LL,
    STATUS_MEMBER_NOT_IN_ALIAS = 0xFFFFFFFFC0000152LL,
    STATUS_MEMBER_IN_ALIAS = 0xFFFFFFFFC0000153LL,
    STATUS_ALIAS_EXISTS = 0xFFFFFFFFC0000154LL,
    STATUS_LOGON_NOT_GRANTED = 0xFFFFFFFFC0000155LL,
    STATUS_TOO_MANY_SECRETS = 0xFFFFFFFFC0000156LL,
    STATUS_SECRET_TOO_LONG = 0xFFFFFFFFC0000157LL,
    STATUS_INTERNAL_DB_ERROR = 0xFFFFFFFFC0000158LL,
    STATUS_FULLSCREEN_MODE = 0xFFFFFFFFC0000159LL,
    STATUS_TOO_MANY_CONTEXT_IDS = 0xFFFFFFFFC000015ALL,
    STATUS_NOT_REGISTRY_FILE = 0xFFFFFFFFC000015CLL,
    STATUS_NT_CROSS_ENCRYPTION_REQUIRED = 0xFFFFFFFFC000015DLL,
    STATUS_DOMAIN_CTRLR_CONFIG_ERROR = 0xFFFFFFFFC000015ELL,
    STATUS_FT_MISSING_MEMBER = 0xFFFFFFFFC000015FLL,
    STATUS_ILL_FORMED_SERVICE_ENTRY = 0xFFFFFFFFC0000160LL,
    STATUS_ILLEGAL_CHARACTER = 0xFFFFFFFFC0000161LL,
    STATUS_UNMAPPABLE_CHARACTER = 0xFFFFFFFFC0000162LL,
    STATUS_UNDEFINED_CHARACTER = 0xFFFFFFFFC0000163LL,
    STATUS_FLOPPY_VOLUME = 0xFFFFFFFFC0000164LL,
    STATUS_FLOPPY_ID_MARK_NOT_FOUND = 0xFFFFFFFFC0000165LL,
    STATUS_FLOPPY_WRONG_CYLINDER = 0xFFFFFFFFC0000166LL,
    STATUS_FLOPPY_UNKNOWN_ERROR = 0xFFFFFFFFC0000167LL,
    STATUS_FLOPPY_BAD_REGISTERS = 0xFFFFFFFFC0000168LL,
    STATUS_DISK_RECALIBRATE_FAILED = 0xFFFFFFFFC0000169LL,
    STATUS_DISK_OPERATION_FAILED = 0xFFFFFFFFC000016ALL,
    STATUS_DISK_RESET_FAILED = 0xFFFFFFFFC000016BLL,
    STATUS_SHARED_IRQ_BUSY = 0xFFFFFFFFC000016CLL,
    STATUS_FT_ORPHANING = 0xFFFFFFFFC000016DLL,
    STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT = 0xFFFFFFFFC000016ELL,
    STATUS_PARTITION_FAILURE = 0xFFFFFFFFC0000172LL,
    STATUS_INVALID_BLOCK_LENGTH = 0xFFFFFFFFC0000173LL,
    STATUS_DEVICE_NOT_PARTITIONED = 0xFFFFFFFFC0000174LL,
    STATUS_UNABLE_TO_LOCK_MEDIA = 0xFFFFFFFFC0000175LL,
    STATUS_UNABLE_TO_UNLOAD_MEDIA = 0xFFFFFFFFC0000176LL,
    STATUS_EOM_OVERFLOW = 0xFFFFFFFFC0000177LL,
    STATUS_NO_MEDIA = 0xFFFFFFFFC0000178LL,
    STATUS_NO_SUCH_MEMBER = 0xFFFFFFFFC000017ALL,
    STATUS_INVALID_MEMBER = 0xFFFFFFFFC000017BLL,
    STATUS_KEY_DELETED = 0xFFFFFFFFC000017CLL,
    STATUS_NO_LOG_SPACE = 0xFFFFFFFFC000017DLL,
    STATUS_TOO_MANY_SIDS = 0xFFFFFFFFC000017ELL,
    STATUS_LM_CROSS_ENCRYPTION_REQUIRED = 0xFFFFFFFFC000017FLL,
    STATUS_KEY_HAS_CHILDREN = 0xFFFFFFFFC0000180LL,
    STATUS_CHILD_MUST_BE_VOLATILE = 0xFFFFFFFFC0000181LL,
    STATUS_DEVICE_CONFIGURATION_ERROR = 0xFFFFFFFFC0000182LL,
    STATUS_DRIVER_INTERNAL_ERROR = 0xFFFFFFFFC0000183LL,
    STATUS_INVALID_DEVICE_STATE = 0xFFFFFFFFC0000184LL,
    STATUS_IO_DEVICE_ERROR = 0xFFFFFFFFC0000185LL,
    STATUS_DEVICE_PROTOCOL_ERROR = 0xFFFFFFFFC0000186LL,
    STATUS_BACKUP_CONTROLLER = 0xFFFFFFFFC0000187LL,
    STATUS_LOG_FILE_FULL = 0xFFFFFFFFC0000188LL,
    STATUS_TOO_LATE = 0xFFFFFFFFC0000189LL,
    STATUS_NO_TRUST_LSA_SECRET = 0xFFFFFFFFC000018ALL,
    STATUS_NO_TRUST_SAM_ACCOUNT = 0xFFFFFFFFC000018BLL,
    STATUS_TRUSTED_DOMAIN_FAILURE = 0xFFFFFFFFC000018CLL,
    STATUS_TRUSTED_RELATIONSHIP_FAILURE = 0xFFFFFFFFC000018DLL,
    STATUS_EVENTLOG_FILE_CORRUPT = 0xFFFFFFFFC000018ELL,
    STATUS_EVENTLOG_CANT_START = 0xFFFFFFFFC000018FLL,
    STATUS_TRUST_FAILURE = 0xFFFFFFFFC0000190LL,
    STATUS_MUTANT_LIMIT_EXCEEDED = 0xFFFFFFFFC0000191LL,
    STATUS_NETLOGON_NOT_STARTED = 0xFFFFFFFFC0000192LL,
    STATUS_POSSIBLE_DEADLOCK = 0xFFFFFFFFC0000194LL,
    STATUS_NETWORK_CREDENTIAL_CONFLICT = 0xFFFFFFFFC0000195LL,
    STATUS_REMOTE_SESSION_LIMIT = 0xFFFFFFFFC0000196LL,
    STATUS_EVENTLOG_FILE_CHANGED = 0xFFFFFFFFC0000197LL,
    STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 0xFFFFFFFFC0000198LL,
    STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xFFFFFFFFC0000199LL,
    STATUS_NOLOGON_SERVER_TRUST_ACCOUNT = 0xFFFFFFFFC000019ALL,
    STATUS_DOMAIN_TRUST_INCONSISTENT = 0xFFFFFFFFC000019BLL,
    STATUS_FS_DRIVER_REQUIRED = 0xFFFFFFFFC000019CLL,
    STATUS_IMAGE_ALREADY_LOADED_AS_DLL = 0xFFFFFFFFC000019DLL,
    STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING = 0xFFFFFFFFC000019ELL,
    STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME = 0xFFFFFFFFC000019FLL,
    STATUS_SECURITY_STREAM_IS_INCONSISTENT = 0xFFFFFFFFC00001A0LL,
    STATUS_INVALID_LOCK_RANGE = 0xFFFFFFFFC00001A1LL,
    STATUS_INVALID_ACE_CONDITION = 0xFFFFFFFFC00001A2LL,
    STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT = 0xFFFFFFFFC00001A3LL,
    STATUS_NOTIFICATION_GUID_ALREADY_DEFINED = 0xFFFFFFFFC00001A4LL,
    STATUS_INVALID_EXCEPTION_HANDLER = 0xFFFFFFFFC00001A5LL,
    STATUS_DUPLICATE_PRIVILEGES = 0xFFFFFFFFC00001A6LL,
    STATUS_NOT_ALLOWED_ON_SYSTEM_FILE = 0xFFFFFFFFC00001A7LL,
    STATUS_REPAIR_NEEDED = 0xFFFFFFFFC00001A8LL,
    STATUS_QUOTA_NOT_ENABLED = 0xFFFFFFFFC00001A9LL,
    STATUS_NO_APPLICATION_PACKAGE = 0xFFFFFFFFC00001AALL,
    STATUS_FILE_METADATA_OPTIMIZATION_IN_PROGRESS = 0xFFFFFFFFC00001ABLL,
    STATUS_NOT_SAME_OBJECT = 0xFFFFFFFFC00001ACLL,
    STATUS_FATAL_MEMORY_EXHAUSTION = 0xFFFFFFFFC00001ADLL,
    STATUS_ERROR_PROCESS_NOT_IN_JOB = 0xFFFFFFFFC00001AELL,
    STATUS_CPU_SET_INVALID = 0xFFFFFFFFC00001AFLL,
    STATUS_IO_DEVICE_INVALID_DATA = 0xFFFFFFFFC00001B0LL,
    STATUS_NETWORK_OPEN_RESTRICTION = 0xFFFFFFFFC0000201LL,
    STATUS_NO_USER_SESSION_KEY = 0xFFFFFFFFC0000202LL,
    STATUS_USER_SESSION_DELETED = 0xFFFFFFFFC0000203LL,
    STATUS_RESOURCE_LANG_NOT_FOUND = 0xFFFFFFFFC0000204LL,
    STATUS_INSUFF_SERVER_RESOURCES = 0xFFFFFFFFC0000205LL,
    STATUS_INVALID_BUFFER_SIZE = 0xFFFFFFFFC0000206LL,
    STATUS_INVALID_ADDRESS_COMPONENT = 0xFFFFFFFFC0000207LL,
    STATUS_INVALID_ADDRESS_WILDCARD = 0xFFFFFFFFC0000208LL,
    STATUS_TOO_MANY_ADDRESSES = 0xFFFFFFFFC0000209LL,
    STATUS_ADDRESS_ALREADY_EXISTS = 0xFFFFFFFFC000020ALL,
    STATUS_ADDRESS_CLOSED = 0xFFFFFFFFC000020BLL,
    STATUS_CONNECTION_DISCONNECTED = 0xFFFFFFFFC000020CLL,
    STATUS_CONNECTION_RESET = 0xFFFFFFFFC000020DLL,
    STATUS_TOO_MANY_NODES = 0xFFFFFFFFC000020ELL,
    STATUS_TRANSACTION_ABORTED = 0xFFFFFFFFC000020FLL,
    STATUS_TRANSACTION_TIMED_OUT = 0xFFFFFFFFC0000210LL,
    STATUS_TRANSACTION_NO_RELEASE = 0xFFFFFFFFC0000211LL,
    STATUS_TRANSACTION_NO_MATCH = 0xFFFFFFFFC0000212LL,
    STATUS_TRANSACTION_RESPONDED = 0xFFFFFFFFC0000213LL,
    STATUS_TRANSACTION_INVALID_ID = 0xFFFFFFFFC0000214LL,
    STATUS_TRANSACTION_INVALID_TYPE = 0xFFFFFFFFC0000215LL,
    STATUS_NOT_SERVER_SESSION = 0xFFFFFFFFC0000216LL,
    STATUS_NOT_CLIENT_SESSION = 0xFFFFFFFFC0000217LL,
    STATUS_CANNOT_LOAD_REGISTRY_FILE = 0xFFFFFFFFC0000218LL,
    STATUS_DEBUG_ATTACH_FAILED = 0xFFFFFFFFC0000219LL,
    STATUS_SYSTEM_PROCESS_TERMINATED = 0xFFFFFFFFC000021ALL,
    STATUS_DATA_NOT_ACCEPTED = 0xFFFFFFFFC000021BLL,
    STATUS_NO_BROWSER_SERVERS_FOUND = 0xFFFFFFFFC000021CLL,
    STATUS_VDM_HARD_ERROR = 0xFFFFFFFFC000021DLL,
    STATUS_DRIVER_CANCEL_TIMEOUT = 0xFFFFFFFFC000021ELL,
    STATUS_REPLY_MESSAGE_MISMATCH = 0xFFFFFFFFC000021FLL,
    STATUS_MAPPED_ALIGNMENT = 0xFFFFFFFFC0000220LL,
    STATUS_IMAGE_CHECKSUM_MISMATCH = 0xFFFFFFFFC0000221LL,
    STATUS_LOST_WRITEBEHIND_DATA = 0xFFFFFFFFC0000222LL,
    STATUS_CLIENT_SERVER_PARAMETERS_INVALID = 0xFFFFFFFFC0000223LL,
    STATUS_NOT_FOUND = 0xFFFFFFFFC0000225LL,
    STATUS_NOT_TINY_STREAM = 0xFFFFFFFFC0000226LL,
    STATUS_RECOVERY_FAILURE = 0xFFFFFFFFC0000227LL,
    STATUS_STACK_OVERFLOW_READ = 0xFFFFFFFFC0000228LL,
    STATUS_FAIL_CHECK = 0xFFFFFFFFC0000229LL,
    STATUS_DUPLICATE_OBJECTID = 0xFFFFFFFFC000022ALL,
    STATUS_OBJECTID_EXISTS = 0xFFFFFFFFC000022BLL,
    STATUS_CONVERT_TO_LARGE = 0xFFFFFFFFC000022CLL,
    STATUS_RETRY = 0xFFFFFFFFC000022DLL,
    STATUS_FOUND_OUT_OF_SCOPE = 0xFFFFFFFFC000022ELL,
    STATUS_ALLOCATE_BUCKET = 0xFFFFFFFFC000022FLL,
    STATUS_PROPSET_NOT_FOUND = 0xFFFFFFFFC0000230LL,
    STATUS_MARSHALL_OVERFLOW = 0xFFFFFFFFC0000231LL,
    STATUS_INVALID_VARIANT = 0xFFFFFFFFC0000232LL,
    STATUS_DOMAIN_CONTROLLER_NOT_FOUND = 0xFFFFFFFFC0000233LL,
    STATUS_HANDLE_NOT_CLOSABLE = 0xFFFFFFFFC0000235LL,
    STATUS_CONNECTION_REFUSED = 0xFFFFFFFFC0000236LL,
    STATUS_GRACEFUL_DISCONNECT = 0xFFFFFFFFC0000237LL,
    STATUS_ADDRESS_ALREADY_ASSOCIATED = 0xFFFFFFFFC0000238LL,
    STATUS_ADDRESS_NOT_ASSOCIATED = 0xFFFFFFFFC0000239LL,
    STATUS_CONNECTION_INVALID = 0xFFFFFFFFC000023ALL,
    STATUS_CONNECTION_ACTIVE = 0xFFFFFFFFC000023BLL,
    STATUS_NETWORK_UNREACHABLE = 0xFFFFFFFFC000023CLL,
    STATUS_HOST_UNREACHABLE = 0xFFFFFFFFC000023DLL,
    STATUS_PROTOCOL_UNREACHABLE = 0xFFFFFFFFC000023ELL,
    STATUS_PORT_UNREACHABLE = 0xFFFFFFFFC000023FLL,
    STATUS_REQUEST_ABORTED = 0xFFFFFFFFC0000240LL,
    STATUS_CONNECTION_ABORTED = 0xFFFFFFFFC0000241LL,
    STATUS_BAD_COMPRESSION_BUFFER = 0xFFFFFFFFC0000242LL,
    STATUS_USER_MAPPED_FILE = 0xFFFFFFFFC0000243LL,
    STATUS_AUDIT_FAILED = 0xFFFFFFFFC0000244LL,
    STATUS_TIMER_RESOLUTION_NOT_SET = 0xFFFFFFFFC0000245LL,
    STATUS_CONNECTION_COUNT_LIMIT = 0xFFFFFFFFC0000246LL,
    STATUS_LOGIN_TIME_RESTRICTION = 0xFFFFFFFFC0000247LL,
    STATUS_LOGIN_WKSTA_RESTRICTION = 0xFFFFFFFFC0000248LL,
    STATUS_IMAGE_MP_UP_MISMATCH = 0xFFFFFFFFC0000249LL,
    STATUS_INSUFFICIENT_LOGON_INFO = 0xFFFFFFFFC0000250LL,
    STATUS_BAD_DLL_ENTRYPOINT = 0xFFFFFFFFC0000251LL,
    STATUS_BAD_SERVICE_ENTRYPOINT = 0xFFFFFFFFC0000252LL,
    STATUS_LPC_REPLY_LOST = 0xFFFFFFFFC0000253LL,
    STATUS_IP_ADDRESS_CONFLICT1 = 0xFFFFFFFFC0000254LL,
    STATUS_IP_ADDRESS_CONFLICT2 = 0xFFFFFFFFC0000255LL,
    STATUS_REGISTRY_QUOTA_LIMIT = 0xFFFFFFFFC0000256LL,
    STATUS_PATH_NOT_COVERED = 0xFFFFFFFFC0000257LL,
    STATUS_NO_CALLBACK_ACTIVE = 0xFFFFFFFFC0000258LL,
    STATUS_LICENSE_QUOTA_EXCEEDED = 0xFFFFFFFFC0000259LL,
    STATUS_PWD_TOO_SHORT = 0xFFFFFFFFC000025ALL,
    STATUS_PWD_TOO_RECENT = 0xFFFFFFFFC000025BLL,
    STATUS_PWD_HISTORY_CONFLICT = 0xFFFFFFFFC000025CLL,
    STATUS_PLUGPLAY_NO_DEVICE = 0xFFFFFFFFC000025ELL,
    STATUS_UNSUPPORTED_COMPRESSION = 0xFFFFFFFFC000025FLL,
    STATUS_INVALID_HW_PROFILE = 0xFFFFFFFFC0000260LL,
    STATUS_INVALID_PLUGPLAY_DEVICE_PATH = 0xFFFFFFFFC0000261LL,
    STATUS_DRIVER_ORDINAL_NOT_FOUND = 0xFFFFFFFFC0000262LL,
    STATUS_DRIVER_ENTRYPOINT_NOT_FOUND = 0xFFFFFFFFC0000263LL,
    STATUS_RESOURCE_NOT_OWNED = 0xFFFFFFFFC0000264LL,
    STATUS_TOO_MANY_LINKS = 0xFFFFFFFFC0000265LL,
    STATUS_QUOTA_LIST_INCONSISTENT = 0xFFFFFFFFC0000266LL,
    STATUS_FILE_IS_OFFLINE = 0xFFFFFFFFC0000267LL,
    STATUS_EVALUATION_EXPIRATION = 0xFFFFFFFFC0000268LL,
    STATUS_ILLEGAL_DLL_RELOCATION = 0xFFFFFFFFC0000269LL,
    STATUS_LICENSE_VIOLATION = 0xFFFFFFFFC000026ALL,
    STATUS_DLL_INIT_FAILED_LOGOFF = 0xFFFFFFFFC000026BLL,
    STATUS_DRIVER_UNABLE_TO_LOAD = 0xFFFFFFFFC000026CLL,
    STATUS_DFS_UNAVAILABLE = 0xFFFFFFFFC000026DLL,
    STATUS_VOLUME_DISMOUNTED = 0xFFFFFFFFC000026ELL,
    STATUS_WX86_INTERNAL_ERROR = 0xFFFFFFFFC000026FLL,
    STATUS_WX86_FLOAT_STACK_CHECK = 0xFFFFFFFFC0000270LL,
    STATUS_VALIDATE_CONTINUE = 0xFFFFFFFFC0000271LL,
    STATUS_NO_MATCH = 0xFFFFFFFFC0000272LL,
    STATUS_NO_MORE_MATCHES = 0xFFFFFFFFC0000273LL,
    STATUS_NOT_A_REPARSE_POINT = 0xFFFFFFFFC0000275LL,
    STATUS_IO_REPARSE_TAG_INVALID = 0xFFFFFFFFC0000276LL,
    STATUS_IO_REPARSE_TAG_MISMATCH = 0xFFFFFFFFC0000277LL,
    STATUS_IO_REPARSE_DATA_INVALID = 0xFFFFFFFFC0000278LL,
    STATUS_IO_REPARSE_TAG_NOT_HANDLED = 0xFFFFFFFFC0000279LL,
    STATUS_PWD_TOO_LONG = 0xFFFFFFFFC000027ALL,
    STATUS_STOWED_EXCEPTION = 0xFFFFFFFFC000027BLL,
    STATUS_CONTEXT_STOWED_EXCEPTION = 0xFFFFFFFFC000027CLL,
    STATUS_REPARSE_POINT_NOT_RESOLVED = 0xFFFFFFFFC0000280LL,
    STATUS_DIRECTORY_IS_A_REPARSE_POINT = 0xFFFFFFFFC0000281LL,
    STATUS_RANGE_LIST_CONFLICT = 0xFFFFFFFFC0000282LL,
    STATUS_SOURCE_ELEMENT_EMPTY = 0xFFFFFFFFC0000283LL,
    STATUS_DESTINATION_ELEMENT_FULL = 0xFFFFFFFFC0000284LL,
    STATUS_ILLEGAL_ELEMENT_ADDRESS = 0xFFFFFFFFC0000285LL,
    STATUS_MAGAZINE_NOT_PRESENT = 0xFFFFFFFFC0000286LL,
    STATUS_REINITIALIZATION_NEEDED = 0xFFFFFFFFC0000287LL,
    STATUS_DEVICE_REQUIRES_CLEANING = 0xFFFFFFFF80000288LL,
    STATUS_DEVICE_DOOR_OPEN = 0xFFFFFFFF80000289LL,
    STATUS_ENCRYPTION_FAILED = 0xFFFFFFFFC000028ALL,
    STATUS_DECRYPTION_FAILED = 0xFFFFFFFFC000028BLL,
    STATUS_RANGE_NOT_FOUND = 0xFFFFFFFFC000028CLL,
    STATUS_NO_RECOVERY_POLICY = 0xFFFFFFFFC000028DLL,
    STATUS_NO_EFS = 0xFFFFFFFFC000028ELL,
    STATUS_WRONG_EFS = 0xFFFFFFFFC000028FLL,
    STATUS_NO_USER_KEYS = 0xFFFFFFFFC0000290LL,
    STATUS_FILE_NOT_ENCRYPTED = 0xFFFFFFFFC0000291LL,
    STATUS_NOT_EXPORT_FORMAT = 0xFFFFFFFFC0000292LL,
    STATUS_FILE_ENCRYPTED = 0xFFFFFFFFC0000293LL,
    STATUS_WAKE_SYSTEM = 0x40000294LL,
    STATUS_WMI_GUID_NOT_FOUND = 0xFFFFFFFFC0000295LL,
    STATUS_WMI_INSTANCE_NOT_FOUND = 0xFFFFFFFFC0000296LL,
    STATUS_WMI_ITEMID_NOT_FOUND = 0xFFFFFFFFC0000297LL,
    STATUS_WMI_TRY_AGAIN = 0xFFFFFFFFC0000298LL,
    STATUS_SHARED_POLICY = 0xFFFFFFFFC0000299LL,
    STATUS_POLICY_OBJECT_NOT_FOUND = 0xFFFFFFFFC000029ALL,
    STATUS_POLICY_ONLY_IN_DS = 0xFFFFFFFFC000029BLL,
    STATUS_VOLUME_NOT_UPGRADED = 0xFFFFFFFFC000029CLL,
    STATUS_REMOTE_STORAGE_NOT_ACTIVE = 0xFFFFFFFFC000029DLL,
    STATUS_REMOTE_STORAGE_MEDIA_ERROR = 0xFFFFFFFFC000029ELL,
    STATUS_NO_TRACKING_SERVICE = 0xFFFFFFFFC000029FLL,
    STATUS_SERVER_SID_MISMATCH = 0xFFFFFFFFC00002A0LL,
    STATUS_DS_NO_ATTRIBUTE_OR_VALUE = 0xFFFFFFFFC00002A1LL,
    STATUS_DS_INVALID_ATTRIBUTE_SYNTAX = 0xFFFFFFFFC00002A2LL,
    STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED = 0xFFFFFFFFC00002A3LL,
    STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS = 0xFFFFFFFFC00002A4LL,
    STATUS_DS_BUSY = 0xFFFFFFFFC00002A5LL,
    STATUS_DS_UNAVAILABLE = 0xFFFFFFFFC00002A6LL,
    STATUS_DS_NO_RIDS_ALLOCATED = 0xFFFFFFFFC00002A7LL,
    STATUS_DS_NO_MORE_RIDS = 0xFFFFFFFFC00002A8LL,
    STATUS_DS_INCORRECT_ROLE_OWNER = 0xFFFFFFFFC00002A9LL,
    STATUS_DS_RIDMGR_INIT_ERROR = 0xFFFFFFFFC00002AALL,
    STATUS_DS_OBJ_CLASS_VIOLATION = 0xFFFFFFFFC00002ABLL,
    STATUS_DS_CANT_ON_NON_LEAF = 0xFFFFFFFFC00002ACLL,
    STATUS_DS_CANT_ON_RDN = 0xFFFFFFFFC00002ADLL,
    STATUS_DS_CANT_MOD_OBJ_CLASS = 0xFFFFFFFFC00002AELL,
    STATUS_DS_CROSS_DOM_MOVE_FAILED = 0xFFFFFFFFC00002AFLL,
    STATUS_DS_GC_NOT_AVAILABLE = 0xFFFFFFFFC00002B0LL,
    STATUS_DIRECTORY_SERVICE_REQUIRED = 0xFFFFFFFFC00002B1LL,
    STATUS_REPARSE_ATTRIBUTE_CONFLICT = 0xFFFFFFFFC00002B2LL,
    STATUS_CANT_ENABLE_DENY_ONLY = 0xFFFFFFFFC00002B3LL,
    STATUS_FLOAT_MULTIPLE_FAULTS = 0xC00002B4LL,
    STATUS_FLOAT_MULTIPLE_TRAPS = 0xC00002B5LL,
    STATUS_DEVICE_REMOVED = 0xFFFFFFFFC00002B6LL,
    STATUS_JOURNAL_DELETE_IN_PROGRESS = 0xFFFFFFFFC00002B7LL,
    STATUS_JOURNAL_NOT_ACTIVE = 0xFFFFFFFFC00002B8LL,
    STATUS_NOINTERFACE = 0xFFFFFFFFC00002B9LL,
    STATUS_DS_RIDMGR_DISABLED = 0xFFFFFFFFC00002BALL,
    STATUS_DS_ADMIN_LIMIT_EXCEEDED = 0xFFFFFFFFC00002C1LL,
    STATUS_DRIVER_FAILED_SLEEP = 0xFFFFFFFFC00002C2LL,
    STATUS_MUTUAL_AUTHENTICATION_FAILED = 0xFFFFFFFFC00002C3LL,
    STATUS_CORRUPT_SYSTEM_FILE = 0xFFFFFFFFC00002C4LL,
    STATUS_DATATYPE_MISALIGNMENT_ERROR = 0xFFFFFFFFC00002C5LL,
    STATUS_WMI_READ_ONLY = 0xFFFFFFFFC00002C6LL,
    STATUS_WMI_SET_FAILURE = 0xFFFFFFFFC00002C7LL,
    STATUS_COMMITMENT_MINIMUM = 0xFFFFFFFFC00002C8LL,
    STATUS_REG_NAT_CONSUMPTION = 0xC00002C9LL,
    STATUS_TRANSPORT_FULL = 0xFFFFFFFFC00002CALL,
    STATUS_DS_SAM_INIT_FAILURE = 0xFFFFFFFFC00002CBLL,
    STATUS_ONLY_IF_CONNECTED = 0xFFFFFFFFC00002CCLL,
    STATUS_DS_SENSITIVE_GROUP_VIOLATION = 0xFFFFFFFFC00002CDLL,
    STATUS_PNP_RESTART_ENUMERATION = 0xFFFFFFFFC00002CELL,
    STATUS_JOURNAL_ENTRY_DELETED = 0xFFFFFFFFC00002CFLL,
    STATUS_DS_CANT_MOD_PRIMARYGROUPID = 0xFFFFFFFFC00002D0LL,
    STATUS_SYSTEM_IMAGE_BAD_SIGNATURE = 0xFFFFFFFFC00002D1LL,
    STATUS_PNP_REBOOT_REQUIRED = 0xFFFFFFFFC00002D2LL,
    STATUS_POWER_STATE_INVALID = 0xFFFFFFFFC00002D3LL,
    STATUS_DS_INVALID_GROUP_TYPE = 0xFFFFFFFFC00002D4LL,
    STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN = 0xFFFFFFFFC00002D5LL,
    STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN = 0xFFFFFFFFC00002D6LL,
    STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER = 0xFFFFFFFFC00002D7LL,
    STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER = 0xFFFFFFFFC00002D8LL,
    STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER = 0xFFFFFFFFC00002D9LL,
    STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER = 0xFFFFFFFFC00002DALL,
    STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER = 0xFFFFFFFFC00002DBLL,
    STATUS_DS_HAVE_PRIMARY_MEMBERS = 0xFFFFFFFFC00002DCLL,
    STATUS_WMI_NOT_SUPPORTED = 0xFFFFFFFFC00002DDLL,
    STATUS_INSUFFICIENT_POWER = 0xFFFFFFFFC00002DELL,
    STATUS_SAM_NEED_BOOTKEY_PASSWORD = 0xFFFFFFFFC00002DFLL,
    STATUS_SAM_NEED_BOOTKEY_FLOPPY = 0xFFFFFFFFC00002E0LL,
    STATUS_DS_CANT_START = 0xFFFFFFFFC00002E1LL,
    STATUS_DS_INIT_FAILURE = 0xFFFFFFFFC00002E2LL,
    STATUS_SAM_INIT_FAILURE = 0xFFFFFFFFC00002E3LL,
    STATUS_DS_GC_REQUIRED = 0xFFFFFFFFC00002E4LL,
    STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY = 0xFFFFFFFFC00002E5LL,
    STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS = 0xFFFFFFFFC00002E6LL,
    STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED = 0xFFFFFFFFC00002E7LL,
    STATUS_MULTIPLE_FAULT_VIOLATION = 0xFFFFFFFFC00002E8LL,
    STATUS_CURRENT_DOMAIN_NOT_ALLOWED = 0xFFFFFFFFC00002E9LL,
    STATUS_CANNOT_MAKE = 0xFFFFFFFFC00002EALL,
    STATUS_SYSTEM_SHUTDOWN = 0xFFFFFFFFC00002EBLL,
    STATUS_DS_INIT_FAILURE_CONSOLE = 0xFFFFFFFFC00002ECLL,
    STATUS_DS_SAM_INIT_FAILURE_CONSOLE = 0xFFFFFFFFC00002EDLL,
    STATUS_UNFINISHED_CONTEXT_DELETED = 0xFFFFFFFFC00002EELL,
    STATUS_NO_TGT_REPLY = 0xFFFFFFFFC00002EFLL,
    STATUS_OBJECTID_NOT_FOUND = 0xFFFFFFFFC00002F0LL,
    STATUS_NO_IP_ADDRESSES = 0xFFFFFFFFC00002F1LL,
    STATUS_WRONG_CREDENTIAL_HANDLE = 0xFFFFFFFFC00002F2LL,
    STATUS_CRYPTO_SYSTEM_INVALID = 0xFFFFFFFFC00002F3LL,
    STATUS_MAX_REFERRALS_EXCEEDED = 0xFFFFFFFFC00002F4LL,
    STATUS_MUST_BE_KDC = 0xFFFFFFFFC00002F5LL,
    STATUS_STRONG_CRYPTO_NOT_SUPPORTED = 0xFFFFFFFFC00002F6LL,
    STATUS_TOO_MANY_PRINCIPALS = 0xFFFFFFFFC00002F7LL,
    STATUS_NO_PA_DATA = 0xFFFFFFFFC00002F8LL,
    STATUS_PKINIT_NAME_MISMATCH = 0xFFFFFFFFC00002F9LL,
    STATUS_SMARTCARD_LOGON_REQUIRED = 0xFFFFFFFFC00002FALL,
    STATUS_KDC_INVALID_REQUEST = 0xFFFFFFFFC00002FBLL,
    STATUS_KDC_UNABLE_TO_REFER = 0xFFFFFFFFC00002FCLL,
    STATUS_KDC_UNKNOWN_ETYPE = 0xFFFFFFFFC00002FDLL,
    STATUS_SHUTDOWN_IN_PROGRESS = 0xFFFFFFFFC00002FELL,
    STATUS_SERVER_SHUTDOWN_IN_PROGRESS = 0xFFFFFFFFC00002FFLL,
    STATUS_NOT_SUPPORTED_ON_SBS = 0xFFFFFFFFC0000300LL,
    STATUS_WMI_GUID_DISCONNECTED = 0xFFFFFFFFC0000301LL,
    STATUS_WMI_ALREADY_DISABLED = 0xFFFFFFFFC0000302LL,
    STATUS_WMI_ALREADY_ENABLED = 0xFFFFFFFFC0000303LL,
    STATUS_MFT_TOO_FRAGMENTED = 0xFFFFFFFFC0000304LL,
    STATUS_COPY_PROTECTION_FAILURE = 0xFFFFFFFFC0000305LL,
    STATUS_CSS_AUTHENTICATION_FAILURE = 0xFFFFFFFFC0000306LL,
    STATUS_CSS_KEY_NOT_PRESENT = 0xFFFFFFFFC0000307LL,
    STATUS_CSS_KEY_NOT_ESTABLISHED = 0xFFFFFFFFC0000308LL,
    STATUS_CSS_SCRAMBLED_SECTOR = 0xFFFFFFFFC0000309LL,
    STATUS_CSS_REGION_MISMATCH = 0xFFFFFFFFC000030ALL,
    STATUS_CSS_RESETS_EXHAUSTED = 0xFFFFFFFFC000030BLL,
    STATUS_PASSWORD_CHANGE_REQUIRED = 0xFFFFFFFFC000030CLL,
    STATUS_LOST_MODE_LOGON_RESTRICTION = 0xFFFFFFFFC000030DLL,
    STATUS_PKINIT_FAILURE = 0xFFFFFFFFC0000320LL,
    STATUS_SMARTCARD_SUBSYSTEM_FAILURE = 0xFFFFFFFFC0000321LL,
    STATUS_NO_KERB_KEY = 0xFFFFFFFFC0000322LL,
    STATUS_HOST_DOWN = 0xFFFFFFFFC0000350LL,
    STATUS_UNSUPPORTED_PREAUTH = 0xFFFFFFFFC0000351LL,
    STATUS_EFS_ALG_BLOB_TOO_BIG = 0xFFFFFFFFC0000352LL,
    STATUS_PORT_NOT_SET = 0xFFFFFFFFC0000353LL,
    STATUS_DEBUGGER_INACTIVE = 0xFFFFFFFFC0000354LL,
    STATUS_DS_VERSION_CHECK_FAILURE = 0xFFFFFFFFC0000355LL,
    STATUS_AUDITING_DISABLED = 0xFFFFFFFFC0000356LL,
    STATUS_PRENT4_MACHINE_ACCOUNT = 0xFFFFFFFFC0000357LL,
    STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER = 0xFFFFFFFFC0000358LL,
    STATUS_INVALID_IMAGE_WIN_32 = 0xFFFFFFFFC0000359LL,
    STATUS_INVALID_IMAGE_WIN_64 = 0xFFFFFFFFC000035ALL,
    STATUS_BAD_BINDINGS = 0xFFFFFFFFC000035BLL,
    STATUS_NETWORK_SESSION_EXPIRED = 0xFFFFFFFFC000035CLL,
    STATUS_APPHELP_BLOCK = 0xFFFFFFFFC000035DLL,
    STATUS_ALL_SIDS_FILTERED = 0xFFFFFFFFC000035ELL,
    STATUS_NOT_SAFE_MODE_DRIVER = 0xFFFFFFFFC000035FLL,
    STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT = 0xFFFFFFFFC0000361LL,
    STATUS_ACCESS_DISABLED_BY_POLICY_PATH = 0xFFFFFFFFC0000362LL,
    STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER = 0xFFFFFFFFC0000363LL,
    STATUS_ACCESS_DISABLED_BY_POLICY_OTHER = 0xFFFFFFFFC0000364LL,
    STATUS_FAILED_DRIVER_ENTRY = 0xFFFFFFFFC0000365LL,
    STATUS_DEVICE_ENUMERATION_ERROR = 0xFFFFFFFFC0000366LL,
    STATUS_MOUNT_POINT_NOT_RESOLVED = 0xFFFFFFFFC0000368LL,
    STATUS_INVALID_DEVICE_OBJECT_PARAMETER = 0xFFFFFFFFC0000369LL,
    STATUS_MCA_OCCURED = 0xFFFFFFFFC000036ALL,
    STATUS_DRIVER_BLOCKED_CRITICAL = 0xFFFFFFFFC000036BLL,
    STATUS_DRIVER_BLOCKED = 0xFFFFFFFFC000036CLL,
    STATUS_DRIVER_DATABASE_ERROR = 0xFFFFFFFFC000036DLL,
    STATUS_SYSTEM_HIVE_TOO_LARGE = 0xFFFFFFFFC000036ELL,
    STATUS_INVALID_IMPORT_OF_NON_DLL = 0xFFFFFFFFC000036FLL,
    STATUS_DS_SHUTTING_DOWN = 0x40000370LL,
    STATUS_NO_SECRETS = 0xFFFFFFFFC0000371LL,
    STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY = 0xFFFFFFFFC0000372LL,
    STATUS_FAILED_STACK_SWITCH = 0xFFFFFFFFC0000373LL,
    STATUS_HEAP_CORRUPTION = 0xFFFFFFFFC0000374LL,
    STATUS_SMARTCARD_WRONG_PIN = 0xFFFFFFFFC0000380LL,
    STATUS_SMARTCARD_CARD_BLOCKED = 0xFFFFFFFFC0000381LL,
    STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED = 0xFFFFFFFFC0000382LL,
    STATUS_SMARTCARD_NO_CARD = 0xFFFFFFFFC0000383LL,
    STATUS_SMARTCARD_NO_KEY_CONTAINER = 0xFFFFFFFFC0000384LL,
    STATUS_SMARTCARD_NO_CERTIFICATE = 0xFFFFFFFFC0000385LL,
    STATUS_SMARTCARD_NO_KEYSET = 0xFFFFFFFFC0000386LL,
    STATUS_SMARTCARD_IO_ERROR = 0xFFFFFFFFC0000387LL,
    STATUS_SMARTCARD_CERT_REVOKED = 0xFFFFFFFFC0000389LL,
    STATUS_ISSUING_CA_UNTRUSTED = 0xFFFFFFFFC000038ALL,
    STATUS_REVOCATION_OFFLINE_C = 0xFFFFFFFFC000038BLL,
    STATUS_PKINIT_CLIENT_FAILURE = 0xFFFFFFFFC000038CLL,
    STATUS_SMARTCARD_CERT_EXPIRED = 0xFFFFFFFFC000038DLL,
    STATUS_DRIVER_FAILED_PRIOR_UNLOAD = 0xFFFFFFFFC000038ELL,
    STATUS_SMARTCARD_SILENT_CONTEXT = 0xFFFFFFFFC000038FLL,
    STATUS_PER_USER_TRUST_QUOTA_EXCEEDED = 0xFFFFFFFFC0000401LL,
    STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED = 0xFFFFFFFFC0000402LL,
    STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED = 0xFFFFFFFFC0000403LL,
    STATUS_DS_NAME_NOT_UNIQUE = 0xFFFFFFFFC0000404LL,
    STATUS_DS_DUPLICATE_ID_FOUND = 0xFFFFFFFFC0000405LL,
    STATUS_DS_GROUP_CONVERSION_ERROR = 0xFFFFFFFFC0000406LL,
    STATUS_VOLSNAP_PREPARE_HIBERNATE = 0xFFFFFFFFC0000407LL,
    STATUS_USER2USER_REQUIRED = 0xFFFFFFFFC0000408LL,
    STATUS_STACK_BUFFER_OVERRUN = 0xC0000409LL,
    STATUS_NO_S4U_PROT_SUPPORT = 0xFFFFFFFFC000040ALL,
    STATUS_CROSSREALM_DELEGATION_FAILURE = 0xFFFFFFFFC000040BLL,
    STATUS_REVOCATION_OFFLINE_KDC = 0xFFFFFFFFC000040CLL,
    STATUS_ISSUING_CA_UNTRUSTED_KDC = 0xFFFFFFFFC000040DLL,
    STATUS_KDC_CERT_EXPIRED = 0xFFFFFFFFC000040ELL,
    STATUS_KDC_CERT_REVOKED = 0xFFFFFFFFC000040FLL,
    STATUS_PARAMETER_QUOTA_EXCEEDED = 0xFFFFFFFFC0000410LL,
    STATUS_HIBERNATION_FAILURE = 0xFFFFFFFFC0000411LL,
    STATUS_DELAY_LOAD_FAILED = 0xFFFFFFFFC0000412LL,
    STATUS_VDM_DISALLOWED = 0xFFFFFFFFC0000414LL,
    STATUS_HUNG_DISPLAY_DRIVER_THREAD = 0xFFFFFFFFC0000415LL,
    STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = 0xFFFFFFFFC0000416LL,
    STATUS_INVALID_CRUNTIME_PARAMETER = 0xC0000417LL,
    STATUS_NTLM_BLOCKED = 0xFFFFFFFFC0000418LL,
    STATUS_DS_SRC_SID_EXISTS_IN_FOREST = 0xFFFFFFFFC0000419LL,
    STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST = 0xFFFFFFFFC000041ALL,
    STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST = 0xFFFFFFFFC000041BLL,
    STATUS_INVALID_USER_PRINCIPAL_NAME = 0xFFFFFFFFC000041CLL,
    STATUS_FATAL_USER_CALLBACK_EXCEPTION = 0xFFFFFFFFC000041DLL,
    STATUS_ASSERTION_FAILURE = 0xC0000420LL,
    STATUS_VERIFIER_STOP = 0xFFFFFFFFC0000421LL,
    STATUS_CALLBACK_POP_STACK = 0xFFFFFFFFC0000423LL,
    STATUS_INCOMPATIBLE_DRIVER_BLOCKED = 0xFFFFFFFFC0000424LL,
    STATUS_HIVE_UNLOADED = 0xFFFFFFFFC0000425LL,
    STATUS_COMPRESSION_DISABLED = 0xFFFFFFFFC0000426LL,
    STATUS_FILE_SYSTEM_LIMITATION = 0xFFFFFFFFC0000427LL,
    STATUS_INVALID_IMAGE_HASH = 0xFFFFFFFFC0000428LL,
    STATUS_NOT_CAPABLE = 0xFFFFFFFFC0000429LL,
    STATUS_REQUEST_OUT_OF_SEQUENCE = 0xFFFFFFFFC000042ALL,
    STATUS_IMPLEMENTATION_LIMIT = 0xFFFFFFFFC000042BLL,
    STATUS_ELEVATION_REQUIRED = 0xFFFFFFFFC000042CLL,
    STATUS_NO_SECURITY_CONTEXT = 0xFFFFFFFFC000042DLL,
    STATUS_PKU2U_CERT_FAILURE = 0xFFFFFFFFC000042FLL,
    STATUS_BEYOND_VDL = 0xFFFFFFFFC0000432LL,
    STATUS_ENCOUNTERED_WRITE_IN_PROGRESS = 0xFFFFFFFFC0000433LL,
    STATUS_PTE_CHANGED = 0xFFFFFFFFC0000434LL,
    STATUS_PURGE_FAILED = 0xFFFFFFFFC0000435LL,
    STATUS_CRED_REQUIRES_CONFIRMATION = 0xFFFFFFFFC0000440LL,
    STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE = 0xFFFFFFFFC0000441LL,
    STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER = 0xFFFFFFFFC0000442LL,
    STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE = 0xFFFFFFFFC0000443LL,
    STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE = 0xFFFFFFFFC0000444LL,
    STATUS_CS_ENCRYPTION_FILE_NOT_CSE = 0xFFFFFFFFC0000445LL,
    STATUS_INVALID_LABEL = 0xFFFFFFFFC0000446LL,
    STATUS_DRIVER_PROCESS_TERMINATED = 0xFFFFFFFFC0000450LL,
    STATUS_AMBIGUOUS_SYSTEM_DEVICE = 0xFFFFFFFFC0000451LL,
    STATUS_SYSTEM_DEVICE_NOT_FOUND = 0xFFFFFFFFC0000452LL,
    STATUS_RESTART_BOOT_APPLICATION = 0xFFFFFFFFC0000453LL,
    STATUS_INSUFFICIENT_NVRAM_RESOURCES = 0xFFFFFFFFC0000454LL,
    STATUS_INVALID_SESSION = 0xFFFFFFFFC0000455LL,
    STATUS_THREAD_ALREADY_IN_SESSION = 0xFFFFFFFFC0000456LL,
    STATUS_THREAD_NOT_IN_SESSION = 0xFFFFFFFFC0000457LL,
    STATUS_INVALID_WEIGHT = 0xFFFFFFFFC0000458LL,
    STATUS_REQUEST_PAUSED = 0xFFFFFFFFC0000459LL,
    STATUS_NO_RANGES_PROCESSED = 0xFFFFFFFFC0000460LL,
    STATUS_DISK_RESOURCES_EXHAUSTED = 0xFFFFFFFFC0000461LL,
    STATUS_NEEDS_REMEDIATION = 0xFFFFFFFFC0000462LL,
    STATUS_DEVICE_FEATURE_NOT_SUPPORTED = 0xFFFFFFFFC0000463LL,
    STATUS_DEVICE_UNREACHABLE = 0xFFFFFFFFC0000464LL,
    STATUS_INVALID_TOKEN = 0xFFFFFFFFC0000465LL,
    STATUS_SERVER_UNAVAILABLE = 0xFFFFFFFFC0000466LL,
    STATUS_FILE_NOT_AVAILABLE = 0xFFFFFFFFC0000467LL,
    STATUS_DEVICE_INSUFFICIENT_RESOURCES = 0xFFFFFFFFC0000468LL,
    STATUS_PACKAGE_UPDATING = 0xFFFFFFFFC0000469LL,
    STATUS_NOT_READ_FROM_COPY = 0xFFFFFFFFC000046ALL,
    STATUS_FT_WRITE_FAILURE = 0xFFFFFFFFC000046BLL,
    STATUS_FT_DI_SCAN_REQUIRED = 0xFFFFFFFFC000046CLL,
    STATUS_OBJECT_NOT_EXTERNALLY_BACKED = 0xFFFFFFFFC000046DLL,
    STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN = 0xFFFFFFFFC000046ELL,
    STATUS_COMPRESSION_NOT_BENEFICIAL = 0xFFFFFFFFC000046FLL,
    STATUS_DATA_CHECKSUM_ERROR = 0xFFFFFFFFC0000470LL,
    STATUS_INTERMIXED_KERNEL_EA_OPERATION = 0xFFFFFFFFC0000471LL,
    STATUS_TRIM_READ_ZERO_NOT_SUPPORTED = 0xFFFFFFFFC0000472LL,
    STATUS_TOO_MANY_SEGMENT_DESCRIPTORS = 0xFFFFFFFFC0000473LL,
    STATUS_INVALID_OFFSET_ALIGNMENT = 0xFFFFFFFFC0000474LL,
    STATUS_INVALID_FIELD_IN_PARAMETER_LIST = 0xFFFFFFFFC0000475LL,
    STATUS_OPERATION_IN_PROGRESS = 0xFFFFFFFFC0000476LL,
    STATUS_INVALID_INITIATOR_TARGET_PATH = 0xFFFFFFFFC0000477LL,
    STATUS_SCRUB_DATA_DISABLED = 0xFFFFFFFFC0000478LL,
    STATUS_NOT_REDUNDANT_STORAGE = 0xFFFFFFFFC0000479LL,
    STATUS_RESIDENT_FILE_NOT_SUPPORTED = 0xFFFFFFFFC000047ALL,
    STATUS_COMPRESSED_FILE_NOT_SUPPORTED = 0xFFFFFFFFC000047BLL,
    STATUS_DIRECTORY_NOT_SUPPORTED = 0xFFFFFFFFC000047CLL,
    STATUS_IO_OPERATION_TIMEOUT = 0xFFFFFFFFC000047DLL,
    STATUS_SYSTEM_NEEDS_REMEDIATION = 0xFFFFFFFFC000047ELL,
    STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN = 0xFFFFFFFFC000047FLL,
    STATUS_SHARE_UNAVAILABLE = 0xFFFFFFFFC0000480LL,
    STATUS_APISET_NOT_HOSTED = 0xFFFFFFFFC0000481LL,
    STATUS_APISET_NOT_PRESENT = 0xFFFFFFFFC0000482LL,
    STATUS_DEVICE_HARDWARE_ERROR = 0xFFFFFFFFC0000483LL,
    STATUS_FIRMWARE_SLOT_INVALID = 0xFFFFFFFFC0000484LL,
    STATUS_FIRMWARE_IMAGE_INVALID = 0xFFFFFFFFC0000485LL,
    STATUS_STORAGE_TOPOLOGY_ID_MISMATCH = 0xFFFFFFFFC0000486LL,
    STATUS_WIM_NOT_BOOTABLE = 0xFFFFFFFFC0000487LL,
    STATUS_BLOCKED_BY_PARENTAL_CONTROLS = 0xFFFFFFFFC0000488LL,
    STATUS_NEEDS_REGISTRATION = 0xFFFFFFFFC0000489LL,
    STATUS_QUOTA_ACTIVITY = 0xFFFFFFFFC000048ALL,
    STATUS_CALLBACK_INVOKE_INLINE = 0xFFFFFFFFC000048BLL,
    STATUS_BLOCK_TOO_MANY_REFERENCES = 0xFFFFFFFFC000048CLL,
    STATUS_MARKED_TO_DISALLOW_WRITES = 0xFFFFFFFFC000048DLL,
    STATUS_NETWORK_ACCESS_DENIED_EDP = 0xFFFFFFFFC000048ELL,
    STATUS_ENCLAVE_FAILURE = 0xFFFFFFFFC000048FLL,
    STATUS_PNP_NO_COMPAT_DRIVERS = 0xFFFFFFFFC0000490LL,
    STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND = 0xFFFFFFFFC0000491LL,
    STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND = 0xFFFFFFFFC0000492LL,
    STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE = 0xFFFFFFFFC0000493LL,
    STATUS_PNP_FUNCTION_DRIVER_REQUIRED = 0xFFFFFFFFC0000494LL,
    STATUS_PNP_DEVICE_CONFIGURATION_PENDING = 0xFFFFFFFFC0000495LL,
    STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL = 0xFFFFFFFFC0000496LL,
    STATUS_PACKAGE_NOT_AVAILABLE = 0xFFFFFFFFC0000497LL,
    STATUS_DEVICE_IN_MAINTENANCE = 0xFFFFFFFFC0000499LL,
    STATUS_NOT_SUPPORTED_ON_DAX = 0xFFFFFFFFC000049ALL,
    STATUS_FREE_SPACE_TOO_FRAGMENTED = 0xFFFFFFFFC000049BLL,
    STATUS_DAX_MAPPING_EXISTS = 0xFFFFFFFFC000049CLL,
    STATUS_CHILD_PROCESS_BLOCKED = 0xFFFFFFFFC000049DLL,
    STATUS_STORAGE_LOST_DATA_PERSISTENCE = 0xFFFFFFFFC000049ELL,
    STATUS_VRF_CFG_ENABLED = 0xFFFFFFFFC000049FLL,
    STATUS_PARTITION_TERMINATING = 0xFFFFFFFFC00004A0LL,
    STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED = 0xFFFFFFFFC00004A1LL,
    STATUS_ENCLAVE_VIOLATION = 0xFFFFFFFFC00004A2LL,
    STATUS_FILE_PROTECTED_UNDER_DPL = 0xFFFFFFFFC00004A3LL,
    STATUS_VOLUME_NOT_CLUSTER_ALIGNED = 0xFFFFFFFFC00004A4LL,
    STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND = 0xFFFFFFFFC00004A5LL,
    STATUS_APPX_FILE_NOT_ENCRYPTED = 0xFFFFFFFFC00004A6LL,
    STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED = 0xFFFFFFFFC00004A7LL,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET = 0xFFFFFFFFC00004A8LL,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE = 0xFFFFFFFFC00004A9LL,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER = 0xFFFFFFFFC00004AALL,
    STATUS_FT_READ_FAILURE = 0xFFFFFFFFC00004ABLL,
    STATUS_PATCH_CONFLICT = 0xFFFFFFFFC00004ACLL,
    STATUS_STORAGE_RESERVE_ID_INVALID = 0xFFFFFFFFC00004ADLL,
    STATUS_STORAGE_RESERVE_DOES_NOT_EXIST = 0xFFFFFFFFC00004AELL,
    STATUS_STORAGE_RESERVE_ALREADY_EXISTS = 0xFFFFFFFFC00004AFLL,
    STATUS_STORAGE_RESERVE_NOT_EMPTY = 0xFFFFFFFFC00004B0LL,
    STATUS_NOT_A_DAX_VOLUME = 0xFFFFFFFFC00004B1LL,
    STATUS_NOT_DAX_MAPPABLE = 0xFFFFFFFFC00004B2LL,
    STATUS_CASE_DIFFERING_NAMES_IN_DIR = 0xFFFFFFFFC00004B3LL,
    STATUS_INVALID_TASK_NAME = 0xFFFFFFFFC0000500LL,
    STATUS_INVALID_TASK_INDEX = 0xFFFFFFFFC0000501LL,
    STATUS_THREAD_ALREADY_IN_TASK = 0xFFFFFFFFC0000502LL,
    STATUS_CALLBACK_BYPASS = 0xFFFFFFFFC0000503LL,
    STATUS_UNDEFINED_SCOPE = 0xFFFFFFFFC0000504LL,
    STATUS_INVALID_CAP = 0xFFFFFFFFC0000505LL,
    STATUS_NOT_GUI_PROCESS = 0xFFFFFFFFC0000506LL,
    STATUS_DEVICE_HUNG = 0xFFFFFFFFC0000507LL,
    STATUS_CONTAINER_ASSIGNED = 0xFFFFFFFFC0000508LL,
    STATUS_JOB_NO_CONTAINER = 0xFFFFFFFFC0000509LL,
    STATUS_DEVICE_UNRESPONSIVE = 0xFFFFFFFFC000050ALL,
    STATUS_REPARSE_POINT_ENCOUNTERED = 0xFFFFFFFFC000050BLL,
    STATUS_ATTRIBUTE_NOT_PRESENT = 0xFFFFFFFFC000050CLL,
    STATUS_NOT_A_TIERED_VOLUME = 0xFFFFFFFFC000050DLL,
    STATUS_ALREADY_HAS_STREAM_ID = 0xFFFFFFFFC000050ELL,
    STATUS_JOB_NOT_EMPTY = 0xFFFFFFFFC000050FLL,
    STATUS_ALREADY_INITIALIZED = 0xFFFFFFFFC0000510LL,
    STATUS_ENCLAVE_NOT_TERMINATED = 0xFFFFFFFFC0000511LL,
    STATUS_ENCLAVE_IS_TERMINATING = 0xFFFFFFFFC0000512LL,
    STATUS_SMB1_NOT_AVAILABLE = 0xFFFFFFFFC0000513LL,
    STATUS_SMR_GARBAGE_COLLECTION_REQUIRED = 0xFFFFFFFFC0000514LL,
    STATUS_FAIL_FAST_EXCEPTION = 0xFFFFFFFFC0000602LL,
    STATUS_IMAGE_CERT_REVOKED = 0xFFFFFFFFC0000603LL,
    STATUS_DYNAMIC_CODE_BLOCKED = 0xFFFFFFFFC0000604LL,
    STATUS_IMAGE_CERT_EXPIRED = 0xFFFFFFFFC0000605LL,
    STATUS_STRICT_CFG_VIOLATION = 0xFFFFFFFFC0000606LL,
    STATUS_SET_CONTEXT_DENIED = 0xFFFFFFFFC000060ALL,
    STATUS_CROSS_PARTITION_VIOLATION = 0xFFFFFFFFC000060BLL,
    STATUS_PORT_CLOSED = 0xFFFFFFFFC0000700LL,
    STATUS_MESSAGE_LOST = 0xFFFFFFFFC0000701LL,
    STATUS_INVALID_MESSAGE = 0xFFFFFFFFC0000702LL,
    STATUS_REQUEST_CANCELED = 0xFFFFFFFFC0000703LL,
    STATUS_RECURSIVE_DISPATCH = 0xFFFFFFFFC0000704LL,
    STATUS_LPC_RECEIVE_BUFFER_EXPECTED = 0xFFFFFFFFC0000705LL,
    STATUS_LPC_INVALID_CONNECTION_USAGE = 0xFFFFFFFFC0000706LL,
    STATUS_LPC_REQUESTS_NOT_ALLOWED = 0xFFFFFFFFC0000707LL,
    STATUS_RESOURCE_IN_USE = 0xFFFFFFFFC0000708LL,
    STATUS_HARDWARE_MEMORY_ERROR = 0xFFFFFFFFC0000709LL,
    STATUS_THREADPOOL_HANDLE_EXCEPTION = 0xFFFFFFFFC000070ALL,
    STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED = 0xFFFFFFFFC000070BLL,
    STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED = 0xFFFFFFFFC000070CLL,
    STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED = 0xFFFFFFFFC000070DLL,
    STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED = 0xFFFFFFFFC000070ELL,
    STATUS_THREADPOOL_RELEASED_DURING_OPERATION = 0xFFFFFFFFC000070FLL,
    STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING = 0xFFFFFFFFC0000710LL,
    STATUS_APC_RETURNED_WHILE_IMPERSONATING = 0xFFFFFFFFC0000711LL,
    STATUS_PROCESS_IS_PROTECTED = 0xFFFFFFFFC0000712LL,
    STATUS_MCA_EXCEPTION = 0xFFFFFFFFC0000713LL,
    STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE = 0xFFFFFFFFC0000714LL,
    STATUS_SYMLINK_CLASS_DISABLED = 0xFFFFFFFFC0000715LL,
    STATUS_INVALID_IDN_NORMALIZATION = 0xFFFFFFFFC0000716LL,
    STATUS_NO_UNICODE_TRANSLATION = 0xFFFFFFFFC0000717LL,
    STATUS_ALREADY_REGISTERED = 0xFFFFFFFFC0000718LL,
    STATUS_CONTEXT_MISMATCH = 0xFFFFFFFFC0000719LL,
    STATUS_PORT_ALREADY_HAS_COMPLETION_LIST = 0xFFFFFFFFC000071ALL,
    STATUS_CALLBACK_RETURNED_THREAD_PRIORITY = 0xFFFFFFFFC000071BLL,
    STATUS_INVALID_THREAD = 0xFFFFFFFFC000071CLL,
    STATUS_CALLBACK_RETURNED_TRANSACTION = 0xFFFFFFFFC000071DLL,
    STATUS_CALLBACK_RETURNED_LDR_LOCK = 0xFFFFFFFFC000071ELL,
    STATUS_CALLBACK_RETURNED_LANG = 0xFFFFFFFFC000071FLL,
    STATUS_CALLBACK_RETURNED_PRI_BACK = 0xFFFFFFFFC0000720LL,
    STATUS_CALLBACK_RETURNED_THREAD_AFFINITY = 0xFFFFFFFFC0000721LL,
    STATUS_LPC_HANDLE_COUNT_EXCEEDED = 0xFFFFFFFFC0000722LL,
    STATUS_EXECUTABLE_MEMORY_WRITE = 0xFFFFFFFFC0000723LL,
    STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE = 0xFFFFFFFFC0000724LL,
    STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE = 0xFFFFFFFFC0000725LL,
    STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE = 0xFFFFFFFFC0000726LL,
    STATUS_DISK_REPAIR_DISABLED = 0xFFFFFFFFC0000800LL,
    STATUS_DS_DOMAIN_RENAME_IN_PROGRESS = 0xFFFFFFFFC0000801LL,
    STATUS_DISK_QUOTA_EXCEEDED = 0xFFFFFFFFC0000802LL,
    STATUS_DATA_LOST_REPAIR = 0xFFFFFFFF80000803LL,
    STATUS_CONTENT_BLOCKED = 0xFFFFFFFFC0000804LL,
    STATUS_BAD_CLUSTERS = 0xFFFFFFFFC0000805LL,
    STATUS_VOLUME_DIRTY = 0xFFFFFFFFC0000806LL,
    STATUS_DISK_REPAIR_REDIRECTED = 0x40000807LL,
    STATUS_DISK_REPAIR_UNSUCCESSFUL = 0xFFFFFFFFC0000808LL,
    STATUS_CORRUPT_LOG_OVERFULL = 0xFFFFFFFFC0000809LL,
    STATUS_CORRUPT_LOG_CORRUPTED = 0xFFFFFFFFC000080ALL,
    STATUS_CORRUPT_LOG_UNAVAILABLE = 0xFFFFFFFFC000080BLL,
    STATUS_CORRUPT_LOG_DELETED_FULL = 0xFFFFFFFFC000080CLL,
    STATUS_CORRUPT_LOG_CLEARED = 0xFFFFFFFFC000080DLL,
    STATUS_ORPHAN_NAME_EXHAUSTED = 0xFFFFFFFFC000080ELL,
    STATUS_PROACTIVE_SCAN_IN_PROGRESS = 0xFFFFFFFFC000080FLL,
    STATUS_ENCRYPTED_IO_NOT_POSSIBLE = 0xFFFFFFFFC0000810LL,
    STATUS_CORRUPT_LOG_UPLEVEL_RECORDS = 0xFFFFFFFFC0000811LL,
    STATUS_FILE_CHECKED_OUT = 0xFFFFFFFFC0000901LL,
    STATUS_CHECKOUT_REQUIRED = 0xFFFFFFFFC0000902LL,
    STATUS_BAD_FILE_TYPE = 0xFFFFFFFFC0000903LL,
    STATUS_FILE_TOO_LARGE = 0xFFFFFFFFC0000904LL,
    STATUS_FORMS_AUTH_REQUIRED = 0xFFFFFFFFC0000905LL,
    STATUS_VIRUS_INFECTED = 0xFFFFFFFFC0000906LL,
    STATUS_VIRUS_DELETED = 0xFFFFFFFFC0000907LL,
    STATUS_BAD_MCFG_TABLE = 0xFFFFFFFFC0000908LL,
    STATUS_CANNOT_BREAK_OPLOCK = 0xFFFFFFFFC0000909LL,
    STATUS_BAD_KEY = 0xFFFFFFFFC000090ALL,
    STATUS_BAD_DATA = 0xFFFFFFFFC000090BLL,
    STATUS_NO_KEY = 0xFFFFFFFFC000090CLL,
    STATUS_FILE_HANDLE_REVOKED = 0xFFFFFFFFC0000910LL,
    STATUS_WOW_ASSERTION = 0xFFFFFFFFC0009898LL,
    STATUS_INVALID_SIGNATURE = 0xFFFFFFFFC000A000LL,
    STATUS_HMAC_NOT_SUPPORTED = 0xFFFFFFFFC000A001LL,
    STATUS_AUTH_TAG_MISMATCH = 0xFFFFFFFFC000A002LL,
    STATUS_INVALID_STATE_TRANSITION = 0xFFFFFFFFC000A003LL,
    STATUS_INVALID_KERNEL_INFO_VERSION = 0xFFFFFFFFC000A004LL,
    STATUS_INVALID_PEP_INFO_VERSION = 0xFFFFFFFFC000A005LL,
    STATUS_HANDLE_REVOKED = 0xFFFFFFFFC000A006LL,
    STATUS_EOF_ON_GHOSTED_RANGE = 0xFFFFFFFFC000A007LL,
    STATUS_IPSEC_QUEUE_OVERFLOW = 0xFFFFFFFFC000A010LL,
    STATUS_ND_QUEUE_OVERFLOW = 0xFFFFFFFFC000A011LL,
    STATUS_HOPLIMIT_EXCEEDED = 0xFFFFFFFFC000A012LL,
    STATUS_PROTOCOL_NOT_SUPPORTED = 0xFFFFFFFFC000A013LL,
    STATUS_FASTPATH_REJECTED = 0xFFFFFFFFC000A014LL,
    STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED = 0xFFFFFFFFC000A080LL,
    STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR = 0xFFFFFFFFC000A081LL,
    STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR = 0xFFFFFFFFC000A082LL,
    STATUS_XML_PARSE_ERROR = 0xFFFFFFFFC000A083LL,
    STATUS_XMLDSIG_ERROR = 0xFFFFFFFFC000A084LL,
    STATUS_WRONG_COMPARTMENT = 0xFFFFFFFFC000A085LL,
    STATUS_AUTHIP_FAILURE = 0xFFFFFFFFC000A086LL,
    STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS = 0xFFFFFFFFC000A087LL,
    STATUS_DS_OID_NOT_FOUND = 0xFFFFFFFFC000A088LL,
    STATUS_INCORRECT_ACCOUNT_TYPE = 0xFFFFFFFFC000A089LL,
    STATUS_HASH_NOT_SUPPORTED = 0xFFFFFFFFC000A100LL,
    STATUS_HASH_NOT_PRESENT = 0xFFFFFFFFC000A101LL,
    STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED = 0xFFFFFFFFC000A121LL,
    STATUS_GPIO_CLIENT_INFORMATION_INVALID = 0xFFFFFFFFC000A122LL,
    STATUS_GPIO_VERSION_NOT_SUPPORTED = 0xFFFFFFFFC000A123LL,
    STATUS_GPIO_INVALID_REGISTRATION_PACKET = 0xFFFFFFFFC000A124LL,
    STATUS_GPIO_OPERATION_DENIED = 0xFFFFFFFFC000A125LL,
    STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE = 0xFFFFFFFFC000A126LL,
    STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED = 0xFFFFFFFF8000A127LL,
    STATUS_CANNOT_SWITCH_RUNLEVEL = 0xFFFFFFFFC000A141LL,
    STATUS_INVALID_RUNLEVEL_SETTING = 0xFFFFFFFFC000A142LL,
    STATUS_RUNLEVEL_SWITCH_TIMEOUT = 0xFFFFFFFFC000A143LL,
    STATUS_SERVICES_FAILED_AUTOSTART = 0x4000A144LL,
    STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT = 0xFFFFFFFFC000A145LL,
    STATUS_RUNLEVEL_SWITCH_IN_PROGRESS = 0xFFFFFFFFC000A146LL,
    STATUS_NOT_APPCONTAINER = 0xFFFFFFFFC000A200LL,
    STATUS_NOT_SUPPORTED_IN_APPCONTAINER = 0xFFFFFFFFC000A201LL,
    STATUS_INVALID_PACKAGE_SID_LENGTH = 0xFFFFFFFFC000A202LL,
    STATUS_LPAC_ACCESS_DENIED = 0xFFFFFFFFC000A203LL,
    STATUS_ADMINLESS_ACCESS_DENIED = 0xFFFFFFFFC000A204LL,
    STATUS_APP_DATA_NOT_FOUND = 0xFFFFFFFFC000A281LL,
    STATUS_APP_DATA_EXPIRED = 0xFFFFFFFFC000A282LL,
    STATUS_APP_DATA_CORRUPT = 0xFFFFFFFFC000A283LL,
    STATUS_APP_DATA_LIMIT_EXCEEDED = 0xFFFFFFFFC000A284LL,
    STATUS_APP_DATA_REBOOT_REQUIRED = 0xFFFFFFFFC000A285LL,
    STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED = 0xFFFFFFFFC000A2A1LL,
    STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED = 0xFFFFFFFFC000A2A2LL,
    STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED = 0xFFFFFFFFC000A2A3LL,
    STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED = 0xFFFFFFFFC000A2A4LL,
    STATUS_WOF_WIM_HEADER_CORRUPT = 0xFFFFFFFFC000A2A5LL,
    STATUS_WOF_WIM_RESOURCE_TABLE_CORRUPT = 0xFFFFFFFFC000A2A6LL,
    STATUS_WOF_FILE_RESOURCE_TABLE_CORRUPT = 0xFFFFFFFFC000A2A7LL,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE = 0xFFFFFFFFC000CE01LL,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT = 0xFFFFFFFFC000CE02LL,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_BUSY = 0xFFFFFFFFC000CE03LL,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN = 0xFFFFFFFFC000CE04LL,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION = 0xFFFFFFFFC000CE05LL,
    STATUS_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT = 0xFFFFFFFFC000CF00LL,
    STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING = 0xFFFFFFFFC000CF01LL,
    STATUS_CLOUD_FILE_METADATA_CORRUPT = 0xFFFFFFFFC000CF02LL,
    STATUS_CLOUD_FILE_METADATA_TOO_LARGE = 0xFFFFFFFFC000CF03LL,
    STATUS_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE = 0xFFFFFFFF8000CF04LL,
    STATUS_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS = 0xFFFFFFFF8000CF05LL,
    STATUS_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED = 0xFFFFFFFFC000CF06LL,
    STATUS_NOT_A_CLOUD_FILE = 0xFFFFFFFFC000CF07LL,
    STATUS_CLOUD_FILE_NOT_IN_SYNC = 0xFFFFFFFFC000CF08LL,
    STATUS_CLOUD_FILE_ALREADY_CONNECTED = 0xFFFFFFFFC000CF09LL,
    STATUS_CLOUD_FILE_NOT_SUPPORTED = 0xFFFFFFFFC000CF0ALL,
    STATUS_CLOUD_FILE_INVALID_REQUEST = 0xFFFFFFFFC000CF0BLL,
    STATUS_CLOUD_FILE_READ_ONLY_VOLUME = 0xFFFFFFFFC000CF0CLL,
    STATUS_CLOUD_FILE_CONNECTED_PROVIDER_ONLY = 0xFFFFFFFFC000CF0DLL,
    STATUS_CLOUD_FILE_VALIDATION_FAILED = 0xFFFFFFFFC000CF0ELL,
    STATUS_CLOUD_FILE_AUTHENTICATION_FAILED = 0xFFFFFFFFC000CF0FLL,
    STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES = 0xFFFFFFFFC000CF10LL,
    STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE = 0xFFFFFFFFC000CF11LL,
    STATUS_CLOUD_FILE_UNSUCCESSFUL = 0xFFFFFFFFC000CF12LL,
    STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT = 0xFFFFFFFFC000CF13LL,
    STATUS_CLOUD_FILE_IN_USE = 0xFFFFFFFFC000CF14LL,
    STATUS_CLOUD_FILE_PINNED = 0xFFFFFFFFC000CF15LL,
    STATUS_CLOUD_FILE_REQUEST_ABORTED = 0xFFFFFFFFC000CF16LL,
    STATUS_CLOUD_FILE_PROPERTY_CORRUPT = 0xFFFFFFFFC000CF17LL,
    STATUS_CLOUD_FILE_ACCESS_DENIED = 0xFFFFFFFFC000CF18LL,
    STATUS_CLOUD_FILE_INCOMPATIBLE_HARDLINKS = 0xFFFFFFFFC000CF19LL,
    STATUS_CLOUD_FILE_PROPERTY_LOCK_CONFLICT = 0xFFFFFFFFC000CF1ALL,
    STATUS_CLOUD_FILE_REQUEST_CANCELED = 0xFFFFFFFFC000CF1BLL,
    STATUS_CLOUD_FILE_PROVIDER_TERMINATED = 0xFFFFFFFFC000CF1DLL,
    STATUS_NOT_A_CLOUD_SYNC_ROOT = 0xFFFFFFFFC000CF1ELL,
    DBG_NO_STATE_CHANGE = 0xFFFFFFFFC0010001LL,
    DBG_APP_NOT_IDLE = 0xFFFFFFFFC0010002LL,
    RPC_NT_INVALID_STRING_BINDING = 0xFFFFFFFFC0020001LL,
    RPC_NT_WRONG_KIND_OF_BINDING = 0xFFFFFFFFC0020002LL,
    RPC_NT_INVALID_BINDING = 0xFFFFFFFFC0020003LL,
    RPC_NT_PROTSEQ_NOT_SUPPORTED = 0xFFFFFFFFC0020004LL,
    RPC_NT_INVALID_RPC_PROTSEQ = 0xFFFFFFFFC0020005LL,
    RPC_NT_INVALID_STRING_UUID = 0xFFFFFFFFC0020006LL,
    RPC_NT_INVALID_ENDPOINT_FORMAT = 0xFFFFFFFFC0020007LL,
    RPC_NT_INVALID_NET_ADDR = 0xFFFFFFFFC0020008LL,
    RPC_NT_NO_ENDPOINT_FOUND = 0xFFFFFFFFC0020009LL,
    RPC_NT_INVALID_TIMEOUT = 0xFFFFFFFFC002000ALL,
    RPC_NT_OBJECT_NOT_FOUND = 0xFFFFFFFFC002000BLL,
    RPC_NT_ALREADY_REGISTERED = 0xFFFFFFFFC002000CLL,
    RPC_NT_TYPE_ALREADY_REGISTERED = 0xFFFFFFFFC002000DLL,
    RPC_NT_ALREADY_LISTENING = 0xFFFFFFFFC002000ELL,
    RPC_NT_NO_PROTSEQS_REGISTERED = 0xFFFFFFFFC002000FLL,
    RPC_NT_NOT_LISTENING = 0xFFFFFFFFC0020010LL,
    RPC_NT_UNKNOWN_MGR_TYPE = 0xFFFFFFFFC0020011LL,
    RPC_NT_UNKNOWN_IF = 0xFFFFFFFFC0020012LL,
    RPC_NT_NO_BINDINGS = 0xFFFFFFFFC0020013LL,
    RPC_NT_NO_PROTSEQS = 0xFFFFFFFFC0020014LL,
    RPC_NT_CANT_CREATE_ENDPOINT = 0xFFFFFFFFC0020015LL,
    RPC_NT_OUT_OF_RESOURCES = 0xFFFFFFFFC0020016LL,
    RPC_NT_SERVER_UNAVAILABLE = 0xFFFFFFFFC0020017LL,
    RPC_NT_SERVER_TOO_BUSY = 0xFFFFFFFFC0020018LL,
    RPC_NT_INVALID_NETWORK_OPTIONS = 0xFFFFFFFFC0020019LL,
    RPC_NT_NO_CALL_ACTIVE = 0xFFFFFFFFC002001ALL,
    RPC_NT_CALL_FAILED = 0xFFFFFFFFC002001BLL,
    RPC_NT_CALL_FAILED_DNE = 0xFFFFFFFFC002001CLL,
    RPC_NT_PROTOCOL_ERROR = 0xFFFFFFFFC002001DLL,
    RPC_NT_UNSUPPORTED_TRANS_SYN = 0xFFFFFFFFC002001FLL,
    RPC_NT_UNSUPPORTED_TYPE = 0xFFFFFFFFC0020021LL,
    RPC_NT_INVALID_TAG = 0xFFFFFFFFC0020022LL,
    RPC_NT_INVALID_BOUND = 0xFFFFFFFFC0020023LL,
    RPC_NT_NO_ENTRY_NAME = 0xFFFFFFFFC0020024LL,
    RPC_NT_INVALID_NAME_SYNTAX = 0xFFFFFFFFC0020025LL,
    RPC_NT_UNSUPPORTED_NAME_SYNTAX = 0xFFFFFFFFC0020026LL,
    RPC_NT_UUID_NO_ADDRESS = 0xFFFFFFFFC0020028LL,
    RPC_NT_DUPLICATE_ENDPOINT = 0xFFFFFFFFC0020029LL,
    RPC_NT_UNKNOWN_AUTHN_TYPE = 0xFFFFFFFFC002002ALL,
    RPC_NT_MAX_CALLS_TOO_SMALL = 0xFFFFFFFFC002002BLL,
    RPC_NT_STRING_TOO_LONG = 0xFFFFFFFFC002002CLL,
    RPC_NT_PROTSEQ_NOT_FOUND = 0xFFFFFFFFC002002DLL,
    RPC_NT_PROCNUM_OUT_OF_RANGE = 0xFFFFFFFFC002002ELL,
    RPC_NT_BINDING_HAS_NO_AUTH = 0xFFFFFFFFC002002FLL,
    RPC_NT_UNKNOWN_AUTHN_SERVICE = 0xFFFFFFFFC0020030LL,
    RPC_NT_UNKNOWN_AUTHN_LEVEL = 0xFFFFFFFFC0020031LL,
    RPC_NT_INVALID_AUTH_IDENTITY = 0xFFFFFFFFC0020032LL,
    RPC_NT_UNKNOWN_AUTHZ_SERVICE = 0xFFFFFFFFC0020033LL,
    EPT_NT_INVALID_ENTRY = 0xFFFFFFFFC0020034LL,
    EPT_NT_CANT_PERFORM_OP = 0xFFFFFFFFC0020035LL,
    EPT_NT_NOT_REGISTERED = 0xFFFFFFFFC0020036LL,
    RPC_NT_NOTHING_TO_EXPORT = 0xFFFFFFFFC0020037LL,
    RPC_NT_INCOMPLETE_NAME = 0xFFFFFFFFC0020038LL,
    RPC_NT_INVALID_VERS_OPTION = 0xFFFFFFFFC0020039LL,
    RPC_NT_NO_MORE_MEMBERS = 0xFFFFFFFFC002003ALL,
    RPC_NT_NOT_ALL_OBJS_UNEXPORTED = 0xFFFFFFFFC002003BLL,
    RPC_NT_INTERFACE_NOT_FOUND = 0xFFFFFFFFC002003CLL,
    RPC_NT_ENTRY_ALREADY_EXISTS = 0xFFFFFFFFC002003DLL,
    RPC_NT_ENTRY_NOT_FOUND = 0xFFFFFFFFC002003ELL,
    RPC_NT_NAME_SERVICE_UNAVAILABLE = 0xFFFFFFFFC002003FLL,
    RPC_NT_INVALID_NAF_ID = 0xFFFFFFFFC0020040LL,
    RPC_NT_CANNOT_SUPPORT = 0xFFFFFFFFC0020041LL,
    RPC_NT_NO_CONTEXT_AVAILABLE = 0xFFFFFFFFC0020042LL,
    RPC_NT_INTERNAL_ERROR = 0xFFFFFFFFC0020043LL,
    RPC_NT_ZERO_DIVIDE = 0xFFFFFFFFC0020044LL,
    RPC_NT_ADDRESS_ERROR = 0xFFFFFFFFC0020045LL,
    RPC_NT_FP_DIV_ZERO = 0xFFFFFFFFC0020046LL,
    RPC_NT_FP_UNDERFLOW = 0xFFFFFFFFC0020047LL,
    RPC_NT_FP_OVERFLOW = 0xFFFFFFFFC0020048LL,
    RPC_NT_NO_MORE_ENTRIES = 0xFFFFFFFFC0030001LL,
    RPC_NT_SS_CHAR_TRANS_OPEN_FAIL = 0xFFFFFFFFC0030002LL,
    RPC_NT_SS_CHAR_TRANS_SHORT_FILE = 0xFFFFFFFFC0030003LL,
    RPC_NT_SS_IN_NULL_CONTEXT = 0xFFFFFFFFC0030004LL,
    RPC_NT_SS_CONTEXT_MISMATCH = 0xFFFFFFFFC0030005LL,
    RPC_NT_SS_CONTEXT_DAMAGED = 0xFFFFFFFFC0030006LL,
    RPC_NT_SS_HANDLES_MISMATCH = 0xFFFFFFFFC0030007LL,
    RPC_NT_SS_CANNOT_GET_CALL_HANDLE = 0xFFFFFFFFC0030008LL,
    RPC_NT_NULL_REF_POINTER = 0xFFFFFFFFC0030009LL,
    RPC_NT_ENUM_VALUE_OUT_OF_RANGE = 0xFFFFFFFFC003000ALL,
    RPC_NT_BYTE_COUNT_TOO_SMALL = 0xFFFFFFFFC003000BLL,
    RPC_NT_BAD_STUB_DATA = 0xFFFFFFFFC003000CLL,
    RPC_NT_CALL_IN_PROGRESS = 0xFFFFFFFFC0020049LL,
    RPC_NT_NO_MORE_BINDINGS = 0xFFFFFFFFC002004ALL,
    RPC_NT_GROUP_MEMBER_NOT_FOUND = 0xFFFFFFFFC002004BLL,
    EPT_NT_CANT_CREATE = 0xFFFFFFFFC002004CLL,
    RPC_NT_INVALID_OBJECT = 0xFFFFFFFFC002004DLL,
    RPC_NT_NO_INTERFACES = 0xFFFFFFFFC002004FLL,
    RPC_NT_CALL_CANCELLED = 0xFFFFFFFFC0020050LL,
    RPC_NT_BINDING_INCOMPLETE = 0xFFFFFFFFC0020051LL,
    RPC_NT_COMM_FAILURE = 0xFFFFFFFFC0020052LL,
    RPC_NT_UNSUPPORTED_AUTHN_LEVEL = 0xFFFFFFFFC0020053LL,
    RPC_NT_NO_PRINC_NAME = 0xFFFFFFFFC0020054LL,
    RPC_NT_NOT_RPC_ERROR = 0xFFFFFFFFC0020055LL,
    RPC_NT_UUID_LOCAL_ONLY = 0x40020056LL,
    RPC_NT_SEC_PKG_ERROR = 0xFFFFFFFFC0020057LL,
    RPC_NT_NOT_CANCELLED = 0xFFFFFFFFC0020058LL,
    RPC_NT_INVALID_ES_ACTION = 0xFFFFFFFFC0030059LL,
    RPC_NT_WRONG_ES_VERSION = 0xFFFFFFFFC003005ALL,
    RPC_NT_WRONG_STUB_VERSION = 0xFFFFFFFFC003005BLL,
    RPC_NT_INVALID_PIPE_OBJECT = 0xFFFFFFFFC003005CLL,
    RPC_NT_INVALID_PIPE_OPERATION = 0xFFFFFFFFC003005DLL,
    RPC_NT_WRONG_PIPE_VERSION = 0xFFFFFFFFC003005ELL,
    RPC_NT_PIPE_CLOSED = 0xFFFFFFFFC003005FLL,
    RPC_NT_PIPE_DISCIPLINE_ERROR = 0xFFFFFFFFC0030060LL,
    RPC_NT_PIPE_EMPTY = 0xFFFFFFFFC0030061LL,
    RPC_NT_INVALID_ASYNC_HANDLE = 0xFFFFFFFFC0020062LL,
    RPC_NT_INVALID_ASYNC_CALL = 0xFFFFFFFFC0020063LL,
    RPC_NT_PROXY_ACCESS_DENIED = 0xFFFFFFFFC0020064LL,
    RPC_NT_COOKIE_AUTH_FAILED = 0xFFFFFFFFC0020065LL,
    RPC_NT_SEND_INCOMPLETE = 0x400200AFLL,
    STATUS_ACPI_INVALID_OPCODE = 0xFFFFFFFFC0140001LL,
    STATUS_ACPI_STACK_OVERFLOW = 0xFFFFFFFFC0140002LL,
    STATUS_ACPI_ASSERT_FAILED = 0xFFFFFFFFC0140003LL,
    STATUS_ACPI_INVALID_INDEX = 0xFFFFFFFFC0140004LL,
    STATUS_ACPI_INVALID_ARGUMENT = 0xFFFFFFFFC0140005LL,
    STATUS_ACPI_FATAL = 0xFFFFFFFFC0140006LL,
    STATUS_ACPI_INVALID_SUPERNAME = 0xFFFFFFFFC0140007LL,
    STATUS_ACPI_INVALID_ARGTYPE = 0xFFFFFFFFC0140008LL,
    STATUS_ACPI_INVALID_OBJTYPE = 0xFFFFFFFFC0140009LL,
    STATUS_ACPI_INVALID_TARGETTYPE = 0xFFFFFFFFC014000ALL,
    STATUS_ACPI_INCORRECT_ARGUMENT_COUNT = 0xFFFFFFFFC014000BLL,
    STATUS_ACPI_ADDRESS_NOT_MAPPED = 0xFFFFFFFFC014000CLL,
    STATUS_ACPI_INVALID_EVENTTYPE = 0xFFFFFFFFC014000DLL,
    STATUS_ACPI_HANDLER_COLLISION = 0xFFFFFFFFC014000ELL,
    STATUS_ACPI_INVALID_DATA = 0xFFFFFFFFC014000FLL,
    STATUS_ACPI_INVALID_REGION = 0xFFFFFFFFC0140010LL,
    STATUS_ACPI_INVALID_ACCESS_SIZE = 0xFFFFFFFFC0140011LL,
    STATUS_ACPI_ACQUIRE_GLOBAL_LOCK = 0xFFFFFFFFC0140012LL,
    STATUS_ACPI_ALREADY_INITIALIZED = 0xFFFFFFFFC0140013LL,
    STATUS_ACPI_NOT_INITIALIZED = 0xFFFFFFFFC0140014LL,
    STATUS_ACPI_INVALID_MUTEX_LEVEL = 0xFFFFFFFFC0140015LL,
    STATUS_ACPI_MUTEX_NOT_OWNED = 0xFFFFFFFFC0140016LL,
    STATUS_ACPI_MUTEX_NOT_OWNER = 0xFFFFFFFFC0140017LL,
    STATUS_ACPI_RS_ACCESS = 0xFFFFFFFFC0140018LL,
    STATUS_ACPI_INVALID_TABLE = 0xFFFFFFFFC0140019LL,
    STATUS_ACPI_REG_HANDLER_FAILED = 0xFFFFFFFFC0140020LL,
    STATUS_ACPI_POWER_REQUEST_FAILED = 0xFFFFFFFFC0140021LL,
    STATUS_CTX_WINSTATION_NAME_INVALID = 0xFFFFFFFFC00A0001LL,
    STATUS_CTX_INVALID_PD = 0xFFFFFFFFC00A0002LL,
    STATUS_CTX_PD_NOT_FOUND = 0xFFFFFFFFC00A0003LL,
    STATUS_CTX_CDM_CONNECT = 0x400A0004LL,
    STATUS_CTX_CDM_DISCONNECT = 0x400A0005LL,
    STATUS_CTX_CLOSE_PENDING = 0xFFFFFFFFC00A0006LL,
    STATUS_CTX_NO_OUTBUF = 0xFFFFFFFFC00A0007LL,
    STATUS_CTX_MODEM_INF_NOT_FOUND = 0xFFFFFFFFC00A0008LL,
    STATUS_CTX_INVALID_MODEMNAME = 0xFFFFFFFFC00A0009LL,
    STATUS_CTX_RESPONSE_ERROR = 0xFFFFFFFFC00A000ALL,
    STATUS_CTX_MODEM_RESPONSE_TIMEOUT = 0xFFFFFFFFC00A000BLL,
    STATUS_CTX_MODEM_RESPONSE_NO_CARRIER = 0xFFFFFFFFC00A000CLL,
    STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE = 0xFFFFFFFFC00A000DLL,
    STATUS_CTX_MODEM_RESPONSE_BUSY = 0xFFFFFFFFC00A000ELL,
    STATUS_CTX_MODEM_RESPONSE_VOICE = 0xFFFFFFFFC00A000FLL,
    STATUS_CTX_TD_ERROR = 0xFFFFFFFFC00A0010LL,
    STATUS_CTX_LICENSE_CLIENT_INVALID = 0xFFFFFFFFC00A0012LL,
    STATUS_CTX_LICENSE_NOT_AVAILABLE = 0xFFFFFFFFC00A0013LL,
    STATUS_CTX_LICENSE_EXPIRED = 0xFFFFFFFFC00A0014LL,
    STATUS_CTX_WINSTATION_NOT_FOUND = 0xFFFFFFFFC00A0015LL,
    STATUS_CTX_WINSTATION_NAME_COLLISION = 0xFFFFFFFFC00A0016LL,
    STATUS_CTX_WINSTATION_BUSY = 0xFFFFFFFFC00A0017LL,
    STATUS_CTX_BAD_VIDEO_MODE = 0xFFFFFFFFC00A0018LL,
    STATUS_CTX_GRAPHICS_INVALID = 0xFFFFFFFFC00A0022LL,
    STATUS_CTX_NOT_CONSOLE = 0xFFFFFFFFC00A0024LL,
    STATUS_CTX_CLIENT_QUERY_TIMEOUT = 0xFFFFFFFFC00A0026LL,
    STATUS_CTX_CONSOLE_DISCONNECT = 0xFFFFFFFFC00A0027LL,
    STATUS_CTX_CONSOLE_CONNECT = 0xFFFFFFFFC00A0028LL,
    STATUS_CTX_SHADOW_DENIED = 0xFFFFFFFFC00A002ALL,
    STATUS_CTX_WINSTATION_ACCESS_DENIED = 0xFFFFFFFFC00A002BLL,
    STATUS_CTX_INVALID_WD = 0xFFFFFFFFC00A002ELL,
    STATUS_CTX_WD_NOT_FOUND = 0xFFFFFFFFC00A002FLL,
    STATUS_CTX_SHADOW_INVALID = 0xFFFFFFFFC00A0030LL,
    STATUS_CTX_SHADOW_DISABLED = 0xFFFFFFFFC00A0031LL,
    STATUS_RDP_PROTOCOL_ERROR = 0xFFFFFFFFC00A0032LL,
    STATUS_CTX_CLIENT_LICENSE_NOT_SET = 0xFFFFFFFFC00A0033LL,
    STATUS_CTX_CLIENT_LICENSE_IN_USE = 0xFFFFFFFFC00A0034LL,
    STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE = 0xFFFFFFFFC00A0035LL,
    STATUS_CTX_SHADOW_NOT_RUNNING = 0xFFFFFFFFC00A0036LL,
    STATUS_CTX_LOGON_DISABLED = 0xFFFFFFFFC00A0037LL,
    STATUS_CTX_SECURITY_LAYER_ERROR = 0xFFFFFFFFC00A0038LL,
    STATUS_TS_INCOMPATIBLE_SESSIONS = 0xFFFFFFFFC00A0039LL,
    STATUS_TS_VIDEO_SUBSYSTEM_ERROR = 0xFFFFFFFFC00A003ALL,
    STATUS_PNP_BAD_MPS_TABLE = 0xFFFFFFFFC0040035LL,
    STATUS_PNP_TRANSLATION_FAILED = 0xFFFFFFFFC0040036LL,
    STATUS_PNP_IRQ_TRANSLATION_FAILED = 0xFFFFFFFFC0040037LL,
    STATUS_PNP_INVALID_ID = 0xFFFFFFFFC0040038LL,
    STATUS_IO_REISSUE_AS_CACHED = 0xFFFFFFFFC0040039LL,
    STATUS_MUI_FILE_NOT_FOUND = 0xFFFFFFFFC00B0001LL,
    STATUS_MUI_INVALID_FILE = 0xFFFFFFFFC00B0002LL,
    STATUS_MUI_INVALID_RC_CONFIG = 0xFFFFFFFFC00B0003LL,
    STATUS_MUI_INVALID_LOCALE_NAME = 0xFFFFFFFFC00B0004LL,
    STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME = 0xFFFFFFFFC00B0005LL,
    STATUS_MUI_FILE_NOT_LOADED = 0xFFFFFFFFC00B0006LL,
    STATUS_RESOURCE_ENUM_USER_STOP = 0xFFFFFFFFC00B0007LL,
    STATUS_FLT_NO_HANDLER_DEFINED = 0xFFFFFFFFC01C0001LL,
    STATUS_FLT_CONTEXT_ALREADY_DEFINED = 0xFFFFFFFFC01C0002LL,
    STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST = 0xFFFFFFFFC01C0003LL,
    STATUS_FLT_DISALLOW_FAST_IO = 0xFFFFFFFFC01C0004LL,
    STATUS_FLT_DISALLOW_FSFILTER_IO = 0xFFFFFFFFC01C0004LL,
    STATUS_FLT_INVALID_NAME_REQUEST = 0xFFFFFFFFC01C0005LL,
    STATUS_FLT_NOT_SAFE_TO_POST_OPERATION = 0xFFFFFFFFC01C0006LL,
    STATUS_FLT_NOT_INITIALIZED = 0xFFFFFFFFC01C0007LL,
    STATUS_FLT_FILTER_NOT_READY = 0xFFFFFFFFC01C0008LL,
    STATUS_FLT_POST_OPERATION_CLEANUP = 0xFFFFFFFFC01C0009LL,
    STATUS_FLT_INTERNAL_ERROR = 0xFFFFFFFFC01C000ALL,
    STATUS_FLT_DELETING_OBJECT = 0xFFFFFFFFC01C000BLL,
    STATUS_FLT_MUST_BE_NONPAGED_POOL = 0xFFFFFFFFC01C000CLL,
    STATUS_FLT_DUPLICATE_ENTRY = 0xFFFFFFFFC01C000DLL,
    STATUS_FLT_CBDQ_DISABLED = 0xFFFFFFFFC01C000ELL,
    STATUS_FLT_DO_NOT_ATTACH = 0xFFFFFFFFC01C000FLL,
    STATUS_FLT_DO_NOT_DETACH = 0xFFFFFFFFC01C0010LL,
    STATUS_FLT_INSTANCE_ALTITUDE_COLLISION = 0xFFFFFFFFC01C0011LL,
    STATUS_FLT_INSTANCE_NAME_COLLISION = 0xFFFFFFFFC01C0012LL,
    STATUS_FLT_FILTER_NOT_FOUND = 0xFFFFFFFFC01C0013LL,
    STATUS_FLT_VOLUME_NOT_FOUND = 0xFFFFFFFFC01C0014LL,
    STATUS_FLT_INSTANCE_NOT_FOUND = 0xFFFFFFFFC01C0015LL,
    STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND = 0xFFFFFFFFC01C0016LL,
    STATUS_FLT_INVALID_CONTEXT_REGISTRATION = 0xFFFFFFFFC01C0017LL,
    STATUS_FLT_NAME_CACHE_MISS = 0xFFFFFFFFC01C0018LL,
    STATUS_FLT_NO_DEVICE_OBJECT = 0xFFFFFFFFC01C0019LL,
    STATUS_FLT_VOLUME_ALREADY_MOUNTED = 0xFFFFFFFFC01C001ALL,
    STATUS_FLT_ALREADY_ENLISTED = 0xFFFFFFFFC01C001BLL,
    STATUS_FLT_CONTEXT_ALREADY_LINKED = 0xFFFFFFFFC01C001CLL,
    STATUS_FLT_NO_WAITER_FOR_REPLY = 0xFFFFFFFFC01C0020LL,
    STATUS_FLT_REGISTRATION_BUSY = 0xFFFFFFFFC01C0023LL,
    STATUS_SXS_SECTION_NOT_FOUND = 0xFFFFFFFFC0150001LL,
    STATUS_SXS_CANT_GEN_ACTCTX = 0xFFFFFFFFC0150002LL,
    STATUS_SXS_INVALID_ACTCTXDATA_FORMAT = 0xFFFFFFFFC0150003LL,
    STATUS_SXS_ASSEMBLY_NOT_FOUND = 0xFFFFFFFFC0150004LL,
    STATUS_SXS_MANIFEST_FORMAT_ERROR = 0xFFFFFFFFC0150005LL,
    STATUS_SXS_MANIFEST_PARSE_ERROR = 0xFFFFFFFFC0150006LL,
    STATUS_SXS_ACTIVATION_CONTEXT_DISABLED = 0xFFFFFFFFC0150007LL,
    STATUS_SXS_KEY_NOT_FOUND = 0xFFFFFFFFC0150008LL,
    STATUS_SXS_VERSION_CONFLICT = 0xFFFFFFFFC0150009LL,
    STATUS_SXS_WRONG_SECTION_TYPE = 0xFFFFFFFFC015000ALL,
    STATUS_SXS_THREAD_QUERIES_DISABLED = 0xFFFFFFFFC015000BLL,
    STATUS_SXS_ASSEMBLY_MISSING = 0xFFFFFFFFC015000CLL,
    STATUS_SXS_RELEASE_ACTIVATION_CONTEXT = 0x4015000DLL,
    STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET = 0xFFFFFFFFC015000ELL,
    STATUS_SXS_EARLY_DEACTIVATION = 0xC015000FLL,
    STATUS_SXS_INVALID_DEACTIVATION = 0xC0150010LL,
    STATUS_SXS_MULTIPLE_DEACTIVATION = 0xFFFFFFFFC0150011LL,
    STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY = 0xFFFFFFFFC0150012LL,
    STATUS_SXS_PROCESS_TERMINATION_REQUESTED = 0xFFFFFFFFC0150013LL,
    STATUS_SXS_CORRUPT_ACTIVATION_STACK = 0xFFFFFFFFC0150014LL,
    STATUS_SXS_CORRUPTION = 0xFFFFFFFFC0150015LL,
    STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE = 0xFFFFFFFFC0150016LL,
    STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME = 0xFFFFFFFFC0150017LL,
    STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE = 0xFFFFFFFFC0150018LL,
    STATUS_SXS_IDENTITY_PARSE_ERROR = 0xFFFFFFFFC0150019LL,
    STATUS_SXS_COMPONENT_STORE_CORRUPT = 0xFFFFFFFFC015001ALL,
    STATUS_SXS_FILE_HASH_MISMATCH = 0xFFFFFFFFC015001BLL,
    STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT = 0xFFFFFFFFC015001CLL,
    STATUS_SXS_IDENTITIES_DIFFERENT = 0xFFFFFFFFC015001DLL,
    STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT = 0xFFFFFFFFC015001ELL,
    STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY = 0xFFFFFFFFC015001FLL,
    STATUS_ADVANCED_INSTALLER_FAILED = 0xFFFFFFFFC0150020LL,
    STATUS_XML_ENCODING_MISMATCH = 0xFFFFFFFFC0150021LL,
    STATUS_SXS_MANIFEST_TOO_BIG = 0xFFFFFFFFC0150022LL,
    STATUS_SXS_SETTING_NOT_REGISTERED = 0xFFFFFFFFC0150023LL,
    STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE = 0xFFFFFFFFC0150024LL,
    STATUS_SMI_PRIMITIVE_INSTALLER_FAILED = 0xFFFFFFFFC0150025LL,
    STATUS_GENERIC_COMMAND_FAILED = 0xFFFFFFFFC0150026LL,
    STATUS_SXS_FILE_HASH_MISSING = 0xFFFFFFFFC0150027LL,
    STATUS_CLUSTER_INVALID_NODE = 0xFFFFFFFFC0130001LL,
    STATUS_CLUSTER_NODE_EXISTS = 0xFFFFFFFFC0130002LL,
    STATUS_CLUSTER_JOIN_IN_PROGRESS = 0xFFFFFFFFC0130003LL,
    STATUS_CLUSTER_NODE_NOT_FOUND = 0xFFFFFFFFC0130004LL,
    STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND = 0xFFFFFFFFC0130005LL,
    STATUS_CLUSTER_NETWORK_EXISTS = 0xFFFFFFFFC0130006LL,
    STATUS_CLUSTER_NETWORK_NOT_FOUND = 0xFFFFFFFFC0130007LL,
    STATUS_CLUSTER_NETINTERFACE_EXISTS = 0xFFFFFFFFC0130008LL,
    STATUS_CLUSTER_NETINTERFACE_NOT_FOUND = 0xFFFFFFFFC0130009LL,
    STATUS_CLUSTER_INVALID_REQUEST = 0xFFFFFFFFC013000ALL,
    STATUS_CLUSTER_INVALID_NETWORK_PROVIDER = 0xFFFFFFFFC013000BLL,
    STATUS_CLUSTER_NODE_DOWN = 0xFFFFFFFFC013000CLL,
    STATUS_CLUSTER_NODE_UNREACHABLE = 0xFFFFFFFFC013000DLL,
    STATUS_CLUSTER_NODE_NOT_MEMBER = 0xFFFFFFFFC013000ELL,
    STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS = 0xFFFFFFFFC013000FLL,
    STATUS_CLUSTER_INVALID_NETWORK = 0xFFFFFFFFC0130010LL,
    STATUS_CLUSTER_NO_NET_ADAPTERS = 0xFFFFFFFFC0130011LL,
    STATUS_CLUSTER_NODE_UP = 0xFFFFFFFFC0130012LL,
    STATUS_CLUSTER_NODE_PAUSED = 0xFFFFFFFFC0130013LL,
    STATUS_CLUSTER_NODE_NOT_PAUSED = 0xFFFFFFFFC0130014LL,
    STATUS_CLUSTER_NO_SECURITY_CONTEXT = 0xFFFFFFFFC0130015LL,
    STATUS_CLUSTER_NETWORK_NOT_INTERNAL = 0xFFFFFFFFC0130016LL,
    STATUS_CLUSTER_POISONED = 0xFFFFFFFFC0130017LL,
    STATUS_CLUSTER_NON_CSV_PATH = 0xFFFFFFFFC0130018LL,
    STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL = 0xFFFFFFFFC0130019LL,
    STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS = 0xFFFFFFFFC0130020LL,
    STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR = 0xFFFFFFFFC0130021LL,
    STATUS_CLUSTER_CSV_REDIRECTED = 0xFFFFFFFFC0130022LL,
    STATUS_CLUSTER_CSV_NOT_REDIRECTED = 0xFFFFFFFFC0130023LL,
    STATUS_CLUSTER_CSV_VOLUME_DRAINING = 0xFFFFFFFFC0130024LL,
    STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS = 0xFFFFFFFFC0130025LL,
    STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL = 0xFFFFFFFFC0130026LL,
    STATUS_CLUSTER_CSV_NO_SNAPSHOTS = 0xFFFFFFFFC0130027LL,
    STATUS_CSV_IO_PAUSE_TIMEOUT = 0xFFFFFFFFC0130028LL,
    STATUS_CLUSTER_CSV_INVALID_HANDLE = 0xFFFFFFFFC0130029LL,
    STATUS_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR = 0xFFFFFFFFC0130030LL,
    STATUS_CLUSTER_CAM_TICKET_REPLAY_DETECTED = 0xFFFFFFFFC0130031LL,
    STATUS_TRANSACTIONAL_CONFLICT = 0xFFFFFFFFC0190001LL,
    STATUS_INVALID_TRANSACTION = 0xFFFFFFFFC0190002LL,
    STATUS_TRANSACTION_NOT_ACTIVE = 0xFFFFFFFFC0190003LL,
    STATUS_TM_INITIALIZATION_FAILED = 0xFFFFFFFFC0190004LL,
    STATUS_RM_NOT_ACTIVE = 0xFFFFFFFFC0190005LL,
    STATUS_RM_METADATA_CORRUPT = 0xFFFFFFFFC0190006LL,
    STATUS_TRANSACTION_NOT_JOINED = 0xFFFFFFFFC0190007LL,
    STATUS_DIRECTORY_NOT_RM = 0xFFFFFFFFC0190008LL,
    STATUS_COULD_NOT_RESIZE_LOG = 0xFFFFFFFF80190009LL,
    STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE = 0xFFFFFFFFC019000ALL,
    STATUS_LOG_RESIZE_INVALID_SIZE = 0xFFFFFFFFC019000BLL,
    STATUS_REMOTE_FILE_VERSION_MISMATCH = 0xFFFFFFFFC019000CLL,
    STATUS_CRM_PROTOCOL_ALREADY_EXISTS = 0xFFFFFFFFC019000FLL,
    STATUS_TRANSACTION_PROPAGATION_FAILED = 0xFFFFFFFFC0190010LL,
    STATUS_CRM_PROTOCOL_NOT_FOUND = 0xFFFFFFFFC0190011LL,
    STATUS_TRANSACTION_SUPERIOR_EXISTS = 0xFFFFFFFFC0190012LL,
    STATUS_TRANSACTION_REQUEST_NOT_VALID = 0xFFFFFFFFC0190013LL,
    STATUS_TRANSACTION_NOT_REQUESTED = 0xFFFFFFFFC0190014LL,
    STATUS_TRANSACTION_ALREADY_ABORTED = 0xFFFFFFFFC0190015LL,
    STATUS_TRANSACTION_ALREADY_COMMITTED = 0xFFFFFFFFC0190016LL,
    STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER = 0xFFFFFFFFC0190017LL,
    STATUS_CURRENT_TRANSACTION_NOT_VALID = 0xFFFFFFFFC0190018LL,
    STATUS_LOG_GROWTH_FAILED = 0xFFFFFFFFC0190019LL,
    STATUS_OBJECT_NO_LONGER_EXISTS = 0xFFFFFFFFC0190021LL,
    STATUS_STREAM_MINIVERSION_NOT_FOUND = 0xFFFFFFFFC0190022LL,
    STATUS_STREAM_MINIVERSION_NOT_VALID = 0xFFFFFFFFC0190023LL,
    STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION = 0xFFFFFFFFC0190024LL,
    STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT = 0xFFFFFFFFC0190025LL,
    STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS = 0xFFFFFFFFC0190026LL,
    STATUS_HANDLE_NO_LONGER_VALID = 0xFFFFFFFFC0190028LL,
    STATUS_NO_TXF_METADATA = 0xFFFFFFFF80190029LL,
    STATUS_LOG_CORRUPTION_DETECTED = 0xFFFFFFFFC0190030LL,
    STATUS_CANT_RECOVER_WITH_HANDLE_OPEN = 0xFFFFFFFF80190031LL,
    STATUS_RM_DISCONNECTED = 0xFFFFFFFFC0190032LL,
    STATUS_ENLISTMENT_NOT_SUPERIOR = 0xFFFFFFFFC0190033LL,
    STATUS_RECOVERY_NOT_NEEDED = 0x40190034LL,
    STATUS_RM_ALREADY_STARTED = 0x40190035LL,
    STATUS_FILE_IDENTITY_NOT_PERSISTENT = 0xFFFFFFFFC0190036LL,
    STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY = 0xFFFFFFFFC0190037LL,
    STATUS_CANT_CROSS_RM_BOUNDARY = 0xFFFFFFFFC0190038LL,
    STATUS_TXF_DIR_NOT_EMPTY = 0xFFFFFFFFC0190039LL,
    STATUS_INDOUBT_TRANSACTIONS_EXIST = 0xFFFFFFFFC019003ALL,
    STATUS_TM_VOLATILE = 0xFFFFFFFFC019003BLL,
    STATUS_ROLLBACK_TIMER_EXPIRED = 0xFFFFFFFFC019003CLL,
    STATUS_TXF_ATTRIBUTE_CORRUPT = 0xFFFFFFFFC019003DLL,
    STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION = 0xFFFFFFFFC019003ELL,
    STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED = 0xFFFFFFFFC019003FLL,
    STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE = 0xFFFFFFFFC0190040LL,
    STATUS_TXF_METADATA_ALREADY_PRESENT = 0xFFFFFFFF80190041LL,
    STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET = 0xFFFFFFFF80190042LL,
    STATUS_TRANSACTION_REQUIRED_PROMOTION = 0xFFFFFFFFC0190043LL,
    STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION = 0xFFFFFFFFC0190044LL,
    STATUS_TRANSACTIONS_NOT_FROZEN = 0xFFFFFFFFC0190045LL,
    STATUS_TRANSACTION_FREEZE_IN_PROGRESS = 0xFFFFFFFFC0190046LL,
    STATUS_NOT_SNAPSHOT_VOLUME = 0xFFFFFFFFC0190047LL,
    STATUS_NO_SAVEPOINT_WITH_OPEN_FILES = 0xFFFFFFFFC0190048LL,
    STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION = 0xFFFFFFFFC0190049LL,
    STATUS_TM_IDENTITY_MISMATCH = 0xFFFFFFFFC019004ALL,
    STATUS_FLOATED_SECTION = 0xFFFFFFFFC019004BLL,
    STATUS_CANNOT_ACCEPT_TRANSACTED_WORK = 0xFFFFFFFFC019004CLL,
    STATUS_CANNOT_ABORT_TRANSACTIONS = 0xFFFFFFFFC019004DLL,
    STATUS_TRANSACTION_NOT_FOUND = 0xFFFFFFFFC019004ELL,
    STATUS_RESOURCEMANAGER_NOT_FOUND = 0xFFFFFFFFC019004FLL,
    STATUS_ENLISTMENT_NOT_FOUND = 0xFFFFFFFFC0190050LL,
    STATUS_TRANSACTIONMANAGER_NOT_FOUND = 0xFFFFFFFFC0190051LL,
    STATUS_TRANSACTIONMANAGER_NOT_ONLINE = 0xFFFFFFFFC0190052LL,
    STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION = 0xFFFFFFFFC0190053LL,
    STATUS_TRANSACTION_NOT_ROOT = 0xFFFFFFFFC0190054LL,
    STATUS_TRANSACTION_OBJECT_EXPIRED = 0xFFFFFFFFC0190055LL,
    STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION = 0xFFFFFFFFC0190056LL,
    STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED = 0xFFFFFFFFC0190057LL,
    STATUS_TRANSACTION_RECORD_TOO_LONG = 0xFFFFFFFFC0190058LL,
    STATUS_NO_LINK_TRACKING_IN_TRANSACTION = 0xFFFFFFFFC0190059LL,
    STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION = 0xFFFFFFFFC019005ALL,
    STATUS_TRANSACTION_INTEGRITY_VIOLATED = 0xFFFFFFFFC019005BLL,
    STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH = 0xFFFFFFFFC019005CLL,
    STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT = 0xFFFFFFFFC019005DLL,
    STATUS_TRANSACTION_MUST_WRITETHROUGH = 0xFFFFFFFFC019005ELL,
    STATUS_TRANSACTION_NO_SUPERIOR = 0xFFFFFFFFC019005FLL,
    STATUS_EXPIRED_HANDLE = 0xFFFFFFFFC0190060LL,
    STATUS_TRANSACTION_NOT_ENLISTED = 0xFFFFFFFFC0190061LL,
    STATUS_LOG_SECTOR_INVALID = 0xFFFFFFFFC01A0001LL,
    STATUS_LOG_SECTOR_PARITY_INVALID = 0xFFFFFFFFC01A0002LL,
    STATUS_LOG_SECTOR_REMAPPED = 0xFFFFFFFFC01A0003LL,
    STATUS_LOG_BLOCK_INCOMPLETE = 0xFFFFFFFFC01A0004LL,
    STATUS_LOG_INVALID_RANGE = 0xFFFFFFFFC01A0005LL,
    STATUS_LOG_BLOCKS_EXHAUSTED = 0xFFFFFFFFC01A0006LL,
    STATUS_LOG_READ_CONTEXT_INVALID = 0xFFFFFFFFC01A0007LL,
    STATUS_LOG_RESTART_INVALID = 0xFFFFFFFFC01A0008LL,
    STATUS_LOG_BLOCK_VERSION = 0xFFFFFFFFC01A0009LL,
    STATUS_LOG_BLOCK_INVALID = 0xFFFFFFFFC01A000ALL,
    STATUS_LOG_READ_MODE_INVALID = 0xFFFFFFFFC01A000BLL,
    STATUS_LOG_NO_RESTART = 0x401A000CLL,
    STATUS_LOG_METADATA_CORRUPT = 0xFFFFFFFFC01A000DLL,
    STATUS_LOG_METADATA_INVALID = 0xFFFFFFFFC01A000ELL,
    STATUS_LOG_METADATA_INCONSISTENT = 0xFFFFFFFFC01A000FLL,
    STATUS_LOG_RESERVATION_INVALID = 0xFFFFFFFFC01A0010LL,
    STATUS_LOG_CANT_DELETE = 0xFFFFFFFFC01A0011LL,
    STATUS_LOG_CONTAINER_LIMIT_EXCEEDED = 0xFFFFFFFFC01A0012LL,
    STATUS_LOG_START_OF_LOG = 0xFFFFFFFFC01A0013LL,
    STATUS_LOG_POLICY_ALREADY_INSTALLED = 0xFFFFFFFFC01A0014LL,
    STATUS_LOG_POLICY_NOT_INSTALLED = 0xFFFFFFFFC01A0015LL,
    STATUS_LOG_POLICY_INVALID = 0xFFFFFFFFC01A0016LL,
    STATUS_LOG_POLICY_CONFLICT = 0xFFFFFFFFC01A0017LL,
    STATUS_LOG_PINNED_ARCHIVE_TAIL = 0xFFFFFFFFC01A0018LL,
    STATUS_LOG_RECORD_NONEXISTENT = 0xFFFFFFFFC01A0019LL,
    STATUS_LOG_RECORDS_RESERVED_INVALID = 0xFFFFFFFFC01A001ALL,
    STATUS_LOG_SPACE_RESERVED_INVALID = 0xFFFFFFFFC01A001BLL,
    STATUS_LOG_TAIL_INVALID = 0xFFFFFFFFC01A001CLL,
    STATUS_LOG_FULL = 0xFFFFFFFFC01A001DLL,
    STATUS_LOG_MULTIPLEXED = 0xFFFFFFFFC01A001ELL,
    STATUS_LOG_DEDICATED = 0xFFFFFFFFC01A001FLL,
    STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS = 0xFFFFFFFFC01A0020LL,
    STATUS_LOG_ARCHIVE_IN_PROGRESS = 0xFFFFFFFFC01A0021LL,
    STATUS_LOG_EPHEMERAL = 0xFFFFFFFFC01A0022LL,
    STATUS_LOG_NOT_ENOUGH_CONTAINERS = 0xFFFFFFFFC01A0023LL,
    STATUS_LOG_CLIENT_ALREADY_REGISTERED = 0xFFFFFFFFC01A0024LL,
    STATUS_LOG_CLIENT_NOT_REGISTERED = 0xFFFFFFFFC01A0025LL,
    STATUS_LOG_FULL_HANDLER_IN_PROGRESS = 0xFFFFFFFFC01A0026LL,
    STATUS_LOG_CONTAINER_READ_FAILED = 0xFFFFFFFFC01A0027LL,
    STATUS_LOG_CONTAINER_WRITE_FAILED = 0xFFFFFFFFC01A0028LL,
    STATUS_LOG_CONTAINER_OPEN_FAILED = 0xFFFFFFFFC01A0029LL,
    STATUS_LOG_CONTAINER_STATE_INVALID = 0xFFFFFFFFC01A002ALL,
    STATUS_LOG_STATE_INVALID = 0xFFFFFFFFC01A002BLL,
    STATUS_LOG_PINNED = 0xFFFFFFFFC01A002CLL,
    STATUS_LOG_METADATA_FLUSH_FAILED = 0xFFFFFFFFC01A002DLL,
    STATUS_LOG_INCONSISTENT_SECURITY = 0xFFFFFFFFC01A002ELL,
    STATUS_LOG_APPENDED_FLUSH_FAILED = 0xFFFFFFFFC01A002FLL,
    STATUS_LOG_PINNED_RESERVATION = 0xFFFFFFFFC01A0030LL,
    STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD = 0xFFFFFFFFC01B00EALL,
    STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED = 0xFFFFFFFF801B00EBLL,
    STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST = 0x401B00ECLL,
    STATUS_MONITOR_NO_DESCRIPTOR = 0xFFFFFFFFC01D0001LL,
    STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT = 0xFFFFFFFFC01D0002LL,
    STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM = 0xFFFFFFFFC01D0003LL,
    STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK = 0xFFFFFFFFC01D0004LL,
    STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED = 0xFFFFFFFFC01D0005LL,
    STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK = 0xFFFFFFFFC01D0006LL,
    STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK = 0xFFFFFFFFC01D0007LL,
    STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA = 0xFFFFFFFFC01D0008LL,
    STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK = 0xFFFFFFFFC01D0009LL,
    STATUS_MONITOR_INVALID_MANUFACTURE_DATE = 0xFFFFFFFFC01D000ALL,
    STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER = 0xFFFFFFFFC01E0000LL,
    STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER = 0xFFFFFFFFC01E0001LL,
    STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER = 0xFFFFFFFFC01E0002LL,
    STATUS_GRAPHICS_ADAPTER_WAS_RESET = 0xFFFFFFFFC01E0003LL,
    STATUS_GRAPHICS_INVALID_DRIVER_MODEL = 0xFFFFFFFFC01E0004LL,
    STATUS_GRAPHICS_PRESENT_MODE_CHANGED = 0xFFFFFFFFC01E0005LL,
    STATUS_GRAPHICS_PRESENT_OCCLUDED = 0xFFFFFFFFC01E0006LL,
    STATUS_GRAPHICS_PRESENT_DENIED = 0xFFFFFFFFC01E0007LL,
    STATUS_GRAPHICS_CANNOTCOLORCONVERT = 0xFFFFFFFFC01E0008LL,
    STATUS_GRAPHICS_DRIVER_MISMATCH = 0xFFFFFFFFC01E0009LL,
    STATUS_GRAPHICS_PARTIAL_DATA_POPULATED = 0x401E000ALL,
    STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED = 0xFFFFFFFFC01E000BLL,
    STATUS_GRAPHICS_PRESENT_UNOCCLUDED = 0xFFFFFFFFC01E000CLL,
    STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE = 0xFFFFFFFFC01E000DLL,
    STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED = 0xFFFFFFFFC01E000ELL,
    STATUS_GRAPHICS_PRESENT_INVALID_WINDOW = 0xFFFFFFFFC01E000FLL,
    STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND = 0xFFFFFFFFC01E0010LL,
    STATUS_GRAPHICS_VAIL_STATE_CHANGED = 0xFFFFFFFFC01E0011LL,
    STATUS_GRAPHICS_NO_VIDEO_MEMORY = 0xFFFFFFFFC01E0100LL,
    STATUS_GRAPHICS_CANT_LOCK_MEMORY = 0xFFFFFFFFC01E0101LL,
    STATUS_GRAPHICS_ALLOCATION_BUSY = 0xFFFFFFFFC01E0102LL,
    STATUS_GRAPHICS_TOO_MANY_REFERENCES = 0xFFFFFFFFC01E0103LL,
    STATUS_GRAPHICS_TRY_AGAIN_LATER = 0xFFFFFFFFC01E0104LL,
    STATUS_GRAPHICS_TRY_AGAIN_NOW = 0xFFFFFFFFC01E0105LL,
    STATUS_GRAPHICS_ALLOCATION_INVALID = 0xFFFFFFFFC01E0106LL,
    STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE = 0xFFFFFFFFC01E0107LL,
    STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED = 0xFFFFFFFFC01E0108LL,
    STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION = 0xFFFFFFFFC01E0109LL,
    STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE = 0xFFFFFFFFC01E0110LL,
    STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION = 0xFFFFFFFFC01E0111LL,
    STATUS_GRAPHICS_ALLOCATION_CLOSED = 0xFFFFFFFFC01E0112LL,
    STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE = 0xFFFFFFFFC01E0113LL,
    STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE = 0xFFFFFFFFC01E0114LL,
    STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE = 0xFFFFFFFFC01E0115LL,
    STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST = 0xFFFFFFFFC01E0116LL,
    STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE = 0xFFFFFFFFC01E0200LL,
    STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION = 0x401E0201LL,
    STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY = 0xFFFFFFFFC01E0300LL,
    STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED = 0xFFFFFFFFC01E0301LL,
    STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED = 0xFFFFFFFFC01E0302LL,
    STATUS_GRAPHICS_INVALID_VIDPN = 0xFFFFFFFFC01E0303LL,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE = 0xFFFFFFFFC01E0304LL,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET = 0xFFFFFFFFC01E0305LL,
    STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED = 0xFFFFFFFFC01E0306LL,
    STATUS_GRAPHICS_MODE_NOT_PINNED = 0x401E0307LL,
    STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET = 0xFFFFFFFFC01E0308LL,
    STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET = 0xFFFFFFFFC01E0309LL,
    STATUS_GRAPHICS_INVALID_FREQUENCY = 0xFFFFFFFFC01E030ALL,
    STATUS_GRAPHICS_INVALID_ACTIVE_REGION = 0xFFFFFFFFC01E030BLL,
    STATUS_GRAPHICS_INVALID_TOTAL_REGION = 0xFFFFFFFFC01E030CLL,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE = 0xFFFFFFFFC01E0310LL,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE = 0xFFFFFFFFC01E0311LL,
    STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET = 0xFFFFFFFFC01E0312LL,
    STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY = 0xFFFFFFFFC01E0313LL,
    STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET = 0xFFFFFFFFC01E0314LL,
    STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET = 0xFFFFFFFFC01E0315LL,
    STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET = 0xFFFFFFFFC01E0316LL,
    STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET = 0xFFFFFFFFC01E0317LL,
    STATUS_GRAPHICS_TARGET_ALREADY_IN_SET = 0xFFFFFFFFC01E0318LL,
    STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH = 0xFFFFFFFFC01E0319LL,
    STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY = 0xFFFFFFFFC01E031ALL,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET = 0xFFFFFFFFC01E031BLL,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE = 0xFFFFFFFFC01E031CLL,
    STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET = 0xFFFFFFFFC01E031DLL,
    STATUS_GRAPHICS_NO_PREFERRED_MODE = 0x401E031ELL,
    STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET = 0xFFFFFFFFC01E031FLL,
    STATUS_GRAPHICS_STALE_MODESET = 0xFFFFFFFFC01E0320LL,
    STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET = 0xFFFFFFFFC01E0321LL,
    STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE = 0xFFFFFFFFC01E0322LL,
    STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN = 0xFFFFFFFFC01E0323LL,
    STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE = 0xFFFFFFFFC01E0324LL,
    STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION = 0xFFFFFFFFC01E0325LL,
    STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES = 0xFFFFFFFFC01E0326LL,
    STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY = 0xFFFFFFFFC01E0327LL,
    STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE = 0xFFFFFFFFC01E0328LL,
    STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET = 0xFFFFFFFFC01E0329LL,
    STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET = 0xFFFFFFFFC01E032ALL,
    STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR = 0xFFFFFFFFC01E032BLL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET = 0xFFFFFFFFC01E032CLL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET = 0xFFFFFFFFC01E032DLL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE = 0xFFFFFFFFC01E032ELL,
    STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE = 0xFFFFFFFFC01E032FLL,
    STATUS_GRAPHICS_RESOURCES_NOT_RELATED = 0xFFFFFFFFC01E0330LL,
    STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE = 0xFFFFFFFFC01E0331LL,
    STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE = 0xFFFFFFFFC01E0332LL,
    STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET = 0xFFFFFFFFC01E0333LL,
    STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER = 0xFFFFFFFFC01E0334LL,
    STATUS_GRAPHICS_NO_VIDPNMGR = 0xFFFFFFFFC01E0335LL,
    STATUS_GRAPHICS_NO_ACTIVE_VIDPN = 0xFFFFFFFFC01E0336LL,
    STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY = 0xFFFFFFFFC01E0337LL,
    STATUS_GRAPHICS_MONITOR_NOT_CONNECTED = 0xFFFFFFFFC01E0338LL,
    STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY = 0xFFFFFFFFC01E0339LL,
    STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE = 0xFFFFFFFFC01E033ALL,
    STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE = 0xFFFFFFFFC01E033BLL,
    STATUS_GRAPHICS_INVALID_STRIDE = 0xFFFFFFFFC01E033CLL,
    STATUS_GRAPHICS_INVALID_PIXELFORMAT = 0xFFFFFFFFC01E033DLL,
    STATUS_GRAPHICS_INVALID_COLORBASIS = 0xFFFFFFFFC01E033ELL,
    STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE = 0xFFFFFFFFC01E033FLL,
    STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY = 0xFFFFFFFFC01E0340LL,
    STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT = 0xFFFFFFFFC01E0341LL,
    STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE = 0xFFFFFFFFC01E0342LL,
    STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN = 0xFFFFFFFFC01E0343LL,
    STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL = 0xFFFFFFFFC01E0344LL,
    STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION = 0xFFFFFFFFC01E0345LL,
    STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED = 0xFFFFFFFFC01E0346LL,
    STATUS_GRAPHICS_INVALID_GAMMA_RAMP = 0xFFFFFFFFC01E0347LL,
    STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED = 0xFFFFFFFFC01E0348LL,
    STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED = 0xFFFFFFFFC01E0349LL,
    STATUS_GRAPHICS_MODE_NOT_IN_MODESET = 0xFFFFFFFFC01E034ALL,
    STATUS_GRAPHICS_DATASET_IS_EMPTY = 0x401E034BLL,
    STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET = 0x401E034CLL,
    STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON = 0xFFFFFFFFC01E034DLL,
    STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE = 0xFFFFFFFFC01E034ELL,
    STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE = 0xFFFFFFFFC01E034FLL,
    STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS = 0xFFFFFFFFC01E0350LL,
    STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED = 0x401E0351LL,
    STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING = 0xFFFFFFFFC01E0352LL,
    STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED = 0xFFFFFFFFC01E0353LL,
    STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS = 0xFFFFFFFFC01E0354LL,
    STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT = 0xFFFFFFFFC01E0355LL,
    STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM = 0xFFFFFFFFC01E0356LL,
    STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN = 0xFFFFFFFFC01E0357LL,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT = 0xFFFFFFFFC01E0358LL,
    STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED = 0xFFFFFFFFC01E0359LL,
    STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION = 0xFFFFFFFFC01E035ALL,
    STATUS_GRAPHICS_INVALID_CLIENT_TYPE = 0xFFFFFFFFC01E035BLL,
    STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET = 0xFFFFFFFFC01E035CLL,
    STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED = 0xFFFFFFFFC01E0400LL,
    STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED = 0xFFFFFFFFC01E0401LL,
    STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS = 0x401E042FLL,
    STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER = 0xFFFFFFFFC01E0430LL,
    STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED = 0xFFFFFFFFC01E0431LL,
    STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED = 0xFFFFFFFFC01E0432LL,
    STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY = 0xFFFFFFFFC01E0433LL,
    STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED = 0xFFFFFFFFC01E0434LL,
    STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON = 0xFFFFFFFFC01E0435LL,
    STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE = 0xFFFFFFFFC01E0436LL,
    STATUS_GRAPHICS_LEADLINK_START_DEFERRED = 0x401E0437LL,
    STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER = 0xFFFFFFFFC01E0438LL,
    STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY = 0x401E0439LL,
    STATUS_GRAPHICS_START_DEFERRED = 0x401E043ALL,
    STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED = 0xFFFFFFFFC01E043BLL,
    STATUS_GRAPHICS_DEPENDABLE_CHILD_STATUS = 0x401E043CLL,
    STATUS_GRAPHICS_OPM_NOT_SUPPORTED = 0xFFFFFFFFC01E0500LL,
    STATUS_GRAPHICS_COPP_NOT_SUPPORTED = 0xFFFFFFFFC01E0501LL,
    STATUS_GRAPHICS_UAB_NOT_SUPPORTED = 0xFFFFFFFFC01E0502LL,
    STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS = 0xFFFFFFFFC01E0503LL,
    STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST = 0xFFFFFFFFC01E0505LL,
    STATUS_GRAPHICS_OPM_INTERNAL_ERROR = 0xFFFFFFFFC01E050BLL,
    STATUS_GRAPHICS_OPM_INVALID_HANDLE = 0xFFFFFFFFC01E050CLL,
    STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH = 0xFFFFFFFFC01E050ELL,
    STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED = 0xFFFFFFFFC01E050FLL,
    STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED = 0xFFFFFFFFC01E0510LL,
    STATUS_GRAPHICS_PVP_HFS_FAILED = 0xFFFFFFFFC01E0511LL,
    STATUS_GRAPHICS_OPM_INVALID_SRM = 0xFFFFFFFFC01E0512LL,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP = 0xFFFFFFFFC01E0513LL,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP = 0xFFFFFFFFC01E0514LL,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA = 0xFFFFFFFFC01E0515LL,
    STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET = 0xFFFFFFFFC01E0516LL,
    STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH = 0xFFFFFFFFC01E0517LL,
    STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE = 0xFFFFFFFFC01E0518LL,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS = 0xFFFFFFFFC01E051ALL,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS = 0xFFFFFFFFC01E051CLL,
    STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST = 0xFFFFFFFFC01E051DLL,
    STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR = 0xFFFFFFFFC01E051ELL,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS = 0xFFFFFFFFC01E051FLL,
    STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED = 0xFFFFFFFFC01E0520LL,
    STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST = 0xFFFFFFFFC01E0521LL,
    STATUS_GRAPHICS_I2C_NOT_SUPPORTED = 0xFFFFFFFFC01E0580LL,
    STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST = 0xFFFFFFFFC01E0581LL,
    STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA = 0xFFFFFFFFC01E0582LL,
    STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA = 0xFFFFFFFFC01E0583LL,
    STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED = 0xFFFFFFFFC01E0584LL,
    STATUS_GRAPHICS_DDCCI_INVALID_DATA = 0xFFFFFFFFC01E0585LL,
    STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE = 0xFFFFFFFFC01E0586LL,
    STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING = 0xFFFFFFFFC01E0587LL,
    STATUS_GRAPHICS_MCA_INTERNAL_ERROR = 0xFFFFFFFFC01E0588LL,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND = 0xFFFFFFFFC01E0589LL,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH = 0xFFFFFFFFC01E058ALL,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM = 0xFFFFFFFFC01E058BLL,
    STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE = 0xFFFFFFFFC01E058CLL,
    STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS = 0xFFFFFFFFC01E058DLL,
    STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED = 0xFFFFFFFFC01E05E0LL,
    STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME = 0xFFFFFFFFC01E05E1LL,
    STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP = 0xFFFFFFFFC01E05E2LL,
    STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED = 0xFFFFFFFFC01E05E3LL,
    STATUS_GRAPHICS_INVALID_POINTER = 0xFFFFFFFFC01E05E4LL,
    STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE = 0xFFFFFFFFC01E05E5LL,
    STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL = 0xFFFFFFFFC01E05E6LL,
    STATUS_GRAPHICS_INTERNAL_ERROR = 0xFFFFFFFFC01E05E7LL,
    STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS = 0xFFFFFFFFC01E05E8LL,
    STATUS_FVE_LOCKED_VOLUME = 0xFFFFFFFFC0210000LL,
    STATUS_FVE_NOT_ENCRYPTED = 0xFFFFFFFFC0210001LL,
    STATUS_FVE_BAD_INFORMATION = 0xFFFFFFFFC0210002LL,
    STATUS_FVE_TOO_SMALL = 0xFFFFFFFFC0210003LL,
    STATUS_FVE_FAILED_WRONG_FS = 0xFFFFFFFFC0210004LL,
    STATUS_FVE_BAD_PARTITION_SIZE = 0xFFFFFFFFC0210005LL,
    STATUS_FVE_FS_NOT_EXTENDED = 0xFFFFFFFFC0210006LL,
    STATUS_FVE_FS_MOUNTED = 0xFFFFFFFFC0210007LL,
    STATUS_FVE_NO_LICENSE = 0xFFFFFFFFC0210008LL,
    STATUS_FVE_ACTION_NOT_ALLOWED = 0xFFFFFFFFC0210009LL,
    STATUS_FVE_BAD_DATA = 0xFFFFFFFFC021000ALL,
    STATUS_FVE_VOLUME_NOT_BOUND = 0xFFFFFFFFC021000BLL,
    STATUS_FVE_NOT_DATA_VOLUME = 0xFFFFFFFFC021000CLL,
    STATUS_FVE_CONV_READ_ERROR = 0xFFFFFFFFC021000DLL,
    STATUS_FVE_CONV_WRITE_ERROR = 0xFFFFFFFFC021000ELL,
    STATUS_FVE_OVERLAPPED_UPDATE = 0xFFFFFFFFC021000FLL,
    STATUS_FVE_FAILED_SECTOR_SIZE = 0xFFFFFFFFC0210010LL,
    STATUS_FVE_FAILED_AUTHENTICATION = 0xFFFFFFFFC0210011LL,
    STATUS_FVE_NOT_OS_VOLUME = 0xFFFFFFFFC0210012LL,
    STATUS_FVE_KEYFILE_NOT_FOUND = 0xFFFFFFFFC0210013LL,
    STATUS_FVE_KEYFILE_INVALID = 0xFFFFFFFFC0210014LL,
    STATUS_FVE_KEYFILE_NO_VMK = 0xFFFFFFFFC0210015LL,
    STATUS_FVE_TPM_DISABLED = 0xFFFFFFFFC0210016LL,
    STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO = 0xFFFFFFFFC0210017LL,
    STATUS_FVE_TPM_INVALID_PCR = 0xFFFFFFFFC0210018LL,
    STATUS_FVE_TPM_NO_VMK = 0xFFFFFFFFC0210019LL,
    STATUS_FVE_PIN_INVALID = 0xFFFFFFFFC021001ALL,
    STATUS_FVE_AUTH_INVALID_APPLICATION = 0xFFFFFFFFC021001BLL,
    STATUS_FVE_AUTH_INVALID_CONFIG = 0xFFFFFFFFC021001CLL,
    STATUS_FVE_DEBUGGER_ENABLED = 0xFFFFFFFFC021001DLL,
    STATUS_FVE_DRY_RUN_FAILED = 0xFFFFFFFFC021001ELL,
    STATUS_FVE_BAD_METADATA_POINTER = 0xFFFFFFFFC021001FLL,
    STATUS_FVE_OLD_METADATA_COPY = 0xFFFFFFFFC0210020LL,
    STATUS_FVE_REBOOT_REQUIRED = 0xFFFFFFFFC0210021LL,
    STATUS_FVE_RAW_ACCESS = 0xFFFFFFFFC0210022LL,
    STATUS_FVE_RAW_BLOCKED = 0xFFFFFFFFC0210023LL,
    STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY = 0xFFFFFFFFC0210024LL,
    STATUS_FVE_MOR_FAILED = 0xFFFFFFFFC0210025LL,
    STATUS_FVE_NO_FEATURE_LICENSE = 0xFFFFFFFFC0210026LL,
    STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED = 0xFFFFFFFFC0210027LL,
    STATUS_FVE_CONV_RECOVERY_FAILED = 0xFFFFFFFFC0210028LL,
    STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG = 0xFFFFFFFFC0210029LL,
    STATUS_FVE_INVALID_DATUM_TYPE = 0xFFFFFFFFC021002ALL,
    STATUS_FVE_VOLUME_TOO_SMALL = 0xFFFFFFFFC0210030LL,
    STATUS_FVE_ENH_PIN_INVALID = 0xFFFFFFFFC0210031LL,
    STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE = 0xFFFFFFFFC0210032LL,
    STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE = 0xFFFFFFFFC0210033LL,
    STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK = 0xFFFFFFFFC0210034LL,
    STATUS_FVE_NOT_ALLOWED_ON_CLUSTER = 0xFFFFFFFFC0210035LL,
    STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING = 0xFFFFFFFFC0210036LL,
    STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE = 0xFFFFFFFFC0210037LL,
    STATUS_FVE_EDRIVE_DRY_RUN_FAILED = 0xFFFFFFFFC0210038LL,
    STATUS_FVE_SECUREBOOT_DISABLED = 0xFFFFFFFFC0210039LL,
    STATUS_FVE_SECUREBOOT_CONFIG_CHANGE = 0xFFFFFFFFC021003ALL,
    STATUS_FVE_DEVICE_LOCKEDOUT = 0xFFFFFFFFC021003BLL,
    STATUS_FVE_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT = 0xFFFFFFFFC021003CLL,
    STATUS_FVE_NOT_DE_VOLUME = 0xFFFFFFFFC021003DLL,
    STATUS_FVE_PROTECTION_DISABLED = 0xFFFFFFFFC021003ELL,
    STATUS_FVE_PROTECTION_CANNOT_BE_DISABLED = 0xFFFFFFFFC021003FLL,
    STATUS_FVE_OSV_KSR_NOT_ALLOWED = 0xFFFFFFFFC0210040LL,
    STATUS_FWP_CALLOUT_NOT_FOUND = 0xFFFFFFFFC0220001LL,
    STATUS_FWP_CONDITION_NOT_FOUND = 0xFFFFFFFFC0220002LL,
    STATUS_FWP_FILTER_NOT_FOUND = 0xFFFFFFFFC0220003LL,
    STATUS_FWP_LAYER_NOT_FOUND = 0xFFFFFFFFC0220004LL,
    STATUS_FWP_PROVIDER_NOT_FOUND = 0xFFFFFFFFC0220005LL,
    STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND = 0xFFFFFFFFC0220006LL,
    STATUS_FWP_SUBLAYER_NOT_FOUND = 0xFFFFFFFFC0220007LL,
    STATUS_FWP_NOT_FOUND = 0xFFFFFFFFC0220008LL,
    STATUS_FWP_ALREADY_EXISTS = 0xFFFFFFFFC0220009LL,
    STATUS_FWP_IN_USE = 0xFFFFFFFFC022000ALL,
    STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS = 0xFFFFFFFFC022000BLL,
    STATUS_FWP_WRONG_SESSION = 0xFFFFFFFFC022000CLL,
    STATUS_FWP_NO_TXN_IN_PROGRESS = 0xFFFFFFFFC022000DLL,
    STATUS_FWP_TXN_IN_PROGRESS = 0xFFFFFFFFC022000ELL,
    STATUS_FWP_TXN_ABORTED = 0xFFFFFFFFC022000FLL,
    STATUS_FWP_SESSION_ABORTED = 0xFFFFFFFFC0220010LL,
    STATUS_FWP_INCOMPATIBLE_TXN = 0xFFFFFFFFC0220011LL,
    STATUS_FWP_TIMEOUT = 0xFFFFFFFFC0220012LL,
    STATUS_FWP_NET_EVENTS_DISABLED = 0xFFFFFFFFC0220013LL,
    STATUS_FWP_INCOMPATIBLE_LAYER = 0xFFFFFFFFC0220014LL,
    STATUS_FWP_KM_CLIENTS_ONLY = 0xFFFFFFFFC0220015LL,
    STATUS_FWP_LIFETIME_MISMATCH = 0xFFFFFFFFC0220016LL,
    STATUS_FWP_BUILTIN_OBJECT = 0xFFFFFFFFC0220017LL,
    STATUS_FWP_TOO_MANY_CALLOUTS = 0xFFFFFFFFC0220018LL,
    STATUS_FWP_NOTIFICATION_DROPPED = 0xFFFFFFFFC0220019LL,
    STATUS_FWP_TRAFFIC_MISMATCH = 0xFFFFFFFFC022001ALL,
    STATUS_FWP_INCOMPATIBLE_SA_STATE = 0xFFFFFFFFC022001BLL,
    STATUS_FWP_NULL_POINTER = 0xFFFFFFFFC022001CLL,
    STATUS_FWP_INVALID_ENUMERATOR = 0xFFFFFFFFC022001DLL,
    STATUS_FWP_INVALID_FLAGS = 0xFFFFFFFFC022001ELL,
    STATUS_FWP_INVALID_NET_MASK = 0xFFFFFFFFC022001FLL,
    STATUS_FWP_INVALID_RANGE = 0xFFFFFFFFC0220020LL,
    STATUS_FWP_INVALID_INTERVAL = 0xFFFFFFFFC0220021LL,
    STATUS_FWP_ZERO_LENGTH_ARRAY = 0xFFFFFFFFC0220022LL,
    STATUS_FWP_NULL_DISPLAY_NAME = 0xFFFFFFFFC0220023LL,
    STATUS_FWP_INVALID_ACTION_TYPE = 0xFFFFFFFFC0220024LL,
    STATUS_FWP_INVALID_WEIGHT = 0xFFFFFFFFC0220025LL,
    STATUS_FWP_MATCH_TYPE_MISMATCH = 0xFFFFFFFFC0220026LL,
    STATUS_FWP_TYPE_MISMATCH = 0xFFFFFFFFC0220027LL,
    STATUS_FWP_OUT_OF_BOUNDS = 0xFFFFFFFFC0220028LL,
    STATUS_FWP_RESERVED = 0xFFFFFFFFC0220029LL,
    STATUS_FWP_DUPLICATE_CONDITION = 0xFFFFFFFFC022002ALL,
    STATUS_FWP_DUPLICATE_KEYMOD = 0xFFFFFFFFC022002BLL,
    STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER = 0xFFFFFFFFC022002CLL,
    STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER = 0xFFFFFFFFC022002DLL,
    STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER = 0xFFFFFFFFC022002ELL,
    STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT = 0xFFFFFFFFC022002FLL,
    STATUS_FWP_INCOMPATIBLE_AUTH_METHOD = 0xFFFFFFFFC0220030LL,
    STATUS_FWP_INCOMPATIBLE_DH_GROUP = 0xFFFFFFFFC0220031LL,
    STATUS_FWP_EM_NOT_SUPPORTED = 0xFFFFFFFFC0220032LL,
    STATUS_FWP_NEVER_MATCH = 0xFFFFFFFFC0220033LL,
    STATUS_FWP_PROVIDER_CONTEXT_MISMATCH = 0xFFFFFFFFC0220034LL,
    STATUS_FWP_INVALID_PARAMETER = 0xFFFFFFFFC0220035LL,
    STATUS_FWP_TOO_MANY_SUBLAYERS = 0xFFFFFFFFC0220036LL,
    STATUS_FWP_CALLOUT_NOTIFICATION_FAILED = 0xFFFFFFFFC0220037LL,
    STATUS_FWP_INVALID_AUTH_TRANSFORM = 0xFFFFFFFFC0220038LL,
    STATUS_FWP_INVALID_CIPHER_TRANSFORM = 0xFFFFFFFFC0220039LL,
    STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM = 0xFFFFFFFFC022003ALL,
    STATUS_FWP_INVALID_TRANSFORM_COMBINATION = 0xFFFFFFFFC022003BLL,
    STATUS_FWP_DUPLICATE_AUTH_METHOD = 0xFFFFFFFFC022003CLL,
    STATUS_FWP_INVALID_TUNNEL_ENDPOINT = 0xFFFFFFFFC022003DLL,
    STATUS_FWP_L2_DRIVER_NOT_READY = 0xFFFFFFFFC022003ELL,
    STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED = 0xFFFFFFFFC022003FLL,
    STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL = 0xFFFFFFFFC0220040LL,
    STATUS_FWP_CONNECTIONS_DISABLED = 0xFFFFFFFFC0220041LL,
    STATUS_FWP_INVALID_DNS_NAME = 0xFFFFFFFFC0220042LL,
    STATUS_FWP_STILL_ON = 0xFFFFFFFFC0220043LL,
    STATUS_FWP_IKEEXT_NOT_RUNNING = 0xFFFFFFFFC0220044LL,
    STATUS_FWP_TCPIP_NOT_READY = 0xFFFFFFFFC0220100LL,
    STATUS_FWP_INJECT_HANDLE_CLOSING = 0xFFFFFFFFC0220101LL,
    STATUS_FWP_INJECT_HANDLE_STALE = 0xFFFFFFFFC0220102LL,
    STATUS_FWP_CANNOT_PEND = 0xFFFFFFFFC0220103LL,
    STATUS_FWP_DROP_NOICMP = 0xFFFFFFFFC0220104LL,
    STATUS_NDIS_CLOSING = 0xFFFFFFFFC0230002LL,
    STATUS_NDIS_BAD_VERSION = 0xFFFFFFFFC0230004LL,
    STATUS_NDIS_BAD_CHARACTERISTICS = 0xFFFFFFFFC0230005LL,
    STATUS_NDIS_ADAPTER_NOT_FOUND = 0xFFFFFFFFC0230006LL,
    STATUS_NDIS_OPEN_FAILED = 0xFFFFFFFFC0230007LL,
    STATUS_NDIS_DEVICE_FAILED = 0xFFFFFFFFC0230008LL,
    STATUS_NDIS_MULTICAST_FULL = 0xFFFFFFFFC0230009LL,
    STATUS_NDIS_MULTICAST_EXISTS = 0xFFFFFFFFC023000ALL,
    STATUS_NDIS_MULTICAST_NOT_FOUND = 0xFFFFFFFFC023000BLL,
    STATUS_NDIS_REQUEST_ABORTED = 0xFFFFFFFFC023000CLL,
    STATUS_NDIS_RESET_IN_PROGRESS = 0xFFFFFFFFC023000DLL,
    STATUS_NDIS_NOT_SUPPORTED = 0xFFFFFFFFC02300BBLL,
    STATUS_NDIS_INVALID_PACKET = 0xFFFFFFFFC023000FLL,
    STATUS_NDIS_ADAPTER_NOT_READY = 0xFFFFFFFFC0230011LL,
    STATUS_NDIS_INVALID_LENGTH = 0xFFFFFFFFC0230014LL,
    STATUS_NDIS_INVALID_DATA = 0xFFFFFFFFC0230015LL,
    STATUS_NDIS_BUFFER_TOO_SHORT = 0xFFFFFFFFC0230016LL,
    STATUS_NDIS_INVALID_OID = 0xFFFFFFFFC0230017LL,
    STATUS_NDIS_ADAPTER_REMOVED = 0xFFFFFFFFC0230018LL,
    STATUS_NDIS_UNSUPPORTED_MEDIA = 0xFFFFFFFFC0230019LL,
    STATUS_NDIS_GROUP_ADDRESS_IN_USE = 0xFFFFFFFFC023001ALL,
    STATUS_NDIS_FILE_NOT_FOUND = 0xFFFFFFFFC023001BLL,
    STATUS_NDIS_ERROR_READING_FILE = 0xFFFFFFFFC023001CLL,
    STATUS_NDIS_ALREADY_MAPPED = 0xFFFFFFFFC023001DLL,
    STATUS_NDIS_RESOURCE_CONFLICT = 0xFFFFFFFFC023001ELL,
    STATUS_NDIS_MEDIA_DISCONNECTED = 0xFFFFFFFFC023001FLL,
    STATUS_NDIS_INVALID_ADDRESS = 0xFFFFFFFFC0230022LL,
    STATUS_NDIS_INVALID_DEVICE_REQUEST = 0xFFFFFFFFC0230010LL,
    STATUS_NDIS_PAUSED = 0xFFFFFFFFC023002ALL,
    STATUS_NDIS_INTERFACE_NOT_FOUND = 0xFFFFFFFFC023002BLL,
    STATUS_NDIS_UNSUPPORTED_REVISION = 0xFFFFFFFFC023002CLL,
    STATUS_NDIS_INVALID_PORT = 0xFFFFFFFFC023002DLL,
    STATUS_NDIS_INVALID_PORT_STATE = 0xFFFFFFFFC023002ELL,
    STATUS_NDIS_LOW_POWER_STATE = 0xFFFFFFFFC023002FLL,
    STATUS_NDIS_REINIT_REQUIRED = 0xFFFFFFFFC0230030LL,
    STATUS_NDIS_NO_QUEUES = 0xFFFFFFFFC0230031LL,
    STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED = 0xFFFFFFFFC0232000LL,
    STATUS_NDIS_DOT11_MEDIA_IN_USE = 0xFFFFFFFFC0232001LL,
    STATUS_NDIS_DOT11_POWER_STATE_INVALID = 0xFFFFFFFFC0232002LL,
    STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL = 0xFFFFFFFFC0232003LL,
    STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL = 0xFFFFFFFFC0232004LL,
    STATUS_NDIS_DOT11_AP_CHANNEL_CURRENTLY_NOT_AVAILABLE = 0xFFFFFFFFC0232005LL,
    STATUS_NDIS_DOT11_AP_BAND_CURRENTLY_NOT_AVAILABLE = 0xFFFFFFFFC0232006LL,
    STATUS_NDIS_DOT11_AP_CHANNEL_NOT_ALLOWED = 0xFFFFFFFFC0232007LL,
    STATUS_NDIS_DOT11_AP_BAND_NOT_ALLOWED = 0xFFFFFFFFC0232008LL,
    STATUS_NDIS_INDICATION_REQUIRED = 0x40230001LL,
    STATUS_NDIS_OFFLOAD_POLICY = 0xFFFFFFFFC023100FLL,
    STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED = 0xFFFFFFFFC0231012LL,
    STATUS_NDIS_OFFLOAD_PATH_REJECTED = 0xFFFFFFFFC0231013LL,
    STATUS_TPM_ERROR_MASK = 0xFFFFFFFFC0290000LL,
    STATUS_TPM_AUTHFAIL = 0xFFFFFFFFC0290001LL,
    STATUS_TPM_BADINDEX = 0xFFFFFFFFC0290002LL,
    STATUS_TPM_BAD_PARAMETER = 0xFFFFFFFFC0290003LL,
    STATUS_TPM_AUDITFAILURE = 0xFFFFFFFFC0290004LL,
    STATUS_TPM_CLEAR_DISABLED = 0xFFFFFFFFC0290005LL,
    STATUS_TPM_DEACTIVATED = 0xFFFFFFFFC0290006LL,
    STATUS_TPM_DISABLED = 0xFFFFFFFFC0290007LL,
    STATUS_TPM_DISABLED_CMD = 0xFFFFFFFFC0290008LL,
    STATUS_TPM_FAIL = 0xFFFFFFFFC0290009LL,
    STATUS_TPM_BAD_ORDINAL = 0xFFFFFFFFC029000ALL,
    STATUS_TPM_INSTALL_DISABLED = 0xFFFFFFFFC029000BLL,
    STATUS_TPM_INVALID_KEYHANDLE = 0xFFFFFFFFC029000CLL,
    STATUS_TPM_KEYNOTFOUND = 0xFFFFFFFFC029000DLL,
    STATUS_TPM_INAPPROPRIATE_ENC = 0xFFFFFFFFC029000ELL,
    STATUS_TPM_MIGRATEFAIL = 0xFFFFFFFFC029000FLL,
    STATUS_TPM_INVALID_PCR_INFO = 0xFFFFFFFFC0290010LL,
    STATUS_TPM_NOSPACE = 0xFFFFFFFFC0290011LL,
    STATUS_TPM_NOSRK = 0xFFFFFFFFC0290012LL,
    STATUS_TPM_NOTSEALED_BLOB = 0xFFFFFFFFC0290013LL,
    STATUS_TPM_OWNER_SET = 0xFFFFFFFFC0290014LL,
    STATUS_TPM_RESOURCES = 0xFFFFFFFFC0290015LL,
    STATUS_TPM_SHORTRANDOM = 0xFFFFFFFFC0290016LL,
    STATUS_TPM_SIZE = 0xFFFFFFFFC0290017LL,
    STATUS_TPM_WRONGPCRVAL = 0xFFFFFFFFC0290018LL,
    STATUS_TPM_BAD_PARAM_SIZE = 0xFFFFFFFFC0290019LL,
    STATUS_TPM_SHA_THREAD = 0xFFFFFFFFC029001ALL,
    STATUS_TPM_SHA_ERROR = 0xFFFFFFFFC029001BLL,
    STATUS_TPM_FAILEDSELFTEST = 0xFFFFFFFFC029001CLL,
    STATUS_TPM_AUTH2FAIL = 0xFFFFFFFFC029001DLL,
    STATUS_TPM_BADTAG = 0xFFFFFFFFC029001ELL,
    STATUS_TPM_IOERROR = 0xFFFFFFFFC029001FLL,
    STATUS_TPM_ENCRYPT_ERROR = 0xFFFFFFFFC0290020LL,
    STATUS_TPM_DECRYPT_ERROR = 0xFFFFFFFFC0290021LL,
    STATUS_TPM_INVALID_AUTHHANDLE = 0xFFFFFFFFC0290022LL,
    STATUS_TPM_NO_ENDORSEMENT = 0xFFFFFFFFC0290023LL,
    STATUS_TPM_INVALID_KEYUSAGE = 0xFFFFFFFFC0290024LL,
    STATUS_TPM_WRONG_ENTITYTYPE = 0xFFFFFFFFC0290025LL,
    STATUS_TPM_INVALID_POSTINIT = 0xFFFFFFFFC0290026LL,
    STATUS_TPM_INAPPROPRIATE_SIG = 0xFFFFFFFFC0290027LL,
    STATUS_TPM_BAD_KEY_PROPERTY = 0xFFFFFFFFC0290028LL,
    STATUS_TPM_BAD_MIGRATION = 0xFFFFFFFFC0290029LL,
    STATUS_TPM_BAD_SCHEME = 0xFFFFFFFFC029002ALL,
    STATUS_TPM_BAD_DATASIZE = 0xFFFFFFFFC029002BLL,
    STATUS_TPM_BAD_MODE = 0xFFFFFFFFC029002CLL,
    STATUS_TPM_BAD_PRESENCE = 0xFFFFFFFFC029002DLL,
    STATUS_TPM_BAD_VERSION = 0xFFFFFFFFC029002ELL,
    STATUS_TPM_NO_WRAP_TRANSPORT = 0xFFFFFFFFC029002FLL,
    STATUS_TPM_AUDITFAIL_UNSUCCESSFUL = 0xFFFFFFFFC0290030LL,
    STATUS_TPM_AUDITFAIL_SUCCESSFUL = 0xFFFFFFFFC0290031LL,
    STATUS_TPM_NOTRESETABLE = 0xFFFFFFFFC0290032LL,
    STATUS_TPM_NOTLOCAL = 0xFFFFFFFFC0290033LL,
    STATUS_TPM_BAD_TYPE = 0xFFFFFFFFC0290034LL,
    STATUS_TPM_INVALID_RESOURCE = 0xFFFFFFFFC0290035LL,
    STATUS_TPM_NOTFIPS = 0xFFFFFFFFC0290036LL,
    STATUS_TPM_INVALID_FAMILY = 0xFFFFFFFFC0290037LL,
    STATUS_TPM_NO_NV_PERMISSION = 0xFFFFFFFFC0290038LL,
    STATUS_TPM_REQUIRES_SIGN = 0xFFFFFFFFC0290039LL,
    STATUS_TPM_KEY_NOTSUPPORTED = 0xFFFFFFFFC029003ALL,
    STATUS_TPM_AUTH_CONFLICT = 0xFFFFFFFFC029003BLL,
    STATUS_TPM_AREA_LOCKED = 0xFFFFFFFFC029003CLL,
    STATUS_TPM_BAD_LOCALITY = 0xFFFFFFFFC029003DLL,
    STATUS_TPM_READ_ONLY = 0xFFFFFFFFC029003ELL,
    STATUS_TPM_PER_NOWRITE = 0xFFFFFFFFC029003FLL,
    STATUS_TPM_FAMILYCOUNT = 0xFFFFFFFFC0290040LL,
    STATUS_TPM_WRITE_LOCKED = 0xFFFFFFFFC0290041LL,
    STATUS_TPM_BAD_ATTRIBUTES = 0xFFFFFFFFC0290042LL,
    STATUS_TPM_INVALID_STRUCTURE = 0xFFFFFFFFC0290043LL,
    STATUS_TPM_KEY_OWNER_CONTROL = 0xFFFFFFFFC0290044LL,
    STATUS_TPM_BAD_COUNTER = 0xFFFFFFFFC0290045LL,
    STATUS_TPM_NOT_FULLWRITE = 0xFFFFFFFFC0290046LL,
    STATUS_TPM_CONTEXT_GAP = 0xFFFFFFFFC0290047LL,
    STATUS_TPM_MAXNVWRITES = 0xFFFFFFFFC0290048LL,
    STATUS_TPM_NOOPERATOR = 0xFFFFFFFFC0290049LL,
    STATUS_TPM_RESOURCEMISSING = 0xFFFFFFFFC029004ALL,
    STATUS_TPM_DELEGATE_LOCK = 0xFFFFFFFFC029004BLL,
    STATUS_TPM_DELEGATE_FAMILY = 0xFFFFFFFFC029004CLL,
    STATUS_TPM_DELEGATE_ADMIN = 0xFFFFFFFFC029004DLL,
    STATUS_TPM_TRANSPORT_NOTEXCLUSIVE = 0xFFFFFFFFC029004ELL,
    STATUS_TPM_OWNER_CONTROL = 0xFFFFFFFFC029004FLL,
    STATUS_TPM_DAA_RESOURCES = 0xFFFFFFFFC0290050LL,
    STATUS_TPM_DAA_INPUT_DATA0 = 0xFFFFFFFFC0290051LL,
    STATUS_TPM_DAA_INPUT_DATA1 = 0xFFFFFFFFC0290052LL,
    STATUS_TPM_DAA_ISSUER_SETTINGS = 0xFFFFFFFFC0290053LL,
    STATUS_TPM_DAA_TPM_SETTINGS = 0xFFFFFFFFC0290054LL,
    STATUS_TPM_DAA_STAGE = 0xFFFFFFFFC0290055LL,
    STATUS_TPM_DAA_ISSUER_VALIDITY = 0xFFFFFFFFC0290056LL,
    STATUS_TPM_DAA_WRONG_W = 0xFFFFFFFFC0290057LL,
    STATUS_TPM_BAD_HANDLE = 0xFFFFFFFFC0290058LL,
    STATUS_TPM_BAD_DELEGATE = 0xFFFFFFFFC0290059LL,
    STATUS_TPM_BADCONTEXT = 0xFFFFFFFFC029005ALL,
    STATUS_TPM_TOOMANYCONTEXTS = 0xFFFFFFFFC029005BLL,
    STATUS_TPM_MA_TICKET_SIGNATURE = 0xFFFFFFFFC029005CLL,
    STATUS_TPM_MA_DESTINATION = 0xFFFFFFFFC029005DLL,
    STATUS_TPM_MA_SOURCE = 0xFFFFFFFFC029005ELL,
    STATUS_TPM_MA_AUTHORITY = 0xFFFFFFFFC029005FLL,
    STATUS_TPM_PERMANENTEK = 0xFFFFFFFFC0290061LL,
    STATUS_TPM_BAD_SIGNATURE = 0xFFFFFFFFC0290062LL,
    STATUS_TPM_NOCONTEXTSPACE = 0xFFFFFFFFC0290063LL,
    STATUS_TPM_20_E_ASYMMETRIC = 0xFFFFFFFFC0290081LL,
    STATUS_TPM_20_E_ATTRIBUTES = 0xFFFFFFFFC0290082LL,
    STATUS_TPM_20_E_HASH = 0xFFFFFFFFC0290083LL,
    STATUS_TPM_20_E_VALUE = 0xFFFFFFFFC0290084LL,
    STATUS_TPM_20_E_HIERARCHY = 0xFFFFFFFFC0290085LL,
    STATUS_TPM_20_E_KEY_SIZE = 0xFFFFFFFFC0290087LL,
    STATUS_TPM_20_E_MGF = 0xFFFFFFFFC0290088LL,
    STATUS_TPM_20_E_MODE = 0xFFFFFFFFC0290089LL,
    STATUS_TPM_20_E_TYPE = 0xFFFFFFFFC029008ALL,
    STATUS_TPM_20_E_HANDLE = 0xFFFFFFFFC029008BLL,
    STATUS_TPM_20_E_KDF = 0xFFFFFFFFC029008CLL,
    STATUS_TPM_20_E_RANGE = 0xFFFFFFFFC029008DLL,
    STATUS_TPM_20_E_AUTH_FAIL = 0xFFFFFFFFC029008ELL,
    STATUS_TPM_20_E_NONCE = 0xFFFFFFFFC029008FLL,
    STATUS_TPM_20_E_PP = 0xFFFFFFFFC0290090LL,
    STATUS_TPM_20_E_SCHEME = 0xFFFFFFFFC0290092LL,
    STATUS_TPM_20_E_SIZE = 0xFFFFFFFFC0290095LL,
    STATUS_TPM_20_E_SYMMETRIC = 0xFFFFFFFFC0290096LL,
    STATUS_TPM_20_E_TAG = 0xFFFFFFFFC0290097LL,
    STATUS_TPM_20_E_SELECTOR = 0xFFFFFFFFC0290098LL,
    STATUS_TPM_20_E_INSUFFICIENT = 0xFFFFFFFFC029009ALL,
    STATUS_TPM_20_E_SIGNATURE = 0xFFFFFFFFC029009BLL,
    STATUS_TPM_20_E_KEY = 0xFFFFFFFFC029009CLL,
    STATUS_TPM_20_E_POLICY_FAIL = 0xFFFFFFFFC029009DLL,
    STATUS_TPM_20_E_INTEGRITY = 0xFFFFFFFFC029009FLL,
    STATUS_TPM_20_E_TICKET = 0xFFFFFFFFC02900A0LL,
    STATUS_TPM_20_E_RESERVED_BITS = 0xFFFFFFFFC02900A1LL,
    STATUS_TPM_20_E_BAD_AUTH = 0xFFFFFFFFC02900A2LL,
    STATUS_TPM_20_E_EXPIRED = 0xFFFFFFFFC02900A3LL,
    STATUS_TPM_20_E_POLICY_CC = 0xFFFFFFFFC02900A4LL,
    STATUS_TPM_20_E_BINDING = 0xFFFFFFFFC02900A5LL,
    STATUS_TPM_20_E_CURVE = 0xFFFFFFFFC02900A6LL,
    STATUS_TPM_20_E_ECC_POINT = 0xFFFFFFFFC02900A7LL,
    STATUS_TPM_20_E_INITIALIZE = 0xFFFFFFFFC0290100LL,
    STATUS_TPM_20_E_FAILURE = 0xFFFFFFFFC0290101LL,
    STATUS_TPM_20_E_SEQUENCE = 0xFFFFFFFFC0290103LL,
    STATUS_TPM_20_E_PRIVATE = 0xFFFFFFFFC029010BLL,
    STATUS_TPM_20_E_HMAC = 0xFFFFFFFFC0290119LL,
    STATUS_TPM_20_E_DISABLED = 0xFFFFFFFFC0290120LL,
    STATUS_TPM_20_E_EXCLUSIVE = 0xFFFFFFFFC0290121LL,
    STATUS_TPM_20_E_ECC_CURVE = 0xFFFFFFFFC0290123LL,
    STATUS_TPM_20_E_AUTH_TYPE = 0xFFFFFFFFC0290124LL,
    STATUS_TPM_20_E_AUTH_MISSING = 0xFFFFFFFFC0290125LL,
    STATUS_TPM_20_E_POLICY = 0xFFFFFFFFC0290126LL,
    STATUS_TPM_20_E_PCR = 0xFFFFFFFFC0290127LL,
    STATUS_TPM_20_E_PCR_CHANGED = 0xFFFFFFFFC0290128LL,
    STATUS_TPM_20_E_UPGRADE = 0xFFFFFFFFC029012DLL,
    STATUS_TPM_20_E_TOO_MANY_CONTEXTS = 0xFFFFFFFFC029012ELL,
    STATUS_TPM_20_E_AUTH_UNAVAILABLE = 0xFFFFFFFFC029012FLL,
    STATUS_TPM_20_E_REBOOT = 0xFFFFFFFFC0290130LL,
    STATUS_TPM_20_E_UNBALANCED = 0xFFFFFFFFC0290131LL,
    STATUS_TPM_20_E_COMMAND_SIZE = 0xFFFFFFFFC0290142LL,
    STATUS_TPM_20_E_COMMAND_CODE = 0xFFFFFFFFC0290143LL,
    STATUS_TPM_20_E_AUTHSIZE = 0xFFFFFFFFC0290144LL,
    STATUS_TPM_20_E_AUTH_CONTEXT = 0xFFFFFFFFC0290145LL,
    STATUS_TPM_20_E_NV_RANGE = 0xFFFFFFFFC0290146LL,
    STATUS_TPM_20_E_NV_SIZE = 0xFFFFFFFFC0290147LL,
    STATUS_TPM_20_E_NV_LOCKED = 0xFFFFFFFFC0290148LL,
    STATUS_TPM_20_E_NV_AUTHORIZATION = 0xFFFFFFFFC0290149LL,
    STATUS_TPM_20_E_NV_UNINITIALIZED = 0xFFFFFFFFC029014ALL,
    STATUS_TPM_20_E_NV_SPACE = 0xFFFFFFFFC029014BLL,
    STATUS_TPM_20_E_NV_DEFINED = 0xFFFFFFFFC029014CLL,
    STATUS_TPM_20_E_BAD_CONTEXT = 0xFFFFFFFFC0290150LL,
    STATUS_TPM_20_E_CPHASH = 0xFFFFFFFFC0290151LL,
    STATUS_TPM_20_E_PARENT = 0xFFFFFFFFC0290152LL,
    STATUS_TPM_20_E_NEEDS_TEST = 0xFFFFFFFFC0290153LL,
    STATUS_TPM_20_E_NO_RESULT = 0xFFFFFFFFC0290154LL,
    STATUS_TPM_20_E_SENSITIVE = 0xFFFFFFFFC0290155LL,
    STATUS_TPM_COMMAND_BLOCKED = 0xFFFFFFFFC0290400LL,
    STATUS_TPM_INVALID_HANDLE = 0xFFFFFFFFC0290401LL,
    STATUS_TPM_DUPLICATE_VHANDLE = 0xFFFFFFFFC0290402LL,
    STATUS_TPM_EMBEDDED_COMMAND_BLOCKED = 0xFFFFFFFFC0290403LL,
    STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED = 0xFFFFFFFFC0290404LL,
    STATUS_TPM_RETRY = 0xFFFFFFFFC0290800LL,
    STATUS_TPM_NEEDS_SELFTEST = 0xFFFFFFFFC0290801LL,
    STATUS_TPM_DOING_SELFTEST = 0xFFFFFFFFC0290802LL,
    STATUS_TPM_DEFEND_LOCK_RUNNING = 0xFFFFFFFFC0290803LL,
    STATUS_TPM_COMMAND_CANCELED = 0xFFFFFFFFC0291001LL,
    STATUS_TPM_TOO_MANY_CONTEXTS = 0xFFFFFFFFC0291002LL,
    STATUS_TPM_NOT_FOUND = 0xFFFFFFFFC0291003LL,
    STATUS_TPM_ACCESS_DENIED = 0xFFFFFFFFC0291004LL,
    STATUS_TPM_INSUFFICIENT_BUFFER = 0xFFFFFFFFC0291005LL,
    STATUS_TPM_PPI_FUNCTION_UNSUPPORTED = 0xFFFFFFFFC0291006LL,
    STATUS_PCP_ERROR_MASK = 0xFFFFFFFFC0292000LL,
    STATUS_PCP_DEVICE_NOT_READY = 0xFFFFFFFFC0292001LL,
    STATUS_PCP_INVALID_HANDLE = 0xFFFFFFFFC0292002LL,
    STATUS_PCP_INVALID_PARAMETER = 0xFFFFFFFFC0292003LL,
    STATUS_PCP_FLAG_NOT_SUPPORTED = 0xFFFFFFFFC0292004LL,
    STATUS_PCP_NOT_SUPPORTED = 0xFFFFFFFFC0292005LL,
    STATUS_PCP_BUFFER_TOO_SMALL = 0xFFFFFFFFC0292006LL,
    STATUS_PCP_INTERNAL_ERROR = 0xFFFFFFFFC0292007LL,
    STATUS_PCP_AUTHENTICATION_FAILED = 0xFFFFFFFFC0292008LL,
    STATUS_PCP_AUTHENTICATION_IGNORED = 0xFFFFFFFFC0292009LL,
    STATUS_PCP_POLICY_NOT_FOUND = 0xFFFFFFFFC029200ALL,
    STATUS_PCP_PROFILE_NOT_FOUND = 0xFFFFFFFFC029200BLL,
    STATUS_PCP_VALIDATION_FAILED = 0xFFFFFFFFC029200CLL,
    STATUS_PCP_DEVICE_NOT_FOUND = 0xFFFFFFFFC029200DLL,
    STATUS_PCP_WRONG_PARENT = 0xFFFFFFFFC029200ELL,
    STATUS_PCP_KEY_NOT_LOADED = 0xFFFFFFFFC029200FLL,
    STATUS_PCP_NO_KEY_CERTIFICATION = 0xFFFFFFFFC0292010LL,
    STATUS_PCP_KEY_NOT_FINALIZED = 0xFFFFFFFFC0292011LL,
    STATUS_PCP_ATTESTATION_CHALLENGE_NOT_SET = 0xFFFFFFFFC0292012LL,
    STATUS_PCP_NOT_PCR_BOUND = 0xFFFFFFFFC0292013LL,
    STATUS_PCP_KEY_ALREADY_FINALIZED = 0xFFFFFFFFC0292014LL,
    STATUS_PCP_KEY_USAGE_POLICY_NOT_SUPPORTED = 0xFFFFFFFFC0292015LL,
    STATUS_PCP_KEY_USAGE_POLICY_INVALID = 0xFFFFFFFFC0292016LL,
    STATUS_PCP_SOFT_KEY_ERROR = 0xFFFFFFFFC0292017LL,
    STATUS_PCP_KEY_NOT_AUTHENTICATED = 0xFFFFFFFFC0292018LL,
    STATUS_PCP_KEY_NOT_AIK = 0xFFFFFFFFC0292019LL,
    STATUS_PCP_KEY_NOT_SIGNING_KEY = 0xFFFFFFFFC029201ALL,
    STATUS_PCP_LOCKED_OUT = 0xFFFFFFFFC029201BLL,
    STATUS_PCP_CLAIM_TYPE_NOT_SUPPORTED = 0xFFFFFFFFC029201CLL,
    STATUS_PCP_TPM_VERSION_NOT_SUPPORTED = 0xFFFFFFFFC029201DLL,
    STATUS_PCP_BUFFER_LENGTH_MISMATCH = 0xFFFFFFFFC029201ELL,
    STATUS_PCP_IFX_RSA_KEY_CREATION_BLOCKED = 0xFFFFFFFFC029201FLL,
    STATUS_PCP_TICKET_MISSING = 0xFFFFFFFFC0292020LL,
    STATUS_PCP_RAW_POLICY_NOT_SUPPORTED = 0xFFFFFFFFC0292021LL,
    STATUS_PCP_KEY_HANDLE_INVALIDATED = 0xFFFFFFFFC0292022LL,
    STATUS_PCP_UNSUPPORTED_PSS_SALT = 0x40292023LL,
    STATUS_RTPM_CONTEXT_CONTINUE = 0x293000LL,
    STATUS_RTPM_CONTEXT_COMPLETE = 0x293001LL,
    STATUS_RTPM_NO_RESULT = 0xFFFFFFFFC0293002LL,
    STATUS_RTPM_PCR_READ_INCOMPLETE = 0xFFFFFFFFC0293003LL,
    STATUS_RTPM_INVALID_CONTEXT = 0xFFFFFFFFC0293004LL,
    STATUS_RTPM_UNSUPPORTED_CMD = 0xFFFFFFFFC0293005LL,
    STATUS_TPM_ZERO_EXHAUST_ENABLED = 0xFFFFFFFFC0294000LL,
    STATUS_HV_INVALID_HYPERCALL_CODE = 0xFFFFFFFFC0350002LL,
    STATUS_HV_INVALID_HYPERCALL_INPUT = 0xFFFFFFFFC0350003LL,
    STATUS_HV_INVALID_ALIGNMENT = 0xFFFFFFFFC0350004LL,
    STATUS_HV_INVALID_PARAMETER = 0xFFFFFFFFC0350005LL,
    STATUS_HV_ACCESS_DENIED = 0xFFFFFFFFC0350006LL,
    STATUS_HV_INVALID_PARTITION_STATE = 0xFFFFFFFFC0350007LL,
    STATUS_HV_OPERATION_DENIED = 0xFFFFFFFFC0350008LL,
    STATUS_HV_UNKNOWN_PROPERTY = 0xFFFFFFFFC0350009LL,
    STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE = 0xFFFFFFFFC035000ALL,
    STATUS_HV_INSUFFICIENT_MEMORY = 0xFFFFFFFFC035000BLL,
    STATUS_HV_PARTITION_TOO_DEEP = 0xFFFFFFFFC035000CLL,
    STATUS_HV_INVALID_PARTITION_ID = 0xFFFFFFFFC035000DLL,
    STATUS_HV_INVALID_VP_INDEX = 0xFFFFFFFFC035000ELL,
    STATUS_HV_INVALID_PORT_ID = 0xFFFFFFFFC0350011LL,
    STATUS_HV_INVALID_CONNECTION_ID = 0xFFFFFFFFC0350012LL,
    STATUS_HV_INSUFFICIENT_BUFFERS = 0xFFFFFFFFC0350013LL,
    STATUS_HV_NOT_ACKNOWLEDGED = 0xFFFFFFFFC0350014LL,
    STATUS_HV_INVALID_VP_STATE = 0xFFFFFFFFC0350015LL,
    STATUS_HV_ACKNOWLEDGED = 0xFFFFFFFFC0350016LL,
    STATUS_HV_INVALID_SAVE_RESTORE_STATE = 0xFFFFFFFFC0350017LL,
    STATUS_HV_INVALID_SYNIC_STATE = 0xFFFFFFFFC0350018LL,
    STATUS_HV_OBJECT_IN_USE = 0xFFFFFFFFC0350019LL,
    STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO = 0xFFFFFFFFC035001ALL,
    STATUS_HV_NO_DATA = 0xFFFFFFFFC035001BLL,
    STATUS_HV_INACTIVE = 0xFFFFFFFFC035001CLL,
    STATUS_HV_NO_RESOURCES = 0xFFFFFFFFC035001DLL,
    STATUS_HV_FEATURE_UNAVAILABLE = 0xFFFFFFFFC035001ELL,
    STATUS_HV_INSUFFICIENT_BUFFER = 0xFFFFFFFFC0350033LL,
    STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS = 0xFFFFFFFFC0350038LL,
    STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR = 0xFFFFFFFFC035003CLL,
    STATUS_HV_CPUID_XSAVE_FEATURE_VALIDATION_ERROR = 0xFFFFFFFFC035003DLL,
    STATUS_HV_PROCESSOR_STARTUP_TIMEOUT = 0xFFFFFFFFC035003ELL,
    STATUS_HV_SMX_ENABLED = 0xFFFFFFFFC035003FLL,
    STATUS_HV_INVALID_LP_INDEX = 0xFFFFFFFFC0350041LL,
    STATUS_HV_INVALID_REGISTER_VALUE = 0xFFFFFFFFC0350050LL,
    STATUS_HV_INVALID_VTL_STATE = 0xFFFFFFFFC0350051LL,
    STATUS_HV_NX_NOT_DETECTED = 0xFFFFFFFFC0350055LL,
    STATUS_HV_INVALID_DEVICE_ID = 0xFFFFFFFFC0350057LL,
    STATUS_HV_INVALID_DEVICE_STATE = 0xFFFFFFFFC0350058LL,
    STATUS_HV_PENDING_PAGE_REQUESTS = 0x350059LL,
    STATUS_HV_PAGE_REQUEST_INVALID = 0xFFFFFFFFC0350060LL,
    STATUS_HV_INVALID_CPU_GROUP_ID = 0xFFFFFFFFC035006FLL,
    STATUS_HV_INVALID_CPU_GROUP_STATE = 0xFFFFFFFFC0350070LL,
    STATUS_HV_OPERATION_FAILED = 0xFFFFFFFFC0350071LL,
    STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE = 0xFFFFFFFFC0350072LL,
    STATUS_HV_INSUFFICIENT_ROOT_MEMORY = 0xFFFFFFFFC0350073LL,
    STATUS_HV_NOT_PRESENT = 0xFFFFFFFFC0351000LL,
    STATUS_VID_DUPLICATE_HANDLER = 0xFFFFFFFFC0370001LL,
    STATUS_VID_TOO_MANY_HANDLERS = 0xFFFFFFFFC0370002LL,
    STATUS_VID_QUEUE_FULL = 0xFFFFFFFFC0370003LL,
    STATUS_VID_HANDLER_NOT_PRESENT = 0xFFFFFFFFC0370004LL,
    STATUS_VID_INVALID_OBJECT_NAME = 0xFFFFFFFFC0370005LL,
    STATUS_VID_PARTITION_NAME_TOO_LONG = 0xFFFFFFFFC0370006LL,
    STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG = 0xFFFFFFFFC0370007LL,
    STATUS_VID_PARTITION_ALREADY_EXISTS = 0xFFFFFFFFC0370008LL,
    STATUS_VID_PARTITION_DOES_NOT_EXIST = 0xFFFFFFFFC0370009LL,
    STATUS_VID_PARTITION_NAME_NOT_FOUND = 0xFFFFFFFFC037000ALL,
    STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS = 0xFFFFFFFFC037000BLL,
    STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT = 0xFFFFFFFFC037000CLL,
    STATUS_VID_MB_STILL_REFERENCED = 0xFFFFFFFFC037000DLL,
    STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED = 0xFFFFFFFFC037000ELL,
    STATUS_VID_INVALID_NUMA_SETTINGS = 0xFFFFFFFFC037000FLL,
    STATUS_VID_INVALID_NUMA_NODE_INDEX = 0xFFFFFFFFC0370010LL,
    STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED = 0xFFFFFFFFC0370011LL,
    STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE = 0xFFFFFFFFC0370012LL,
    STATUS_VID_PAGE_RANGE_OVERFLOW = 0xFFFFFFFFC0370013LL,
    STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE = 0xFFFFFFFFC0370014LL,
    STATUS_VID_INVALID_GPA_RANGE_HANDLE = 0xFFFFFFFFC0370015LL,
    STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE = 0xFFFFFFFFC0370016LL,
    STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED = 0xFFFFFFFFC0370017LL,
    STATUS_VID_INVALID_PPM_HANDLE = 0xFFFFFFFFC0370018LL,
    STATUS_VID_MBPS_ARE_LOCKED = 0xFFFFFFFFC0370019LL,
    STATUS_VID_MESSAGE_QUEUE_CLOSED = 0xFFFFFFFFC037001ALL,
    STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED = 0xFFFFFFFFC037001BLL,
    STATUS_VID_STOP_PENDING = 0xFFFFFFFFC037001CLL,
    STATUS_VID_INVALID_PROCESSOR_STATE = 0xFFFFFFFFC037001DLL,
    STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT = 0xFFFFFFFFC037001ELL,
    STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED = 0xFFFFFFFFC037001FLL,
    STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET = 0xFFFFFFFFC0370020LL,
    STATUS_VID_MMIO_RANGE_DESTROYED = 0xFFFFFFFFC0370021LL,
    STATUS_VID_INVALID_CHILD_GPA_PAGE_SET = 0xFFFFFFFFC0370022LL,
    STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED = 0xFFFFFFFFC0370023LL,
    STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL = 0xFFFFFFFFC0370024LL,
    STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE = 0xFFFFFFFFC0370025LL,
    STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT = 0xFFFFFFFFC0370026LL,
    STATUS_VID_SAVED_STATE_CORRUPT = 0xFFFFFFFFC0370027LL,
    STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM = 0xFFFFFFFFC0370028LL,
    STATUS_VID_SAVED_STATE_INCOMPATIBLE = 0xFFFFFFFFC0370029LL,
    STATUS_VID_VTL_ACCESS_DENIED = 0xFFFFFFFFC037002ALL,
    STATUS_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED = 0xFFFFFFFF80370001LL,
    STATUS_IPSEC_BAD_SPI = 0xFFFFFFFFC0360001LL,
    STATUS_IPSEC_SA_LIFETIME_EXPIRED = 0xFFFFFFFFC0360002LL,
    STATUS_IPSEC_WRONG_SA = 0xFFFFFFFFC0360003LL,
    STATUS_IPSEC_REPLAY_CHECK_FAILED = 0xFFFFFFFFC0360004LL,
    STATUS_IPSEC_INVALID_PACKET = 0xFFFFFFFFC0360005LL,
    STATUS_IPSEC_INTEGRITY_CHECK_FAILED = 0xFFFFFFFFC0360006LL,
    STATUS_IPSEC_CLEAR_TEXT_DROP = 0xFFFFFFFFC0360007LL,
    STATUS_IPSEC_AUTH_FIREWALL_DROP = 0xFFFFFFFFC0360008LL,
    STATUS_IPSEC_THROTTLE_DROP = 0xFFFFFFFFC0360009LL,
    STATUS_IPSEC_DOSP_BLOCK = 0xFFFFFFFFC0368000LL,
    STATUS_IPSEC_DOSP_RECEIVED_MULTICAST = 0xFFFFFFFFC0368001LL,
    STATUS_IPSEC_DOSP_INVALID_PACKET = 0xFFFFFFFFC0368002LL,
    STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED = 0xFFFFFFFFC0368003LL,
    STATUS_IPSEC_DOSP_MAX_ENTRIES = 0xFFFFFFFFC0368004LL,
    STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED = 0xFFFFFFFFC0368005LL,
    STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES = 0xFFFFFFFFC0368006LL,
    STATUS_VOLMGR_INCOMPLETE_REGENERATION = 0xFFFFFFFF80380001LL,
    STATUS_VOLMGR_INCOMPLETE_DISK_MIGRATION = 0xFFFFFFFF80380002LL,
    STATUS_VOLMGR_DATABASE_FULL = 0xFFFFFFFFC0380001LL,
    STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED = 0xFFFFFFFFC0380002LL,
    STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC = 0xFFFFFFFFC0380003LL,
    STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED = 0xFFFFFFFFC0380004LL,
    STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME = 0xFFFFFFFFC0380005LL,
    STATUS_VOLMGR_DISK_DUPLICATE = 0xFFFFFFFFC0380006LL,
    STATUS_VOLMGR_DISK_DYNAMIC = 0xFFFFFFFFC0380007LL,
    STATUS_VOLMGR_DISK_ID_INVALID = 0xFFFFFFFFC0380008LL,
    STATUS_VOLMGR_DISK_INVALID = 0xFFFFFFFFC0380009LL,
    STATUS_VOLMGR_DISK_LAST_VOTER = 0xFFFFFFFFC038000ALL,
    STATUS_VOLMGR_DISK_LAYOUT_INVALID = 0xFFFFFFFFC038000BLL,
    STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS = 0xFFFFFFFFC038000CLL,
    STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED = 0xFFFFFFFFC038000DLL,
    STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL = 0xFFFFFFFFC038000ELL,
    STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS = 0xFFFFFFFFC038000FLL,
    STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS = 0xFFFFFFFFC0380010LL,
    STATUS_VOLMGR_DISK_MISSING = 0xFFFFFFFFC0380011LL,
    STATUS_VOLMGR_DISK_NOT_EMPTY = 0xFFFFFFFFC0380012LL,
    STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE = 0xFFFFFFFFC0380013LL,
    STATUS_VOLMGR_DISK_REVECTORING_FAILED = 0xFFFFFFFFC0380014LL,
    STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID = 0xFFFFFFFFC0380015LL,
    STATUS_VOLMGR_DISK_SET_NOT_CONTAINED = 0xFFFFFFFFC0380016LL,
    STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS = 0xFFFFFFFFC0380017LL,
    STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES = 0xFFFFFFFFC0380018LL,
    STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED = 0xFFFFFFFFC0380019LL,
    STATUS_VOLMGR_EXTENT_ALREADY_USED = 0xFFFFFFFFC038001ALL,
    STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS = 0xFFFFFFFFC038001BLL,
    STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION = 0xFFFFFFFFC038001CLL,
    STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED = 0xFFFFFFFFC038001DLL,
    STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION = 0xFFFFFFFFC038001ELL,
    STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH = 0xFFFFFFFFC038001FLL,
    STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED = 0xFFFFFFFFC0380020LL,
    STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID = 0xFFFFFFFFC0380021LL,
    STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS = 0xFFFFFFFFC0380022LL,
    STATUS_VOLMGR_MEMBER_IN_SYNC = 0xFFFFFFFFC0380023LL,
    STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE = 0xFFFFFFFFC0380024LL,
    STATUS_VOLMGR_MEMBER_INDEX_INVALID = 0xFFFFFFFFC0380025LL,
    STATUS_VOLMGR_MEMBER_MISSING = 0xFFFFFFFFC0380026LL,
    STATUS_VOLMGR_MEMBER_NOT_DETACHED = 0xFFFFFFFFC0380027LL,
    STATUS_VOLMGR_MEMBER_REGENERATING = 0xFFFFFFFFC0380028LL,
    STATUS_VOLMGR_ALL_DISKS_FAILED = 0xFFFFFFFFC0380029LL,
    STATUS_VOLMGR_NO_REGISTERED_USERS = 0xFFFFFFFFC038002ALL,
    STATUS_VOLMGR_NO_SUCH_USER = 0xFFFFFFFFC038002BLL,
    STATUS_VOLMGR_NOTIFICATION_RESET = 0xFFFFFFFFC038002CLL,
    STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID = 0xFFFFFFFFC038002DLL,
    STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID = 0xFFFFFFFFC038002ELL,
    STATUS_VOLMGR_PACK_DUPLICATE = 0xFFFFFFFFC038002FLL,
    STATUS_VOLMGR_PACK_ID_INVALID = 0xFFFFFFFFC0380030LL,
    STATUS_VOLMGR_PACK_INVALID = 0xFFFFFFFFC0380031LL,
    STATUS_VOLMGR_PACK_NAME_INVALID = 0xFFFFFFFFC0380032LL,
    STATUS_VOLMGR_PACK_OFFLINE = 0xFFFFFFFFC0380033LL,
    STATUS_VOLMGR_PACK_HAS_QUORUM = 0xFFFFFFFFC0380034LL,
    STATUS_VOLMGR_PACK_WITHOUT_QUORUM = 0xFFFFFFFFC0380035LL,
    STATUS_VOLMGR_PARTITION_STYLE_INVALID = 0xFFFFFFFFC0380036LL,
    STATUS_VOLMGR_PARTITION_UPDATE_FAILED = 0xFFFFFFFFC0380037LL,
    STATUS_VOLMGR_PLEX_IN_SYNC = 0xFFFFFFFFC0380038LL,
    STATUS_VOLMGR_PLEX_INDEX_DUPLICATE = 0xFFFFFFFFC0380039LL,
    STATUS_VOLMGR_PLEX_INDEX_INVALID = 0xFFFFFFFFC038003ALL,
    STATUS_VOLMGR_PLEX_LAST_ACTIVE = 0xFFFFFFFFC038003BLL,
    STATUS_VOLMGR_PLEX_MISSING = 0xFFFFFFFFC038003CLL,
    STATUS_VOLMGR_PLEX_REGENERATING = 0xFFFFFFFFC038003DLL,
    STATUS_VOLMGR_PLEX_TYPE_INVALID = 0xFFFFFFFFC038003ELL,
    STATUS_VOLMGR_PLEX_NOT_RAID5 = 0xFFFFFFFFC038003FLL,
    STATUS_VOLMGR_PLEX_NOT_SIMPLE = 0xFFFFFFFFC0380040LL,
    STATUS_VOLMGR_STRUCTURE_SIZE_INVALID = 0xFFFFFFFFC0380041LL,
    STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS = 0xFFFFFFFFC0380042LL,
    STATUS_VOLMGR_TRANSACTION_IN_PROGRESS = 0xFFFFFFFFC0380043LL,
    STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE = 0xFFFFFFFFC0380044LL,
    STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK = 0xFFFFFFFFC0380045LL,
    STATUS_VOLMGR_VOLUME_ID_INVALID = 0xFFFFFFFFC0380046LL,
    STATUS_VOLMGR_VOLUME_LENGTH_INVALID = 0xFFFFFFFFC0380047LL,
    STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE = 0xFFFFFFFFC0380048LL,
    STATUS_VOLMGR_VOLUME_NOT_MIRRORED = 0xFFFFFFFFC0380049LL,
    STATUS_VOLMGR_VOLUME_NOT_RETAINED = 0xFFFFFFFFC038004ALL,
    STATUS_VOLMGR_VOLUME_OFFLINE = 0xFFFFFFFFC038004BLL,
    STATUS_VOLMGR_VOLUME_RETAINED = 0xFFFFFFFFC038004CLL,
    STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID = 0xFFFFFFFFC038004DLL,
    STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE = 0xFFFFFFFFC038004ELL,
    STATUS_VOLMGR_BAD_BOOT_DISK = 0xFFFFFFFFC038004FLL,
    STATUS_VOLMGR_PACK_CONFIG_OFFLINE = 0xFFFFFFFFC0380050LL,
    STATUS_VOLMGR_PACK_CONFIG_ONLINE = 0xFFFFFFFFC0380051LL,
    STATUS_VOLMGR_NOT_PRIMARY_PACK = 0xFFFFFFFFC0380052LL,
    STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED = 0xFFFFFFFFC0380053LL,
    STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID = 0xFFFFFFFFC0380054LL,
    STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID = 0xFFFFFFFFC0380055LL,
    STATUS_VOLMGR_VOLUME_MIRRORED = 0xFFFFFFFFC0380056LL,
    STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED = 0xFFFFFFFFC0380057LL,
    STATUS_VOLMGR_NO_VALID_LOG_COPIES = 0xFFFFFFFFC0380058LL,
    STATUS_VOLMGR_PRIMARY_PACK_PRESENT = 0xFFFFFFFFC0380059LL,
    STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID = 0xFFFFFFFFC038005ALL,
    STATUS_VOLMGR_MIRROR_NOT_SUPPORTED = 0xFFFFFFFFC038005BLL,
    STATUS_VOLMGR_RAID5_NOT_SUPPORTED = 0xFFFFFFFFC038005CLL,
    STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED = 0xFFFFFFFF80390001LL,
    STATUS_BCD_TOO_MANY_ELEMENTS = 0xFFFFFFFFC0390002LL,
    STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED = 0xFFFFFFFF80390003LL,
    STATUS_VHD_DRIVE_FOOTER_MISSING = 0xFFFFFFFFC03A0001LL,
    STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH = 0xFFFFFFFFC03A0002LL,
    STATUS_VHD_DRIVE_FOOTER_CORRUPT = 0xFFFFFFFFC03A0003LL,
    STATUS_VHD_FORMAT_UNKNOWN = 0xFFFFFFFFC03A0004LL,
    STATUS_VHD_FORMAT_UNSUPPORTED_VERSION = 0xFFFFFFFFC03A0005LL,
    STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH = 0xFFFFFFFFC03A0006LL,
    STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION = 0xFFFFFFFFC03A0007LL,
    STATUS_VHD_SPARSE_HEADER_CORRUPT = 0xFFFFFFFFC03A0008LL,
    STATUS_VHD_BLOCK_ALLOCATION_FAILURE = 0xFFFFFFFFC03A0009LL,
    STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT = 0xFFFFFFFFC03A000ALL,
    STATUS_VHD_INVALID_BLOCK_SIZE = 0xFFFFFFFFC03A000BLL,
    STATUS_VHD_BITMAP_MISMATCH = 0xFFFFFFFFC03A000CLL,
    STATUS_VHD_PARENT_VHD_NOT_FOUND = 0xFFFFFFFFC03A000DLL,
    STATUS_VHD_CHILD_PARENT_ID_MISMATCH = 0xFFFFFFFFC03A000ELL,
    STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH = 0xFFFFFFFFC03A000FLL,
    STATUS_VHD_METADATA_READ_FAILURE = 0xFFFFFFFFC03A0010LL,
    STATUS_VHD_METADATA_WRITE_FAILURE = 0xFFFFFFFFC03A0011LL,
    STATUS_VHD_INVALID_SIZE = 0xFFFFFFFFC03A0012LL,
    STATUS_VHD_INVALID_FILE_SIZE = 0xFFFFFFFFC03A0013LL,
    STATUS_VIRTDISK_PROVIDER_NOT_FOUND = 0xFFFFFFFFC03A0014LL,
    STATUS_VIRTDISK_NOT_VIRTUAL_DISK = 0xFFFFFFFFC03A0015LL,
    STATUS_VHD_PARENT_VHD_ACCESS_DENIED = 0xFFFFFFFFC03A0016LL,
    STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH = 0xFFFFFFFFC03A0017LL,
    STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED = 0xFFFFFFFFC03A0018LL,
    STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT = 0xFFFFFFFFC03A0019LL,
    STATUS_VIRTUAL_DISK_LIMITATION = 0xFFFFFFFFC03A001ALL,
    STATUS_VHD_INVALID_TYPE = 0xFFFFFFFFC03A001BLL,
    STATUS_VHD_INVALID_STATE = 0xFFFFFFFFC03A001CLL,
    STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE = 0xFFFFFFFFC03A001DLL,
    STATUS_VIRTDISK_DISK_ALREADY_OWNED = 0xFFFFFFFFC03A001ELL,
    STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE = 0xFFFFFFFFC03A001FLL,
    STATUS_CTLOG_TRACKING_NOT_INITIALIZED = 0xFFFFFFFFC03A0020LL,
    STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE = 0xFFFFFFFFC03A0021LL,
    STATUS_CTLOG_VHD_CHANGED_OFFLINE = 0xFFFFFFFFC03A0022LL,
    STATUS_CTLOG_INVALID_TRACKING_STATE = 0xFFFFFFFFC03A0023LL,
    STATUS_CTLOG_INCONSISTENT_TRACKING_FILE = 0xFFFFFFFFC03A0024LL,
    STATUS_VHD_METADATA_FULL = 0xFFFFFFFFC03A0028LL,
    STATUS_VHD_INVALID_CHANGE_TRACKING_ID = 0xFFFFFFFFC03A0029LL,
    STATUS_VHD_CHANGE_TRACKING_DISABLED = 0xFFFFFFFFC03A002ALL,
    STATUS_VHD_MISSING_CHANGE_TRACKING_INFORMATION = 0xFFFFFFFFC03A0030LL,
    STATUS_VHD_RESIZE_WOULD_TRUNCATE_DATA = 0xFFFFFFFFC03A0031LL,
    STATUS_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE = 0xFFFFFFFFC03A0032LL,
    STATUS_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE = 0xFFFFFFFFC03A0033LL,
    STATUS_QUERY_STORAGE_ERROR = 0xFFFFFFFF803A0001LL,
    STATUS_GDI_HANDLE_LEAK = 0xFFFFFFFF803F0001LL,
    STATUS_RKF_KEY_NOT_FOUND = 0xFFFFFFFFC0400001LL,
    STATUS_RKF_DUPLICATE_KEY = 0xFFFFFFFFC0400002LL,
    STATUS_RKF_BLOB_FULL = 0xFFFFFFFFC0400003LL,
    STATUS_RKF_STORE_FULL = 0xFFFFFFFFC0400004LL,
    STATUS_RKF_FILE_BLOCKED = 0xFFFFFFFFC0400005LL,
    STATUS_RKF_ACTIVE_KEY = 0xFFFFFFFFC0400006LL,
    STATUS_RDBSS_RESTART_OPERATION = 0xFFFFFFFFC0410001LL,
    STATUS_RDBSS_CONTINUE_OPERATION = 0xFFFFFFFFC0410002LL,
    STATUS_RDBSS_POST_OPERATION = 0xFFFFFFFFC0410003LL,
    STATUS_RDBSS_RETRY_LOOKUP = 0xFFFFFFFFC0410004LL,
    STATUS_BTH_ATT_INVALID_HANDLE = 0xFFFFFFFFC0420001LL,
    STATUS_BTH_ATT_READ_NOT_PERMITTED = 0xFFFFFFFFC0420002LL,
    STATUS_BTH_ATT_WRITE_NOT_PERMITTED = 0xFFFFFFFFC0420003LL,
    STATUS_BTH_ATT_INVALID_PDU = 0xFFFFFFFFC0420004LL,
    STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION = 0xFFFFFFFFC0420005LL,
    STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED = 0xFFFFFFFFC0420006LL,
    STATUS_BTH_ATT_INVALID_OFFSET = 0xFFFFFFFFC0420007LL,
    STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION = 0xFFFFFFFFC0420008LL,
    STATUS_BTH_ATT_PREPARE_QUEUE_FULL = 0xFFFFFFFFC0420009LL,
    STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND = 0xFFFFFFFFC042000ALL,
    STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG = 0xFFFFFFFFC042000BLL,
    STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0xFFFFFFFFC042000CLL,
    STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH = 0xFFFFFFFFC042000DLL,
    STATUS_BTH_ATT_UNLIKELY = 0xFFFFFFFFC042000ELL,
    STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION = 0xFFFFFFFFC042000FLL,
    STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE = 0xFFFFFFFFC0420010LL,
    STATUS_BTH_ATT_INSUFFICIENT_RESOURCES = 0xFFFFFFFFC0420011LL,
    STATUS_BTH_ATT_UNKNOWN_ERROR = 0xFFFFFFFFC0421000LL,
    STATUS_SECUREBOOT_ROLLBACK_DETECTED = 0xFFFFFFFFC0430001LL,
    STATUS_SECUREBOOT_POLICY_VIOLATION = 0xFFFFFFFFC0430002LL,
    STATUS_SECUREBOOT_INVALID_POLICY = 0xFFFFFFFFC0430003LL,
    STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND = 0xFFFFFFFFC0430004LL,
    STATUS_SECUREBOOT_POLICY_NOT_SIGNED = 0xFFFFFFFFC0430005LL,
    STATUS_SECUREBOOT_NOT_ENABLED = 0xFFFFFFFF80430006LL,
    STATUS_SECUREBOOT_FILE_REPLACED = 0xFFFFFFFFC0430007LL,
    STATUS_SECUREBOOT_POLICY_NOT_AUTHORIZED = 0xFFFFFFFFC0430008LL,
    STATUS_SECUREBOOT_POLICY_UNKNOWN = 0xFFFFFFFFC0430009LL,
    STATUS_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION = 0xFFFFFFFFC043000ALL,
    STATUS_SECUREBOOT_PLATFORM_ID_MISMATCH = 0xFFFFFFFFC043000BLL,
    STATUS_SECUREBOOT_POLICY_ROLLBACK_DETECTED = 0xFFFFFFFFC043000CLL,
    STATUS_SECUREBOOT_POLICY_UPGRADE_MISMATCH = 0xFFFFFFFFC043000DLL,
    STATUS_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING = 0xFFFFFFFFC043000ELL,
    STATUS_SECUREBOOT_NOT_BASE_POLICY = 0xFFFFFFFFC043000FLL,
    STATUS_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY = 0xFFFFFFFFC0430010LL,
    STATUS_PLATFORM_MANIFEST_NOT_AUTHORIZED = 0xFFFFFFFFC0EB0001LL,
    STATUS_PLATFORM_MANIFEST_INVALID = 0xFFFFFFFFC0EB0002LL,
    STATUS_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED = 0xFFFFFFFFC0EB0003LL,
    STATUS_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED = 0xFFFFFFFFC0EB0004LL,
    STATUS_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND = 0xFFFFFFFFC0EB0005LL,
    STATUS_PLATFORM_MANIFEST_NOT_ACTIVE = 0xFFFFFFFFC0EB0006LL,
    STATUS_PLATFORM_MANIFEST_NOT_SIGNED = 0xFFFFFFFFC0EB0007LL,
    STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED = 0xFFFFFFFFC0E90001LL,
    STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION = 0xFFFFFFFFC0E90002LL,
    STATUS_SYSTEM_INTEGRITY_INVALID_POLICY = 0xFFFFFFFFC0E90003LL,
    STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED = 0xFFFFFFFFC0E90004LL,
    STATUS_NO_APPLICABLE_APP_LICENSES_FOUND = 0xFFFFFFFFC0EA0001LL,
    STATUS_CLIP_LICENSE_NOT_FOUND = 0xFFFFFFFFC0EA0002LL,
    STATUS_CLIP_DEVICE_LICENSE_MISSING = 0xFFFFFFFFC0EA0003LL,
    STATUS_CLIP_LICENSE_INVALID_SIGNATURE = 0xFFFFFFFFC0EA0004LL,
    STATUS_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID = 0xFFFFFFFFC0EA0005LL,
    STATUS_CLIP_LICENSE_EXPIRED = 0xFFFFFFFFC0EA0006LL,
    STATUS_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE = 0xFFFFFFFFC0EA0007LL,
    STATUS_CLIP_LICENSE_NOT_SIGNED = 0xFFFFFFFFC0EA0008LL,
    STATUS_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE = 0xFFFFFFFFC0EA0009LL,
    STATUS_CLIP_LICENSE_DEVICE_ID_MISMATCH = 0xFFFFFFFFC0EA000ALL,
    STATUS_AUDIO_ENGINE_NODE_NOT_FOUND = 0xFFFFFFFFC0440001LL,
    STATUS_HDAUDIO_EMPTY_CONNECTION_LIST = 0xFFFFFFFFC0440002LL,
    STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED = 0xFFFFFFFFC0440003LL,
    STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED = 0xFFFFFFFFC0440004LL,
    STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY = 0xFFFFFFFFC0440005LL,
    STATUS_SPACES_REPAIRED = 0xE70000LL,
    STATUS_SPACES_PAUSE = 0xE70001LL,
    STATUS_SPACES_COMPLETE = 0xE70002LL,
    STATUS_SPACES_REDIRECT = 0xE70003LL,
    STATUS_SPACES_FAULT_DOMAIN_TYPE_INVALID = 0xFFFFFFFFC0E70001LL,
    STATUS_SPACES_RESILIENCY_TYPE_INVALID = 0xFFFFFFFFC0E70003LL,
    STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID = 0xFFFFFFFFC0E70004LL,
    STATUS_SPACES_DRIVE_REDUNDANCY_INVALID = 0xFFFFFFFFC0E70006LL,
    STATUS_SPACES_NUMBER_OF_DATA_COPIES_INVALID = 0xFFFFFFFFC0E70007LL,
    STATUS_SPACES_INTERLEAVE_LENGTH_INVALID = 0xFFFFFFFFC0E70009LL,
    STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID = 0xFFFFFFFFC0E7000ALL,
    STATUS_SPACES_NOT_ENOUGH_DRIVES = 0xFFFFFFFFC0E7000BLL,
    STATUS_SPACES_EXTENDED_ERROR = 0xFFFFFFFFC0E7000CLL,
    STATUS_SPACES_PROVISIONING_TYPE_INVALID = 0xFFFFFFFFC0E7000DLL,
    STATUS_SPACES_ALLOCATION_SIZE_INVALID = 0xFFFFFFFFC0E7000ELL,
    STATUS_SPACES_ENCLOSURE_AWARE_INVALID = 0xFFFFFFFFC0E7000FLL,
    STATUS_SPACES_WRITE_CACHE_SIZE_INVALID = 0xFFFFFFFFC0E70010LL,
    STATUS_SPACES_NUMBER_OF_GROUPS_INVALID = 0xFFFFFFFFC0E70011LL,
    STATUS_SPACES_DRIVE_OPERATIONAL_STATE_INVALID = 0xFFFFFFFFC0E70012LL,
    STATUS_SPACES_UPDATE_COLUMN_STATE = 0xFFFFFFFFC0E70013LL,
    STATUS_SPACES_MAP_REQUIRED = 0xFFFFFFFFC0E70014LL,
    STATUS_SPACES_UNSUPPORTED_VERSION = 0xFFFFFFFFC0E70015LL,
    STATUS_SPACES_CORRUPT_METADATA = 0xFFFFFFFFC0E70016LL,
    STATUS_SPACES_DRT_FULL = 0xFFFFFFFFC0E70017LL,
    STATUS_SPACES_INCONSISTENCY = 0xFFFFFFFFC0E70018LL,
    STATUS_SPACES_LOG_NOT_READY = 0xFFFFFFFFC0E70019LL,
    STATUS_SPACES_NO_REDUNDANCY = 0xFFFFFFFFC0E7001ALL,
    STATUS_SPACES_DRIVE_NOT_READY = 0xFFFFFFFFC0E7001BLL,
    STATUS_SPACES_DRIVE_SPLIT = 0xFFFFFFFFC0E7001CLL,
    STATUS_SPACES_DRIVE_LOST_DATA = 0xFFFFFFFFC0E7001DLL,
    STATUS_SPACES_ENTRY_INCOMPLETE = 0xFFFFFFFFC0E7001ELL,
    STATUS_SPACES_ENTRY_INVALID = 0xFFFFFFFFC0E7001FLL,
    STATUS_VOLSNAP_BOOTFILE_NOT_VALID = 0xFFFFFFFFC0500003LL,
    STATUS_VOLSNAP_ACTIVATION_TIMEOUT = 0xFFFFFFFFC0500004LL,
    STATUS_IO_PREEMPTED = 0xFFFFFFFFC0510001LL,
    STATUS_SVHDX_ERROR_STORED = 0xFFFFFFFFC05C0000LL,
    STATUS_SVHDX_ERROR_NOT_AVAILABLE = 0xFFFFFFFFC05CFF00LL,
    STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE = 0xFFFFFFFFC05CFF01LL,
    STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED = 0xFFFFFFFFC05CFF02LL,
    STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED = 0xFFFFFFFFC05CFF03LL,
    STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED = 0xFFFFFFFFC05CFF04LL,
    STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED = 0xFFFFFFFFC05CFF05LL,
    STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED = 0xFFFFFFFFC05CFF06LL,
    STATUS_SVHDX_RESERVATION_CONFLICT = 0xFFFFFFFFC05CFF07LL,
    STATUS_SVHDX_WRONG_FILE_TYPE = 0xFFFFFFFFC05CFF08LL,
    STATUS_SVHDX_VERSION_MISMATCH = 0xFFFFFFFFC05CFF09LL,
    STATUS_VHD_SHARED = 0xFFFFFFFFC05CFF0ALL,
    STATUS_SVHDX_NO_INITIATOR = 0xFFFFFFFFC05CFF0BLL,
    STATUS_VHDSET_BACKING_STORAGE_NOT_FOUND = 0xFFFFFFFFC05CFF0CLL,
    STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP = 0xFFFFFFFFC05D0000LL,
    STATUS_SMB_BAD_CLUSTER_DIALECT = 0xFFFFFFFFC05D0001LL,
    STATUS_SMB_GUEST_LOGON_BLOCKED = 0xFFFFFFFFC05D0002LL,
    STATUS_SECCORE_INVALID_COMMAND = 0xFFFFFFFFC0E80000LL,
    STATUS_VSM_NOT_INITIALIZED = 0xFFFFFFFFC0450000LL,
    STATUS_VSM_DMA_PROTECTION_NOT_IN_USE = 0xFFFFFFFFC0450001LL,
    STATUS_APPEXEC_CONDITION_NOT_SATISFIED = 0xFFFFFFFFC0EC0000LL,
    STATUS_APPEXEC_HANDLE_INVALIDATED = 0xFFFFFFFFC0EC0001LL,
    STATUS_APPEXEC_INVALID_HOST_GENERATION = 0xFFFFFFFFC0EC0002LL,
    STATUS_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION = 0xFFFFFFFFC0EC0003LL,
    STATUS_APPEXEC_INVALID_HOST_STATE = 0xFFFFFFFFC0EC0004LL,
    STATUS_APPEXEC_NO_DONOR = 0xFFFFFFFFC0EC0005LL,
    STATUS_APPEXEC_HOST_ID_MISMATCH = 0xFFFFFFFFC0EC0006LL,
    STATUS_APPEXEC_UNKNOWN_USER = 0xFFFFFFFFC0EC0007LL,
};