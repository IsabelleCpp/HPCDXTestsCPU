#pragma once
struct _GENERIC_MAPPING;
struct _nlsversioninfo;
struct _OVERLAPPED;
struct _SECURITY_ATTRIBUTES;
struct HKEY__;
struct _FILETIME;
struct _STARTUPINFOW;
struct _PROCESS_INFORMATION;
struct _STARTUPINFOA;
struct tagACTCTX_SECTION_KEYED_DATA;
struct _REASON_CONTEXT;
struct HINSTANCE__;
struct _OBJECT_TYPE_LIST;
struct _GUID;
struct _PRIVILEGE_SET;
struct _ACL;
struct _TOKEN_PRIVILEGES;
struct _SID_AND_ATTRIBUTES;
struct _TOKEN_GROUPS;
struct _SMALL_RECT;
struct _CONSOLE_READCONSOLE_CONTROL;
struct _MAPPING_OPTIONS;
struct _MAPPING_PROPERTY_BAG;
struct _MAPPING_DATA_RANGE;
struct _UNICODE_STRING;
struct _RTL_CRITICAL_SECTION_DEBUG;
struct _EVENT_DESCRIPTOR;
struct _EVENT_DATA_DESCRIPTOR;
struct _RTLP_CURDIR_REF;
union _LARGE_INTEGER;
struct tagPARSEDURLW;
struct _MESSAGE_RESOURCE_ENTRY;
struct _RTL_HANDLE_TABLE_ENTRY;
struct _IMAGE_NT_HEADERS64;
struct _ACTIVATION_CONTEXT_STACK;
struct _TEB;
struct _EXCEPTION_REGISTRATION_RECORD;
struct _CONTEXT;
struct _PEB;
struct _PEB_LDR_DATA;
struct _RTL_USER_PROCESS_PARAMETERS;
struct _PEB_FREE_BLOCK;
struct _ACTIVATION_CONTEXT_DATA;
struct _TEB_ACTIVE_FRAME;
struct _TEB_ACTIVE_FRAME_CONTEXT;
struct _CSR_CAPTURE_BUFFER;
struct _IMAGE_RESOURCE_DATA_ENTRY;
struct _EVENT_FILTER_DESCRIPTOR;
struct _WSAPROTOCOL_INFOW;
struct _RUNTIME_FUNCTION;
struct _KNONVOLATILE_CONTEXT_POINTERS;
struct _RTL_SRWLOCK;
struct tagPARSEDURLA;
struct _RTL_AVL_TABLE;
struct IOleClientSite;
struct IOleClientSiteVtbl;
struct IMoniker;
struct IMonikerVtbl;
struct IBindCtx;
struct IBindCtxVtbl;
struct IUnknown;
struct IUnknownVtbl;
struct tagBIND_OPTS;
struct IRunningObjectTable;
struct IRunningObjectTableVtbl;
struct IEnumMoniker;
struct IEnumMonikerVtbl;
struct IEnumString;
struct IEnumStringVtbl;
struct IOleContainer;
struct IOleContainerVtbl;
struct IEnumUnknown;
struct IEnumUnknownVtbl;
struct IStorage;
struct IStorageVtbl;
struct IEnumSTATSTG;
struct IEnumSTATSTGVtbl;
struct wavefilter_tag;
struct _PROPERTY_DATA_DESCRIPTOR;

/* 1 */
typedef int BOOL;

/* 2 */
typedef unsigned int DWORD;

/* 4 */
typedef wchar_t WCHAR;

/* 3 */
typedef WCHAR* LPWSTR;

/* 6 */
typedef DWORD* LPDWORD;

/* 7 */
typedef void* HANDLE;

/* 9 */
typedef struct _GENERIC_MAPPING GENERIC_MAPPING;

/* 8 */
typedef GENERIC_MAPPING* PGENERIC_MAPPING;

/* 11 */
typedef DWORD ACCESS_MASK;

/* 10 */
struct _GENERIC_MAPPING
{
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
};

/* 12 */
typedef const WCHAR* LPCWSTR;

/* 13 */
typedef unsigned int ULONG;

/* 14 */
typedef const WCHAR* PCWSTR;

/* 15 */
typedef ULONG* PULONG;

/* 16 */
typedef void* LPVOID;

/* 17 */
typedef DWORD CALTYPE;

/* 19 */
typedef __int64 LONG_PTR;

/* 18 */
typedef LONG_PTR LPARAM;

/* 20 */
typedef struct _nlsversioninfo* LPNLSVERSIONINFO;

/* 21 */
struct _nlsversioninfo
{
    DWORD dwNLSVersionInfoSize;
    DWORD dwNLSVersion;
    DWORD dwDefinedVersion;
};

/* 23 */
typedef char CHAR;

/* 22 */
typedef const CHAR* PCNZCH;

/* 24 */
typedef const WCHAR* PCNZWCH;

/* 26 */
typedef unsigned __int16 WORD;

/* 25 */
typedef WORD* LPWORD;

/* 27 */
typedef const WCHAR* LPCWCH;

/* 28 */
typedef struct _OVERLAPPED* LPOVERLAPPED;

/* 30 */
typedef unsigned __int64 ULONG_PTR;

/* 33 */
typedef void* PVOID;

/* 29 */
struct _OVERLAPPED
{
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union
    {
        struct
        {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
};

/* 34 */
typedef DWORD* PDWORD;

/* 35 */
typedef ACCESS_MASK REGSAM;

/* 36 */
typedef struct _SECURITY_ATTRIBUTES* LPSECURITY_ATTRIBUTES;

/* 37 */
struct _SECURITY_ATTRIBUTES
{
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

/* 39 */
typedef struct HKEY__* HKEY;

/* 38 */
typedef HKEY* PHKEY;

/* 40 */
struct HKEY__
{
    int unused;
};

/* 41 */
typedef struct _FILETIME* PFILETIME;

/* 42 */
struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

/* 44 */
typedef unsigned __int8 BYTE;

/* 43 */
typedef BYTE* LPBYTE;

/* 45 */
typedef const void* LPCVOID;

/* 46 */
typedef CHAR* LPSTR;

/* 47 */
typedef struct _PROC_THREAD_ATTRIBUTE_LIST* LPPROC_THREAD_ATTRIBUTE_LIST;

/* 48 */
typedef struct _STARTUPINFOW* LPSTARTUPINFOW;

/* 49 */
struct _STARTUPINFOW
{
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

/* 50 */
typedef struct _PROCESS_INFORMATION* LPPROCESS_INFORMATION;

/* 51 */
struct _PROCESS_INFORMATION
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

/* 52 */
typedef const CHAR* LPCSTR;

/* 53 */
typedef struct _STARTUPINFOA* LPSTARTUPINFOA;

/* 54 */
struct _STARTUPINFOA
{
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

/* 55 */
typedef const CHAR* LPCCH;

/* 56 */
typedef BOOL* LPBOOL;

/* 57 */
typedef WORD LANGID;

/* 58 */
typedef int* LPINT;

/* 59 */
typedef struct tagACTCTX_SECTION_KEYED_DATA* PACTCTX_SECTION_KEYED_DATA;

/* 62 */
struct tagACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA
{
    PVOID lpInformation;
    PVOID lpSectionBase;
    ULONG ulSectionLength;
    PVOID lpSectionGlobalDataBase;
    ULONG ulSectionGlobalDataLength;
};

/* 61 */
typedef struct tagACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA;

/* 60 */
struct tagACTCTX_SECTION_KEYED_DATA
{
    ULONG cbSize;
    ULONG ulDataFormatVersion;
    PVOID lpData;
    ULONG ulLength;
    PVOID lpSectionGlobalData;
    ULONG ulSectionGlobalDataLength;
    PVOID lpSectionBase;
    ULONG ulSectionTotalLength;
    HANDLE hActCtx;
    ULONG ulAssemblyRosterIndex;
    ULONG ulFlags;
    ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA AssemblyMetadata;
};

/* 63 */
typedef struct _REASON_CONTEXT* PREASON_CONTEXT;

/* 68 */
typedef struct HINSTANCE__* HINSTANCE;

/* 67 */
typedef HINSTANCE HMODULE;

/* Detailed information for a reason context */
typedef struct _REASON_CONTEXT_DETAILED {
    HMODULE LocalizedReasonModule;
    ULONG   LocalizedReasonId;
    ULONG   ReasonStringCount;
    LPWSTR* ReasonStrings;
} REASON_CONTEXT_DETAILED;

/* A union representing either a detailed or a simple reason string */
typedef union _REASON_CONTEXT_UNION {
    REASON_CONTEXT_DETAILED Detailed;
    LPWSTR               SimpleReasonString;
} REASON_CONTEXT_UNION;

/* The main REASON_CONTEXT structure */
typedef struct _REASON_CONTEXT {
    ULONG Version;
    DWORD Flags;
    REASON_CONTEXT_UNION Reason;
} REASON_CONTEXT;

/* 69 */
struct HINSTANCE__
{
    int unused;
};

/* 70 */
typedef ULONG_PTR SIZE_T;

/* 71 */
typedef struct _FILETIME* LPFILETIME;

/* 72 */
typedef struct _OBJECT_TYPE_LIST* POBJECT_TYPE_LIST;

/* 74 */
typedef struct _GUID GUID;

/* 73 */
struct _OBJECT_TYPE_LIST
{
    WORD Level;
    WORD Sbz;
    GUID* ObjectType;
};

/* 75 */
struct _GUID
{
    unsigned int Data1;
    unsigned __int16 Data2;
    unsigned __int16 Data3;
    unsigned __int8 Data4[8];
};

/* 76 */
typedef struct _PRIVILEGE_SET* PPRIVILEGE_SET;

/* 82 */
typedef int LONG;

/* 81 */
struct _LUID
{
    DWORD LowPart;
    LONG HighPart;
};

/* 80 */
typedef struct _LUID LUID;

/* 79 */
#pragma pack(push, 4)
struct _LUID_AND_ATTRIBUTES
{
    LUID Luid;
    DWORD Attributes;
};
#pragma pack(pop)

/* 78 */
typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

/* 77 */
struct _PRIVILEGE_SET
{
    DWORD PrivilegeCount;
    DWORD Control;
    LUID_AND_ATTRIBUTES Privilege[1];
};

/* 84 */
enum _TOKEN_TYPE
{
    TokenPrimary = 0x1,
    TokenImpersonation = 0x2,
};

/* 83 */
typedef enum _TOKEN_TYPE TOKEN_TYPE;

/* 85 */
typedef HANDLE* PHANDLE;

/* 86 */
typedef PVOID PSECURITY_DESCRIPTOR;

/* 88 */
typedef struct _ACL ACL;

/* 87 */
typedef ACL* PACL;

/* 89 */
struct _ACL
{
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

/* 90 */
typedef PVOID PSID;

/* 92 */
enum $4218CD2CD980A290FF820393F4F33E3B
{
    SHREGENUM_DEFAULT = 0x0,
    SHREGENUM_HKCU = 0x1,
    SHREGENUM_HKLM = 0x10,
    SHREGENUM_BOTH = 0x11,
};

/* 91 */
typedef enum $4218CD2CD980A290FF820393F4F33E3B SHREGENUM_FLAGS;

/* 93 */
typedef WCHAR* PWSTR;

/* 94 */
typedef void(__stdcall* LPOVERLAPPED_COMPLETION_ROUTINE)(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped);

/* 95 */
typedef struct _TOKEN_PRIVILEGES* PTOKEN_PRIVILEGES;

/* 96 */
struct _TOKEN_PRIVILEGES
{
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

/* 97 */
typedef ULONG_PTR* PSIZE_T;

/* 99 */
typedef unsigned __int64 ULONGLONG;

/* 98 */
typedef ULONGLONG* PULONGLONG;

/* 100 */
typedef struct _LUID_AND_ATTRIBUTES* PLUID_AND_ATTRIBUTES;

/* 101 */
typedef struct _SID_AND_ATTRIBUTES* PSID_AND_ATTRIBUTES;

/* 102 */
struct _SID_AND_ATTRIBUTES
{
    PSID Sid;
    DWORD Attributes;
};

/* 103 */
typedef struct _TOKEN_GROUPS* PTOKEN_GROUPS;

/* 105 */
typedef struct _SID_AND_ATTRIBUTES SID_AND_ATTRIBUTES;

/* 104 */
struct _TOKEN_GROUPS
{
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
};

/* 106 */
typedef struct _SMALL_RECT* PSMALL_RECT;

/* 108 */
typedef __int16 SHORT;

/* 107 */
struct _SMALL_RECT
{
    SHORT Left;
    SHORT Top;
    SHORT Right;
    SHORT Bottom;
};

/* 109 */
typedef unsigned int* PUINT;

/* 110 */
typedef int INT;

/* 111 */
typedef struct _CONSOLE_READCONSOLE_CONTROL* PCONSOLE_READCONSOLE_CONTROL;

/* 112 */
struct _CONSOLE_READCONSOLE_CONTROL
{
    ULONG nLength;
    ULONG nInitialChars;
    ULONG dwCtrlWakeupMask;
    ULONG dwControlKeyState;
};

/* 114 */
enum _AUDIT_EVENT_TYPE
{
    AuditEventObjectAccess = 0x0,
    AuditEventDirectoryServiceAccess = 0x1,
};

/* 113 */
typedef enum _AUDIT_EVENT_TYPE AUDIT_EVENT_TYPE;

/* 115 */
typedef BYTE BOOLEAN;

/* 116 */
typedef char* va_list;

/* 118 */
enum _SID_NAME_USE
{
    SidTypeUser = 0x1,
    SidTypeGroup = 0x2,
    SidTypeDomain = 0x3,
    SidTypeAlias = 0x4,
    SidTypeWellKnownGroup = 0x5,
    SidTypeDeletedAccount = 0x6,
    SidTypeInvalid = 0x7,
    SidTypeUnknown = 0x8,
    SidTypeComputer = 0x9,
    SidTypeLabel = 0xA,
    SidTypeLogonSession = 0xB,
};

/* 117 */
typedef enum _SID_NAME_USE* PSID_NAME_USE;

/* 119 */
typedef ULONG PROPID;

/* 120 */
typedef struct _MAPPING_OPTIONS* PMAPPING_OPTIONS;

/* 122 */
typedef unsigned __int64 size_t;

/* 127 */
typedef int HRESULT;

/* 123 */
typedef void(__stdcall* PFN_MAPPINGCALLBACKPROC)(struct _MAPPING_PROPERTY_BAG* pBag, LPVOID data, DWORD dwDataSize, HRESULT Result);

/* 121 */
struct _MAPPING_OPTIONS
{
    size_t Size;
    LPWSTR pszInputLanguage;
    LPWSTR pszOutputLanguage;
    LPWSTR pszInputScript;
    LPWSTR pszOutputScript;
    LPWSTR pszInputContentType;
    LPWSTR pszOutputContentType;
    LPWSTR pszUILanguage;
    PFN_MAPPINGCALLBACKPROC pfnRecognizeCallback;
    LPVOID pRecognizeCallerData;
    DWORD dwRecognizeCallerDataSize;
    PFN_MAPPINGCALLBACKPROC pfnActionCallback;
    LPVOID pActionCallerData;
    DWORD dwActionCallerDataSize;
    DWORD dwServiceFlag;
    unsigned __int32 GetActionDisplayName : 1;
};

/* 125 */
typedef struct _MAPPING_DATA_RANGE* PMAPPING_DATA_RANGE;

/* 124 */
struct _MAPPING_PROPERTY_BAG
{
    size_t Size;
    PMAPPING_DATA_RANGE prgResultRanges;
    DWORD dwRangesCount;
    LPVOID pServiceData;
    DWORD dwServiceDataSize;
    LPVOID pCallerData;
    DWORD dwCallerDataSize;
    LPVOID pContext;
};

/* 126 */
struct _MAPPING_DATA_RANGE
{
    DWORD dwStartIndex;
    DWORD dwEndIndex;
    LPWSTR pszDescription;
    DWORD dwDescriptionLength;
    LPVOID pData;
    DWORD dwDataSize;
    LPWSTR pszContentType;
    LPWSTR* prgActionIds;
    DWORD dwActionsCount;
    LPWSTR* prgActionDisplayNames;
};

/* 128 */
typedef struct _MAPPING_PROPERTY_BAG* PMAPPING_PROPERTY_BAG;

/* 129 */
typedef BOOL* PBOOL;

/* 130 */
typedef unsigned int UINT;

/* 131 */
typedef ULONG_PTR DWORD_PTR;

/* 133 */
typedef unsigned int UINT32;

/* 134 */
typedef unsigned __int16 UINT16;

/* 135 */
typedef unsigned __int8 UINT8;

/* 136 */
typedef unsigned __int64 UINT64;

/* 132 */
struct _TraceLoggingMetadata_t
{
    UINT32 Signature;
    UINT16 Size;
    UINT8 Version;
    UINT8 Flags;
    UINT64 Magic;
};

/* 137 */
struct RUNTIME_FUNCTION
{
    void* __ptr32 FunctionStart;
    void* __ptr32 FunctionEnd;
    void* __ptr32 UnwindInfo;
};

/* 138 */
struct UNWIND_INFO_HDR
{
    unsigned __int8 Version : 3;
    unsigned __int8 Flags : 5;
    unsigned __int8 PrologSize;
    unsigned __int8 CntUnwindCodes;
    unsigned __int8 FrameRegister : 4;
    unsigned __int8 FrameOffset : 4;
};

/* 139 */
struct UNWIND_CODE
{
    char PrologOff;
    unsigned __int8 UnwindOp : 4;
    unsigned __int8 OpInfo : 4;
};

/* 140 */
struct C_SCOPE_TABLE
{
    void* __ptr32 Begin;
    void* __ptr32 End;
    void* __ptr32 Handler;
    void* __ptr32 Target;
};

/* 141 */
typedef const CHAR* PCSTR;

/* 142 */
typedef struct _UNICODE_STRING UNICODE_STRING;

/* 144 */
typedef unsigned __int16 USHORT;

/* 143 */
struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

/* 146 */
typedef struct _RTL_CRITICAL_SECTION_DEBUG* PRTL_CRITICAL_SECTION_DEBUG;

/* 145 */
#pragma pack(push, 8)
struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};
#pragma pack(pop)

/* 149 */
struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
};

/* 148 */
typedef struct _LIST_ENTRY LIST_ENTRY;

/* 147 */
struct _RTL_CRITICAL_SECTION_DEBUG
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

/* 151 */
typedef struct _UNICODE_STRING* PUNICODE_STRING;

/* 150 */
struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

/* 152 */
union _RTL_RUN_ONCE
{
    PVOID Ptr;
};

/* 153 */
typedef struct _EVENT_DESCRIPTOR EVENT_DESCRIPTOR;

/* 155 */
typedef unsigned __int8 UCHAR;

/* 154 */
struct _EVENT_DESCRIPTOR
{
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
};

/* 156 */
typedef struct _EVENT_DATA_DESCRIPTOR* PEVENT_DATA_DESCRIPTOR;

/* 157 */
struct _EVENT_DATA_DESCRIPTOR
{
    ULONGLONG Ptr;
    ULONG Size;
    union
    {
        ULONG Reserved;
        struct
        {
            UCHAR Type;
            UCHAR Reserved1;
            USHORT Reserved2;
        };
    };
};

/* 160 */
struct _SID_IDENTIFIER_AUTHORITY
{
    BYTE Value[6];
};

/* 161 */
enum PackageOrigin
{
    PackageOrigin_Unknown = 0x0,
    PackageOrigin_Unsigned = 0x1,
    PackageOrigin_Inbox = 0x2,
    PackageOrigin_Store = 0x3,
    PackageOrigin_DeveloperUnsigned = 0x4,
    PackageOrigin_DeveloperSigned = 0x5,
    PackageOrigin_LineOfBusiness = 0x6,
};

/* 162 */
typedef HANDLE HLOCAL;

/* 164 */
typedef struct _FILETIME FILETIME;

/* 163 */
struct _BY_HANDLE_FILE_INFORMATION
{
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
};

/* 167 */
typedef int NTSTATUS;

/* 165 */
struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
};

/* 169 */
enum _FSINFOCLASS
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
    FileFsMaximumInformation = 0xA,
};

/* 168 */
typedef enum _FSINFOCLASS FS_INFORMATION_CLASS;

/* 171 */
enum _FILE_INFORMATION_CLASS
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
    FileMaximumInformation = 0x38,
};

/* 170 */
typedef enum _FILE_INFORMATION_CLASS FILE_INFORMATION_CLASS;

/* 173 */
typedef struct _RTLP_CURDIR_REF* PRTLP_CURDIR_REF;

/* 172 */
struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
};

/* 174 */
struct _RTLP_CURDIR_REF
{
    LONG RefCount;
    HANDLE Handle;
};

/* 175 */
typedef union _LARGE_INTEGER* PLARGE_INTEGER;

/* 178 */
typedef __int64 LONGLONG;

union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
};

/* 180 */
enum _SECTION_INHERIT
{
    ViewShare = 0x1,
    ViewUnmap = 0x2,
};

/* 179 */
typedef enum _SECTION_INHERIT SECTION_INHERIT;

/* 181 */
typedef WCHAR* LPWCH;

/* 183 */
typedef CHAR* PCHAR;

/* 182 */
struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
};

/* 185 */
typedef __int16 CSHORT;

/* 184 */
struct _TIME_FIELDS
{
    CSHORT Year;
    CSHORT Month;
    CSHORT Day;
    CSHORT Hour;
    CSHORT Minute;
    CSHORT Second;
    CSHORT Milliseconds;
    CSHORT Weekday;
};

/* 188 */
struct _SYSTEMTIME
{
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

/* 187 */
typedef struct _SYSTEMTIME SYSTEMTIME;

/* 186 */
struct _TIME_DYNAMIC_ZONE_INFORMATION
{
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
    WCHAR TimeZoneKeyName[128];
    BOOLEAN DynamicDaylightTimeDisabled;
};

/* 189 */
typedef wchar_t* STRSAFE_LPWSTR;

/* 190 */
typedef struct _IO_STATUS_BLOCK* PIO_STATUS_BLOCK;

/* 194 */
typedef PVOID PACTIVATION_CONTEXT;

/* 193 */
struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
};

/* 192 */
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME RTL_ACTIVATION_CONTEXT_STACK_FRAME;

/* 191 */
struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
    PVOID Extra1;
    PVOID Extra2;
    PVOID Extra3;
    PVOID Extra4;
};

/* 195 */
typedef struct tagPARSEDURLW PARSEDURLW;

/* 196 */
#pragma pack(push, 8)
struct tagPARSEDURLW
{
    DWORD cbSize;
    LPCWSTR pszProtocol;
    UINT cchProtocol;
    LPCWSTR pszSuffix;
    UINT cchSuffix;
    UINT nScheme;
};
#pragma pack(pop)

/* 197 */
typedef struct _MESSAGE_RESOURCE_ENTRY* PMESSAGE_RESOURCE_ENTRY;

/* 198 */
struct _MESSAGE_RESOURCE_ENTRY
{
    WORD Length;
    WORD Flags;
    BYTE Text[1];
};

/* 200 */
typedef struct _RTL_HANDLE_TABLE_ENTRY* PRTL_HANDLE_TABLE_ENTRY;

/* 199 */
struct _RTL_HANDLE_TABLE
{
    ULONG MaximumNumberOfHandles;
    ULONG SizeOfHandleTableEntry;
    ULONG Reserved[2];
    PRTL_HANDLE_TABLE_ENTRY FreeHandles;
    PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
};

/* 201 */
struct _RTL_HANDLE_TABLE_ENTRY
{
    union
    {
        ULONG Flags;
        struct _RTL_HANDLE_TABLE_ENTRY* NextFree;
    };
};

/* 204 */
typedef struct _IMAGE_NT_HEADERS64* PIMAGE_NT_HEADERS64;

/* 203 */
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;

/* 207 */
struct _IMAGE_FILE_HEADER
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
};

/* 206 */
typedef struct _IMAGE_FILE_HEADER IMAGE_FILE_HEADER;

/* 211 */
struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;
    DWORD Size;
};

/* 210 */
typedef struct _IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY;

/* 209 */
struct _IMAGE_OPTIONAL_HEADER64
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

/* 208 */
typedef struct _IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64;

/* 205 */
struct _IMAGE_NT_HEADERS64
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

/* 213 */
typedef union _LARGE_INTEGER LARGE_INTEGER;

/* 212 */
struct _FILE_BASIC_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
};

/* 214 */
struct _FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
};

/* 215 */
typedef struct _OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

/* 216 */
struct _SYSTEM_INFO
{
    union
    {
        DWORD dwOemId;
        struct
        {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

/* 219 */
struct _EXCEPTION_RECORD
{
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

/* 220 */
typedef struct _ACTIVATION_CONTEXT_STACK* PACTIVATION_CONTEXT_STACK;

/* 221 */
struct _ACTIVATION_CONTEXT_STACK
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
};

/* 222 */
typedef struct _TEB* PTEB;

/* 225 */
struct _NT_TIB
{
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union
    {
        PVOID FiberData;
        DWORD Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB* Self;
};

/* 224 */
typedef struct _NT_TIB NT_TIB;

/* 241 */
struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

/* 240 */
typedef struct _CLIENT_ID CLIENT_ID;

/* 242 */
typedef struct _PEB* PPEB;

/* 263 */
typedef DWORD LCID;

/* 265 */
struct _GDI_TEB_BATCH
{
    ULONG Offset;
    HANDLE HDC;
    ULONG Buffer[310];
};

/* 264 */
typedef struct _GDI_TEB_BATCH GDI_TEB_BATCH;

/* 268 */
struct _PROCESSOR_NUMBER
{
    WORD Group;
    BYTE Number;
    BYTE Reserved;
};

/* 267 */
typedef struct _PROCESSOR_NUMBER PROCESSOR_NUMBER;

/* 269 */
typedef unsigned int ULONG32;

/* 271 */
typedef struct _TEB_ACTIVE_FRAME* PTEB_ACTIVE_FRAME;

/* 223 */
struct _TEB
{
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    LONG ExceptionCode;
    UCHAR Padding0[4];
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    UCHAR SpareBytes[24];
    ULONG TxFsContext;
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    PVOID GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    SIZE_T Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    SIZE_T glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UCHAR Padding2[4];
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    UCHAR Padding3[6];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorMode;
    UCHAR Padding4[4];
    PVOID Instrumentation[11];
    GUID ActivityId;
    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG32 IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };
    ULONG GuaranteedStackBytes;
    UCHAR Padding5[4];
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    UCHAR Padding6[4];
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    ULONG_PTR ThreadPoolData;
    PVOID* TlsExpansionSlots;
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
    ULONG ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    UCHAR Padding7[4];
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        USHORT CrossTebFlags;
        struct
        {
            unsigned __int16 SpareCrossTebBits : 16;
        };
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            unsigned __int16 DbgSafeThunkCall : 1;
            unsigned __int16 DbgInDebugPrint : 1;
            unsigned __int16 DbgHasFiberData : 1;
            unsigned __int16 DbgSkipThreadAttach : 1;
            unsigned __int16 DbgWerInShipAssertCode : 1;
            unsigned __int16 DbgIssuedInitialBp : 1;
            unsigned __int16 DbgClonedThread : 1;
            unsigned __int16 SpareSameTebBits : 9;
        };
    };
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
};

/* 238 */
enum _EXCEPTION_DISPOSITION
{
    ExceptionContinueExecution = 0x0,
    ExceptionContinueSearch = 0x1,
    ExceptionNestedException = 0x2,
    ExceptionCollidedUnwind = 0x3,
};

/* 237 */
typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

/* 228 */
typedef EXCEPTION_DISPOSITION __stdcall EXCEPTION_ROUTINE(struct _EXCEPTION_RECORD* ExceptionRecord, PVOID EstablisherFrame, struct _CONTEXT* ContextRecord, PVOID DispatcherContext);

/* 227 */
typedef EXCEPTION_ROUTINE* PEXCEPTION_ROUTINE;

/* 226 */
struct _EXCEPTION_REGISTRATION_RECORD
{
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    PEXCEPTION_ROUTINE Handler;
};

/* 246 */
typedef struct _PEB_LDR_DATA* PPEB_LDR_DATA;

/* 256 */
typedef struct _PEB_FREE_BLOCK* PPEB_FREE_BLOCK;

/* 258 */
typedef NTSTATUS(*PPOST_PROCESS_INIT_ROUTINE)(void);

/* 260 */
union _ULARGE_INTEGER
{
    struct
    {
        DWORD LowPart;
        DWORD HighPart;
    };
    union {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
};

/* 259 */
typedef union _ULARGE_INTEGER ULARGE_INTEGER;

/* 243 */
struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            unsigned __int8 ImageUsesLargePages : 1;
            unsigned __int8 IsProtectedProcess : 1;
            unsigned __int8 IsLegacyProcess : 1;
            unsigned __int8 IsImageDynamicallyRelocated : 1;
            unsigned __int8 SkipPatchingUser32Forwarders : 1;
            unsigned __int8 SpareBits : 3;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    struct _RTL_CRITICAL_SECTION* FastPebLock;
    PVOID AltThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            unsigned __int32 ProcessInJob : 1;
            unsigned __int32 ProcessInitializing : 1;
            unsigned __int32 ProcessUsingVEH : 1;
            unsigned __int32 ProcessUsingVCH : 1;
            unsigned __int32 ReservedBits0 : 28;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG_PTR HeapSegmentReserve;
    ULONG_PTR HeapSegmentCommit;
    ULONG_PTR HeapDeCommitTotalFreeThreshold;
    ULONG_PTR HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    struct _RTL_CRITICAL_SECTION* LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PPOST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    ULONG_PTR MinimumStackCommit;
    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[4];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
};

/* 273 */
typedef const struct _TEB_ACTIVE_FRAME_CONTEXT* PCTEB_ACTIVE_FRAME_CONTEXT;

/* 272 */
struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PCTEB_ACTIVE_FRAME_CONTEXT Context;
};

/* 230 */
typedef unsigned __int64 DWORD64;

/* 235 */
struct __declspec(align(16)) _M128A
{
    ULONGLONG Low;
    LONGLONG High;
};

/* 234 */
typedef struct _M128A M128A;

/* 233 */
struct _XMM_SAVE_AREA32
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

/* 232 */
typedef struct _XMM_SAVE_AREA32 XMM_SAVE_AREA32;

/* 229 */
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

/* 247 */
struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    UCHAR ShutdownInProgress;
    PVOID ShutdownThreadId;
};

/* 250 */
struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
};

/* 249 */
typedef struct _CURDIR CURDIR;

/* 252 */
struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
};

/* 251 */
typedef struct _RTL_DRIVE_LETTER_CURDIR RTL_DRIVE_LETTER_CURDIR;

/* 248 */
struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWSTR Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    SIZE_T EnvironmentSize;
    SIZE_T EnvironmentVersion;
};

/* 257 */
struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;
};

/* 262 */
struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;
    ULONG ExtendedTocOffset;
    ULONG AssemblyRosterOffset;
    ULONG Flags;
};

/* 274 */
struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    LPSTR FrameName;
};

/* 280 */
enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown = 0x0,
    RtlPathTypeUncAbsolute = 0x1,
    RtlPathTypeDriveAbsolute = 0x2,
    RtlPathTypeDriveRelative = 0x3,
    RtlPathTypeRooted = 0x4,
    RtlPathTypeRelative = 0x5,
    RtlPathTypeLocalDevice = 0x6,
    RtlPathTypeRootLocalDevice = 0x7,
};

/* 279 */
typedef enum _RTL_PATH_TYPE RTL_PATH_TYPE;

/* 281 */
typedef struct _CSR_CAPTURE_BUFFER* PCSR_CAPTURE_BUFFER;

/* 282 */
struct _CSR_CAPTURE_BUFFER
{
    ULONG Size;
    struct _CSR_CAPTURE_BUFFER* PreviousCaptureBuffer;
    ULONG PointerCount;
    PVOID BufferEnd;
    ULONG_PTR PointerOffsetsArray[1];
};

/* 283 */
typedef const wchar_t* STRSAFE_LPCWSTR;

/* 286 */
struct _COORD
{
    SHORT X;
    SHORT Y;
};

/* 285 */
typedef struct _COORD COORD;

/* 287 */
typedef struct _SMALL_RECT SMALL_RECT;

/* 288 */
typedef DWORD COLORREF;

/* 284 */
struct _CONSOLE_SCREEN_BUFFER_INFOEX
{
    ULONG cbSize;
    COORD dwSize;
    COORD dwCursorPosition;
    WORD wAttributes;
    SMALL_RECT srWindow;
    COORD dwMaximumWindowSize;
    WORD wPopupAttributes;
    BOOL bFullscreenSupported;
    COLORREF ColorTable[16];
};

/* 289 */
typedef struct _RTL_USER_PROCESS_PARAMETERS* PRTL_USER_PROCESS_PARAMETERS;

/* 290 */
struct _cpinfo
{
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

/* 291 */
struct _LDR_RESOURCE_INFO
{
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG_PTR Language;
};

/* 292 */
typedef struct _IMAGE_RESOURCE_DATA_ENTRY* PIMAGE_RESOURCE_DATA_ENTRY;

/* 293 */
struct _IMAGE_RESOURCE_DATA_ENTRY
{
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
};

/* 294 */
struct _WIN32_FIND_DATAW
{
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

/* 296 */
typedef ULONGLONG DWORDLONG;

/* 295 */
struct _MEMORYSTATUSEX
{
    DWORD dwLength;
    DWORD dwMemoryLoad;
    DWORDLONG ullTotalPhys;
    DWORDLONG ullAvailPhys;
    DWORDLONG ullTotalPageFile;
    DWORDLONG ullAvailPageFile;
    DWORDLONG ullTotalVirtual;
    DWORDLONG ullAvailVirtual;
    DWORDLONG ullAvailExtendedVirtual;
};

/* 297 */
typedef DWORD SECURITY_INFORMATION;

/* 298 */
typedef unsigned __int64* PULONG_PTR;

/* 299 */
struct _OSVERSIONINFOW
{
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
};

/* 300 */
typedef DWORD* PACCESS_MASK;

/* 301 */
typedef int* PNTSTATUS;

/* 302 */
typedef unsigned __int8* PBOOLEAN;

/* 303 */
typedef struct _EVENT_FILTER_DESCRIPTOR* PEVENT_FILTER_DESCRIPTOR;

/* 304 */
struct _EVENT_FILTER_DESCRIPTOR
{
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Type;
};

/* 305 */
typedef size_t rsize_t;

/* 306 */
typedef WCHAR* PWCH;

/* 307 */
typedef struct _STRING STRING;

/* 308 */
typedef UCHAR* PUCHAR;

/* 309 */
typedef void(__stdcall* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

/* 310 */
typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES;

/* 311 */
typedef unsigned int JET_GRBIT;

/* 312 */
typedef struct _HIDP_PREPARSED_DATA* PHIDP_PREPARSED_DATA;

/* 313 */
typedef void* RPC_AUTH_IDENTITY_HANDLE;

/* 314 */
typedef PWSTR* PZPWSTR;

/* 315 */
typedef struct _WSAPROTOCOL_INFOW* LPWSAPROTOCOL_INFOW;

/* 318 */
struct _WSAPROTOCOLCHAIN
{
    int ChainLen;
    DWORD ChainEntries[7];
};

/* 317 */
typedef struct _WSAPROTOCOLCHAIN WSAPROTOCOLCHAIN;

/* 316 */
struct _WSAPROTOCOL_INFOW
{
    DWORD dwServiceFlags1;
    DWORD dwServiceFlags2;
    DWORD dwServiceFlags3;
    DWORD dwServiceFlags4;
    DWORD dwProviderFlags;
    GUID ProviderId;
    DWORD dwCatalogEntryId;
    WSAPROTOCOLCHAIN ProtocolChain;
    int iVersion;
    int iAddressFamily;
    int iMaxSockAddr;
    int iMinSockAddr;
    int iSocketType;
    int iProtocol;
    int iProtocolMaxOffset;
    int iNetworkByteOrder;
    int iSecurityScheme;
    DWORD dwMessageSize;
    DWORD dwProviderReserved;
    WCHAR szProtocol[256];
};

/* 319 */
typedef struct _CONTEXT CONTEXT;

/* 320 */
typedef unsigned __int64 ULONG64;

/* 321 */
typedef struct _RUNTIME_FUNCTION* PRUNTIME_FUNCTION;

/* 322 */
struct _RUNTIME_FUNCTION
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

/* 323 */
typedef CONTEXT* PCONTEXT;

/* 324 */
typedef unsigned __int64* PULONG64;

/* 325 */
typedef struct _KNONVOLATILE_CONTEXT_POINTERS* PKNONVOLATILE_CONTEXT_POINTERS;

/* 328 */
typedef struct _M128A* PM128A;

/* 326 */
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
        PULONG64 IntegerContext[16];
        struct
        {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
};

/* 333 */
typedef struct _EXCEPTION_RECORD* PEXCEPTION_RECORD;

/* 332 */
struct _EXCEPTION_POINTERS
{
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

/* 335 */
typedef struct _RTL_SRWLOCK RTL_SRWLOCK;

/* 334 */
typedef RTL_SRWLOCK* PSRWLOCK;

/* 336 */
struct _RTL_SRWLOCK
{
    PVOID Ptr;
};

/* 337 */
typedef WCHAR OLECHAR;

/* 339 */
enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation = 0x0,
    KeyNodeInformation = 0x1,
    KeyFullInformation = 0x2,
    KeyNameInformation = 0x3,
    KeyCachedInformation = 0x4,
    KeyFlagsInformation = 0x5,
    KeyVirtualizationInformation = 0x6,
    KeyHandleTagsInformation = 0x7,
    MaxKeyInfoClass = 0x8,
};

/* 338 */
typedef enum _KEY_INFORMATION_CLASS KEY_INFORMATION_CLASS;

/* 341 */
enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation = 0x0,
    KeyValueFullInformation = 0x1,
    KeyValuePartialInformation = 0x2,
    KeyValueFullInformationAlign64 = 0x3,
    KeyValuePartialInformationAlign64 = 0x4,
    MaxKeyValueInfoClass = 0x5,
};

/* 340 */
typedef enum _KEY_VALUE_INFORMATION_CLASS KEY_VALUE_INFORMATION_CLASS;

/* 342 */
struct _OSVERSIONINFOEXW
{
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
};

/* 343 */
typedef const wchar_t* STRSAFE_PCNZWCH;

/* 344 */
typedef HANDLE HUSKEY;

/* 345 */
typedef struct tagPARSEDURLA PARSEDURLA;

/* 346 */
#pragma pack(push, 8)
struct tagPARSEDURLA
{
    DWORD cbSize;
    LPCSTR pszProtocol;
    UINT cchProtocol;
    LPCSTR pszSuffix;
    UINT cchSuffix;
    UINT nScheme;
};
#pragma pack(pop)

/* 347 */
typedef struct _RTL_AVL_TABLE* PRTL_AVL_TABLE;

/* 350 */
struct _RTL_BALANCED_LINKS
{
    struct _RTL_BALANCED_LINKS* Parent;
    struct _RTL_BALANCED_LINKS* LeftChild;
    struct _RTL_BALANCED_LINKS* RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
};

/* 349 */
typedef struct _RTL_BALANCED_LINKS RTL_BALANCED_LINKS;

/* 351 */
typedef struct _RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

/* 355 */
enum _RTL_GENERIC_COMPARE_RESULTS
{
    GenericLessThan = 0x0,
    GenericGreaterThan = 0x1,
    GenericEqual = 0x2,
};

/* 354 */
typedef enum _RTL_GENERIC_COMPARE_RESULTS RTL_GENERIC_COMPARE_RESULTS;

/* 353 */
typedef RTL_GENERIC_COMPARE_RESULTS __stdcall RTL_AVL_COMPARE_ROUTINE(struct _RTL_AVL_TABLE* Table, PVOID FirstStruct, PVOID SecondStruct);

/* 352 */
typedef RTL_AVL_COMPARE_ROUTINE* PRTL_AVL_COMPARE_ROUTINE;

/* 358 */
typedef ULONG CLONG;

/* 357 */
typedef PVOID __stdcall RTL_AVL_ALLOCATE_ROUTINE(struct _RTL_AVL_TABLE* Table, CLONG ByteSize);

/* 356 */
typedef RTL_AVL_ALLOCATE_ROUTINE* PRTL_AVL_ALLOCATE_ROUTINE;

/* 360 */
typedef void __stdcall RTL_AVL_FREE_ROUTINE(struct _RTL_AVL_TABLE* Table, PVOID Buffer);

/* 359 */
typedef RTL_AVL_FREE_ROUTINE* PRTL_AVL_FREE_ROUTINE;

/* 348 */
struct _RTL_AVL_TABLE
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
};

/* 361 */
struct _CONSOLE_FONT_INFOEX
{
    ULONG cbSize;
    DWORD nFont;
    COORD dwFontSize;
    UINT FontFamily;
    UINT FontWeight;
    WCHAR FaceName[32];
};

/* 363 */
typedef ULONG_PTR KAFFINITY;

/* 362 */
struct _GROUP_AFFINITY
{
    KAFFINITY Mask;
    WORD Group;
    WORD Reserved[3];
};

/* 366 */
enum _DBG_STATE
{
    DbgIdle = 0x0,
    DbgReplyPending = 0x1,
    DbgCreateThreadStateChange = 0x2,
    DbgCreateProcessStateChange = 0x3,
    DbgExitThreadStateChange = 0x4,
    DbgExitProcessStateChange = 0x5,
    DbgExceptionStateChange = 0x6,
    DbgBreakpointStateChange = 0x7,
    DbgSingleStepStateChange = 0x8,
    DbgLoadDllStateChange = 0x9,
    DbgUnloadDllStateChange = 0xA,
};

/* 365 */
typedef enum _DBG_STATE DBG_STATE;

/* 370 */
struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
};

/* 369 */
typedef struct _DBGKM_CREATE_THREAD DBGKM_CREATE_THREAD;

/* 368 */
struct _DBGUI_WAIT_STATE_CHANGE_CREATE_THREAD
{
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
};

/* 373 */
struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
};

/* 372 */
typedef struct _DBGKM_CREATE_PROCESS DBGKM_CREATE_PROCESS;

/* 371 */
struct _DBGUI_WAIT_STATE_CHANGE_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
};

/* 375 */
struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
};

/* 374 */
typedef struct _DBGKM_EXIT_THREAD DBGKM_EXIT_THREAD;

/* 377 */
struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
};

/* 376 */
typedef struct _DBGKM_EXIT_PROCESS DBGKM_EXIT_PROCESS;

/* 380 */
typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

/* 379 */
struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
};

/* 378 */
typedef struct _DBGKM_EXCEPTION DBGKM_EXCEPTION;

/* 382 */
struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
};

/* 381 */
typedef struct _DBGKM_LOAD_DLL DBGKM_LOAD_DLL;

/* 384 */
struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
};

/* 383 */
typedef struct _DBGKM_UNLOAD_DLL DBGKM_UNLOAD_DLL;

/* 367 */
union _DBGUI_WAIT_STATE_CHANGE_INFO
{
    _DBGUI_WAIT_STATE_CHANGE_CREATE_THREAD CreateThread;
    _DBGUI_WAIT_STATE_CHANGE_CREATE_PROCESS CreateProcessInfo;
    DBGKM_EXIT_THREAD ExitThread;
    DBGKM_EXIT_PROCESS ExitProcess;
    DBGKM_EXCEPTION Exception;
    DBGKM_LOAD_DLL LoadDll;
    DBGKM_UNLOAD_DLL UnloadDll;
};

/* 364 */
struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    _DBGUI_WAIT_STATE_CHANGE_INFO StateInfo;
};

/* 385 */
struct _DCB
{
    DWORD DCBlength;
    DWORD BaudRate;
    unsigned __int32 fBinary : 1;
    unsigned __int32 fParity : 1;
    unsigned __int32 fOutxCtsFlow : 1;
    unsigned __int32 fOutxDsrFlow : 1;
    unsigned __int32 fDtrControl : 2;
    unsigned __int32 fDsrSensitivity : 1;
    unsigned __int32 fTXContinueOnXoff : 1;
    unsigned __int32 fOutX : 1;
    unsigned __int32 fInX : 1;
    unsigned __int32 fErrorChar : 1;
    unsigned __int32 fNull : 1;
    unsigned __int32 fRtsControl : 2;
    unsigned __int32 fAbortOnError : 1;
    unsigned __int32 fDummy2 : 17;
    WORD wReserved;
    WORD XonLim;
    WORD XoffLim;
    BYTE ByteSize;
    BYTE Parity;
    BYTE StopBits;
    char XonChar;
    char XoffChar;
    char ErrorChar;
    char EofChar;
    char EvtChar;
    WORD wReserved1;
};

/* 386 */
typedef const WCHAR* PCWCH;

/* 387 */
typedef const UNICODE_STRING* PCUNICODE_STRING;

/* 388 */
typedef IOleClientSite* LPOLECLIENTSITE;

/* 389 */
#pragma pack(push, 8)
struct IOleClientSite
{
    struct IOleClientSiteVtbl* lpVtbl;
};
#pragma pack(pop)

/* 391 */
typedef GUID IID;

/* 390 */
#pragma pack(push, 8)
struct IOleClientSiteVtbl
{
    HRESULT(__stdcall* QueryInterface)(IOleClientSite* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IOleClientSite* This);
    ULONG(__stdcall* Release)(IOleClientSite* This);
    HRESULT(__stdcall* SaveObject)(IOleClientSite* This);
    HRESULT(__stdcall* GetMoniker)(IOleClientSite* This, DWORD dwAssign, DWORD dwWhichMoniker, IMoniker** ppmk);
    HRESULT(__stdcall* GetContainer)(IOleClientSite* This, IOleContainer** ppContainer);
    HRESULT(__stdcall* ShowObject)(IOleClientSite* This);
    HRESULT(__stdcall* OnShowWindow)(IOleClientSite* This, BOOL fShow);
    HRESULT(__stdcall* RequestNewObjectLayout)(IOleClientSite* This);
};
#pragma pack(pop)

/* 392 */
#pragma pack(push, 8)
struct IMoniker
{
    struct IMonikerVtbl* lpVtbl;
};
#pragma pack(pop)

/* 409 */
#pragma pack(push, 8)
struct IOleContainer
{
    struct IOleContainerVtbl* lpVtbl;
};
#pragma pack(pop)

/* 394 */
typedef GUID CLSID;

/* 395 */
struct IStream;

/* 406 */
typedef OLECHAR* LPOLESTR;

/* 393 */
#pragma pack(push, 8)
struct IMonikerVtbl
{
    HRESULT(__stdcall* QueryInterface)(IMoniker* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IMoniker* This);
    ULONG(__stdcall* Release)(IMoniker* This);
    HRESULT(__stdcall* GetClassID)(IMoniker* This, CLSID* pClassID);
    HRESULT(__stdcall* IsDirty)(IMoniker* This);
    HRESULT(__stdcall* Load)(IMoniker* This, IStream* pStm);
    HRESULT(__stdcall* Save)(IMoniker* This, IStream* pStm, BOOL fClearDirty);
    HRESULT(__stdcall* GetSizeMax)(IMoniker* This, ULARGE_INTEGER* pcbSize);
    HRESULT(__stdcall* BindToObject)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, const IID* const riidResult, void** ppvResult);
    HRESULT(__stdcall* BindToStorage)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, const IID* const riid, void** ppvObj);
    HRESULT(__stdcall* Reduce)(IMoniker* This, IBindCtx* pbc, DWORD dwReduceHowFar, IMoniker** ppmkToLeft, IMoniker** ppmkReduced);
    HRESULT(__stdcall* ComposeWith)(IMoniker* This, IMoniker* pmkRight, BOOL fOnlyIfNotGeneric, IMoniker** ppmkComposite);
    HRESULT(__stdcall* Enum)(IMoniker* This, BOOL fForward, IEnumMoniker** ppenumMoniker);
    HRESULT(__stdcall* IsEqual)(IMoniker* This, IMoniker* pmkOtherMoniker);
    HRESULT(__stdcall* Hash)(IMoniker* This, DWORD* pdwHash);
    HRESULT(__stdcall* IsRunning)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, IMoniker* pmkNewlyRunning);
    HRESULT(__stdcall* GetTimeOfLastChange)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, FILETIME* pFileTime);
    HRESULT(__stdcall* Inverse)(IMoniker* This, IMoniker** ppmk);
    HRESULT(__stdcall* CommonPrefixWith)(IMoniker* This, IMoniker* pmkOther, IMoniker** ppmkPrefix);
    HRESULT(__stdcall* RelativePathTo)(IMoniker* This, IMoniker* pmkOther, IMoniker** ppmkRelPath);
    HRESULT(__stdcall* GetDisplayName)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, LPOLESTR* ppszDisplayName);
    HRESULT(__stdcall* ParseDisplayName)(IMoniker* This, IBindCtx* pbc, IMoniker* pmkToLeft, LPOLESTR pszDisplayName, ULONG* pchEaten, IMoniker** ppmkOut);
    HRESULT(__stdcall* IsSystemMoniker)(IMoniker* This, DWORD* pdwMksys);
};
#pragma pack(pop)

/* 410 */
#pragma pack(push, 8)
struct IOleContainerVtbl
{
    HRESULT(__stdcall* QueryInterface)(IOleContainer* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IOleContainer* This);
    ULONG(__stdcall* Release)(IOleContainer* This);
    HRESULT(__stdcall* ParseDisplayName)(IOleContainer* This, IBindCtx* pbc, LPOLESTR pszDisplayName, ULONG* pchEaten, IMoniker** ppmkOut);
    HRESULT(__stdcall* EnumObjects)(IOleContainer* This, DWORD grfFlags, IEnumUnknown** ppenum);
    HRESULT(__stdcall* LockContainer)(IOleContainer* This, BOOL fLock);
};
#pragma pack(pop)

/* 396 */
#pragma pack(push, 8)
struct IBindCtx
{
    struct IBindCtxVtbl* lpVtbl;
};
#pragma pack(pop)

/* 404 */
#pragma pack(push, 8)
struct IEnumMoniker
{
    struct IEnumMonikerVtbl* lpVtbl;
};
#pragma pack(pop)

/* 411 */
#pragma pack(push, 8)
struct IEnumUnknown
{
    struct IEnumUnknownVtbl* lpVtbl;
};
#pragma pack(pop)

/* 400 */
typedef struct tagBIND_OPTS BIND_OPTS;

/* 397 */
#pragma pack(push, 8)
struct IBindCtxVtbl
{
    HRESULT(__stdcall* QueryInterface)(IBindCtx* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IBindCtx* This);
    ULONG(__stdcall* Release)(IBindCtx* This);
    HRESULT(__stdcall* RegisterObjectBound)(IBindCtx* This, IUnknown* punk);
    HRESULT(__stdcall* RevokeObjectBound)(IBindCtx* This, IUnknown* punk);
    HRESULT(__stdcall* ReleaseBoundObjects)(IBindCtx* This);
    HRESULT(__stdcall* SetBindOptions)(IBindCtx* This, BIND_OPTS* pbindopts);
    HRESULT(__stdcall* GetBindOptions)(IBindCtx* This, BIND_OPTS* pbindopts);
    HRESULT(__stdcall* GetRunningObjectTable)(IBindCtx* This, IRunningObjectTable** pprot);
    HRESULT(__stdcall* RegisterObjectParam)(IBindCtx* This, LPOLESTR pszKey, IUnknown* punk);
    HRESULT(__stdcall* GetObjectParam)(IBindCtx* This, LPOLESTR pszKey, IUnknown** ppunk);
    HRESULT(__stdcall* EnumObjectParam)(IBindCtx* This, IEnumString** ppenum);
    HRESULT(__stdcall* RevokeObjectParam)(IBindCtx* This, LPOLESTR pszKey);
};
#pragma pack(pop)

/* 405 */
#pragma pack(push, 8)
struct IEnumMonikerVtbl
{
    HRESULT(__stdcall* QueryInterface)(IEnumMoniker* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IEnumMoniker* This);
    ULONG(__stdcall* Release)(IEnumMoniker* This);
    HRESULT(__stdcall* Next)(IEnumMoniker* This, ULONG celt, IMoniker** rgelt, ULONG* pceltFetched);
    HRESULT(__stdcall* Skip)(IEnumMoniker* This, ULONG celt);
    HRESULT(__stdcall* Reset)(IEnumMoniker* This);
    HRESULT(__stdcall* Clone)(IEnumMoniker* This, IEnumMoniker** ppenum);
};
#pragma pack(pop)

/* 412 */
#pragma pack(push, 8)
struct IEnumUnknownVtbl
{
    HRESULT(__stdcall* QueryInterface)(IEnumUnknown* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IEnumUnknown* This);
    ULONG(__stdcall* Release)(IEnumUnknown* This);
    HRESULT(__stdcall* Next)(IEnumUnknown* This, ULONG celt, IUnknown** rgelt, ULONG* pceltFetched);
    HRESULT(__stdcall* Skip)(IEnumUnknown* This, ULONG celt);
    HRESULT(__stdcall* Reset)(IEnumUnknown* This);
    HRESULT(__stdcall* Clone)(IEnumUnknown* This, IEnumUnknown** ppenum);
};
#pragma pack(pop)

/* 398 */
#pragma pack(push, 8)
struct IUnknown
{
    struct IUnknownVtbl* lpVtbl;
};
#pragma pack(pop)

/* 401 */
#pragma pack(push, 8)
struct tagBIND_OPTS
{
    DWORD cbStruct;
    DWORD grfFlags;
    DWORD grfMode;
    DWORD dwTickCountDeadline;
};
#pragma pack(pop)

/* 402 */
#pragma pack(push, 8)
struct IRunningObjectTable
{
    struct IRunningObjectTableVtbl* lpVtbl;
};
#pragma pack(pop)

/* 407 */
#pragma pack(push, 8)
struct IEnumString
{
    struct IEnumStringVtbl* lpVtbl;
};
#pragma pack(pop)

/* 399 */
#pragma pack(push, 8)
struct IUnknownVtbl
{
    HRESULT(__stdcall* QueryInterface)(IUnknown* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IUnknown* This);
    ULONG(__stdcall* Release)(IUnknown* This);
};
#pragma pack(pop)

/* 403 */
#pragma pack(push, 8)
struct IRunningObjectTableVtbl
{
    HRESULT(__stdcall* QueryInterface)(IRunningObjectTable* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IRunningObjectTable* This);
    ULONG(__stdcall* Release)(IRunningObjectTable* This);
    HRESULT(__stdcall* Register)(IRunningObjectTable* This, DWORD grfFlags, IUnknown* punkObject, IMoniker* pmkObjectName, DWORD* pdwRegister);
    HRESULT(__stdcall* Revoke)(IRunningObjectTable* This, DWORD dwRegister);
    HRESULT(__stdcall* IsRunning)(IRunningObjectTable* This, IMoniker* pmkObjectName);
    HRESULT(__stdcall* GetObjectA)(IRunningObjectTable* This, IMoniker* pmkObjectName, IUnknown** ppunkObject);
    HRESULT(__stdcall* NoteChangeTime)(IRunningObjectTable* This, DWORD dwRegister, FILETIME* pfiletime);
    HRESULT(__stdcall* GetTimeOfLastChange)(IRunningObjectTable* This, IMoniker* pmkObjectName, FILETIME* pfiletime);
    HRESULT(__stdcall* EnumRunning)(IRunningObjectTable* This, IEnumMoniker** ppenumMoniker);
};
#pragma pack(pop)

/* 408 */
#pragma pack(push, 8)
struct IEnumStringVtbl
{
    HRESULT(__stdcall* QueryInterface)(IEnumString* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IEnumString* This);
    ULONG(__stdcall* Release)(IEnumString* This);
    HRESULT(__stdcall* Next)(IEnumString* This, ULONG celt, LPOLESTR* rgelt, ULONG* pceltFetched);
    HRESULT(__stdcall* Skip)(IEnumString* This, ULONG celt);
    HRESULT(__stdcall* Reset)(IEnumString* This);
    HRESULT(__stdcall* Clone)(IEnumString* This, IEnumString** ppenum);
};
#pragma pack(pop)

/* 413 */
typedef IStorage* LPSTORAGE;

/* 414 */
#pragma pack(push, 8)
struct IStorage
{
    struct IStorageVtbl* lpVtbl;
};
#pragma pack(pop)

/* 416 */
typedef LPOLESTR* SNB;

/* 420 */
struct tagSTATSTG;

/* 419 */
typedef struct tagSTATSTG STATSTG;

/* 415 */
#pragma pack(push, 8)
struct IStorageVtbl
{
    HRESULT(__stdcall* QueryInterface)(IStorage* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IStorage* This);
    ULONG(__stdcall* Release)(IStorage* This);
    HRESULT(__stdcall* CreateStream)(IStorage* This, const OLECHAR* pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStream** ppstm);
    HRESULT(__stdcall* OpenStream)(IStorage* This, const OLECHAR* pwcsName, void* reserved1, DWORD grfMode, DWORD reserved2, IStream** ppstm);
    HRESULT(__stdcall* CreateStorage)(IStorage* This, const OLECHAR* pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStorage** ppstg);
    HRESULT(__stdcall* OpenStorage)(IStorage* This, const OLECHAR* pwcsName, IStorage* pstgPriority, DWORD grfMode, SNB snbExclude, DWORD reserved, IStorage** ppstg);
    HRESULT(__stdcall* CopyTo)(IStorage* This, DWORD ciidExclude, const IID* rgiidExclude, SNB snbExclude, IStorage* pstgDest);
    HRESULT(__stdcall* MoveElementTo)(IStorage* This, const OLECHAR* pwcsName, IStorage* pstgDest, const OLECHAR* pwcsNewName, DWORD grfFlags);
    HRESULT(__stdcall* Commit)(IStorage* This, DWORD grfCommitFlags);
    HRESULT(__stdcall* Revert)(IStorage* This);
    HRESULT(__stdcall* EnumElements)(IStorage* This, DWORD reserved1, void* reserved2, DWORD reserved3, IEnumSTATSTG** ppenum);
    HRESULT(__stdcall* DestroyElement)(IStorage* This, const OLECHAR* pwcsName);
    HRESULT(__stdcall* RenameElement)(IStorage* This, const OLECHAR* pwcsOldName, const OLECHAR* pwcsNewName);
    HRESULT(__stdcall* SetElementTimes)(IStorage* This, const OLECHAR* pwcsName, const FILETIME* pctime, const FILETIME* patime, const FILETIME* pmtime);
    HRESULT(__stdcall* SetClass)(IStorage* This, const IID* const clsid);
    HRESULT(__stdcall* SetStateBits)(IStorage* This, DWORD grfStateBits, DWORD grfMask);
    HRESULT(__stdcall* Stat)(IStorage* This, STATSTG* pstatstg, DWORD grfStatFlag);
};
#pragma pack(pop)

/* 417 */
#pragma pack(push, 8)
struct IEnumSTATSTG
{
    struct IEnumSTATSTGVtbl* lpVtbl;
};
#pragma pack(pop)

/* 418 */
#pragma pack(push, 8)
struct IEnumSTATSTGVtbl
{
    HRESULT(__stdcall* QueryInterface)(IEnumSTATSTG* This, const IID* const riid, void** ppvObject);
    ULONG(__stdcall* AddRef)(IEnumSTATSTG* This);
    ULONG(__stdcall* Release)(IEnumSTATSTG* This);
    HRESULT(__stdcall* Next)(IEnumSTATSTG* This, ULONG celt, STATSTG* rgelt, ULONG* pceltFetched);
    HRESULT(__stdcall* Skip)(IEnumSTATSTG* This, ULONG celt);
    HRESULT(__stdcall* Reset)(IEnumSTATSTG* This);
    HRESULT(__stdcall* Clone)(IEnumSTATSTG* This, IEnumSTATSTG** ppenum);
};
#pragma pack(pop)

/* 421 */
enum D3D10_FEATURE_LEVEL1
{
    D3D10_FEATURE_LEVEL_10_0 = 0xA000,
    D3D10_FEATURE_LEVEL_10_1 = 0xA100,
    D3D10_FEATURE_LEVEL_9_1 = 0x9100,
    D3D10_FEATURE_LEVEL_9_2 = 0x9200,
    D3D10_FEATURE_LEVEL_9_3 = 0x9300,
};

/* 423 */
typedef struct wavefilter_tag WAVEFILTER;

/* 422 */
typedef WAVEFILTER* LPWAVEFILTER;

/* 424 */
#pragma pack(push, 1)
struct wavefilter_tag
{
    DWORD cbStruct;
    DWORD dwFilterTag;
    DWORD fdwFilter;
    DWORD dwReserved[5];
};
#pragma pack(pop)

/* 426 */
typedef struct _PROPERTY_DATA_DESCRIPTOR PROPERTY_DATA_DESCRIPTOR;

/* 425 */
typedef PROPERTY_DATA_DESCRIPTOR* PPROPERTY_DATA_DESCRIPTOR;

/* 427 */
struct _PROPERTY_DATA_DESCRIPTOR
{
    ULONGLONG PropertyName;
    ULONG ArrayIndex;
    ULONG Reserved;
};

/* 428 */
typedef BYTE* PBYTE;

/* 429 */
struct ReservedForLocalUse;

/* 439 */
struct ARI;

/* 444 */
enum PATHCCH_OPTIONS
{
    PATHCCH_NONE = 0x0,
    PATHCCH_ALLOW_LONG_PATHS = 0x1,
    PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS = 0x2,
    PATHCCH_FORCE_DISABLE_LONG_NAME_PROCESS = 0x4,
    PATHCCH_DO_NOT_NORMALIZE_SEGMENTS = 0x8,
    PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH = 0x10,
    PATHCCH_ENSURE_TRAILING_SLASH = 0x20,
};

/* 446 */
struct URL;

/* 447 */
struct URL_STRING;

/* 448 */
struct ShStrA;

/* 449 */
struct ShStrW;

/* 450 */
struct Common;

/* 452 */
struct StateSpace;

/* 453 */
struct StateAtom;

/* 457 */
struct Nfp;

/* 470 */
struct tson;

/* 474 */
struct wil;

/* 475 */
struct StateContainer;

/* 498 */
struct FindDataStack;

/* 502 */
struct AppXMiniRepository;

/* 509 */
struct _WNF_STATE_NAME
{
    ULONG Data[2];
};

/* 510 */
struct StateChangeNotification;

/* 511 */
struct StateLock;

/* 527 */
struct ZuneMusicRepairer;
