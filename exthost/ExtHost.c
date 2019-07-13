#include <ntddk.h>

typedef struct _EX_HOST_BINDING {
    USHORT ExtensionId;
    USHORT ExtensionVersion;
    USHORT FunctionCount;
} EX_HOST_BINDING;

typedef DWORD_PTR PEX_HOST_BIND_NOTIFICATION;

typedef struct _EX_HOST_PARAMETERS {
    EX_HOST_BINDING             HostBinding;
    POOL_TYPE                   PoolType;
    PVOID                       HostTable;
    PEX_HOST_BIND_NOTIFICATION  BindNotification;
    PVOID                       BindNotificationContext;
} EX_HOST_PARAMETERS, *PEX_HOST_PARAMETERS;

typedef struct _EX_HOST {
    LIST_ENTRY          HostListEntry;
    volatile LONG       RefCounter;
    EX_HOST_PARAMETERS  HostParameters;
    EX_RUNDOWN_REF      RundownProtection;
    EX_PUSH_LOCK        PushLock;
    PVOID               ExtensionTable;
    ULONG               Flags;
} EX_HOST, *PEX_HOST;

typedef struct _EX_EXTENSION_BINDING {
    USHORT  ExtensionId;
    USHORT  ExtensionVersion;
    USHORT  FunctionCount;
} EX_EXTENSION_BINDING;

typedef struct _EX_EXTENSION_REGISTRATION {
    EX_EXTENSION_BINDING    ExtensionBinding;
    PVOID                   ExtensionTable;
    PVOID                   *HostTable;
    PVOID                   DriverObject;
} EX_EXTENSION_PARAMETERS, *PEX_EXTENSION_PARAMETERS;

typedef EX_HOST     EX_EXTENSION;
typedef PEX_HOST    PEX_EXTENSION;

#define EXT_TAG 'EXEX'
#define CLB_TAG 'ECLB'
#define BAM_EXTENSION_ID    5
#define BAM_EXTENSION_VER   0xd

typedef NTSTATUS(*ExRegisterExtension)(PEX_EXTENSION, ULONG, PVOID);
typedef VOID(*ExUnregisterExtension)(PEX_EXTENSION);

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

PEX_EXTENSION   g_pExExtension;
PEX_HOST        g_pExHost;
PVOID           g_pNewCallbackTable;
PVOID           g_pOldCallbackTable;

ExRegisterExtension     g_pExRegisterExtension;
ExUnregisterExtension   g_pExUnregisterExtension;


__declspec(noinline)
VOID BAMHook(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               __FUNCTION__ ": BAM BAM BAM!\n");

    //
    // We can call the original function here, not to trigger any issues... but for a poc it's enough
    //
}

__declspec(noinline)
VOID DoNothing(VOID)
{
    ;
}

typedef VOID(*pExtensionFunc)(VOID);
pExtensionFunc g_ExtensionTable[1] = { DoNothing };

_Success_(return == STATUS_SUCCESS)
NTSTATUS DoIt(
    _In_    PDRIVER_OBJECT  DriverObject
)
{
    g_pExExtension = (PEX_EXTENSION)ExAllocatePoolWithTag(NonPagedPool, sizeof(EX_EXTENSION), EXT_TAG);
    if (NULL == g_pExExtension) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ " Failed allocating extension pool\n");

        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    // IPT Extension
    EX_EXTENSION_PARAMETERS ExExtensionParams = { 0 };
    ExExtensionParams.ExtensionBinding.ExtensionId = 0xa;
    ExExtensionParams.ExtensionBinding.ExtensionVersion = 2;
    ExExtensionParams.ExtensionBinding.FunctionCount = 1;
    ExExtensionParams.ExtensionTable = g_ExtensionTable;
    ExExtensionParams.DriverObject = DriverObject;

    NTSTATUS ntStatus = g_pExRegisterExtension(g_pExExtension, 0x10000, (PVOID)&ExExtensionParams);
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ ": Failed to register extension\n");

        goto failed;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": Succeeded registering an extension\n");
    }

    BOOLEAN bHostFound = FALSE;
    g_pExHost = (PEX_HOST)g_pExExtension->HostListEntry.Flink;
    while (g_pExHost->HostListEntry.Flink != g_pExExtension->HostListEntry.Flink) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ " %X - %X - %X\n",
                   g_pExHost->HostParameters.HostBinding.ExtensionId,
                   g_pExHost->HostParameters.HostBinding.ExtensionVersion,
                   g_pExHost->HostParameters.HostBinding.FunctionCount);

        if ((g_pExHost->HostParameters.HostBinding.ExtensionId == BAM_EXTENSION_ID) &&
            (g_pExHost->HostParameters.HostBinding.ExtensionVersion == BAM_EXTENSION_VER)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": Found BAM extension\n");

            bHostFound = TRUE;

            break;
        }

        g_pExHost = (PEX_HOST)g_pExHost->HostListEntry.Flink;
    }

    if (!bHostFound) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ " BAM Host not found\n");

        ntStatus = STATUS_NOT_FOUND;
        goto unreg_ext;
    }
    if (NULL == g_pExHost->ExtensionTable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ " No extension table\n");

        ntStatus = STATUS_FAIL_CHECK;
        goto unreg_ext;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               __FUNCTION__ ": BAM # of ext. callbacks %08x\n", g_pExHost->HostParameters.HostBinding.FunctionCount);

    g_pNewCallbackTable = (PVOID)ExAllocatePoolWithTag(NonPagedPool,
                                                      g_pExHost->HostParameters.HostBinding.FunctionCount * sizeof(PVOID),
                                                      'BOOM');
    if (NULL == g_pNewCallbackTable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ " Failed allocating callbacks pool\n");

        ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
        goto unreg_ext;
    }

    RtlCopyMemory((PVOID)g_pNewCallbackTable, (PVOID)g_pExHost->ExtensionTable, g_pExHost->HostParameters.HostBinding.FunctionCount * sizeof(PVOID));

    g_pOldCallbackTable = g_pExHost->ExtensionTable;
    ((PVOID *)g_pNewCallbackTable)[0] = (PVOID)BAMHook;
    g_pExHost->ExtensionTable = g_pNewCallbackTable;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               __FUNCTION__ ": BAM hook successfully installed!\n");

    return STATUS_SUCCESS;

unreg_ext:
    g_pExUnregisterExtension(g_pExExtension);

failed:
    if (g_pExExtension != NULL) {
        ExFreePoolWithTag(g_pExExtension, EXT_TAG);
        g_pExExtension = NULL;
    }
    if (g_pNewCallbackTable != NULL) {
        ExFreePoolWithTag(g_pNewCallbackTable, CLB_TAG);
        g_pNewCallbackTable = NULL;
    }

    return ntStatus;
}

VOID DriverUnload(
    _In_    PDRIVER_OBJECT  DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if ((g_pExHost != NULL) && (g_pOldCallbackTable != NULL)) {
        g_pExHost->ExtensionTable = g_pOldCallbackTable;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "Restored original callback table!\n");
    }

    if (g_pExExtension != NULL) {
        g_pExUnregisterExtension(g_pExExtension);
        ExFreePoolWithTag(g_pExExtension, EXT_TAG);
        g_pExExtension = NULL;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "Unregistered extension!\n");
    }
    if (g_pNewCallbackTable != NULL) {
        ExFreePoolWithTag(g_pNewCallbackTable, CLB_TAG);
        g_pNewCallbackTable = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "Driver unloading...!\n");
}

NTSTATUS
DriverEntry(
    _In_    PDRIVER_OBJECT  DriverObject,
    _In_    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);    

    DriverObject->DriverUnload = DriverUnload;

    UNICODE_STRING  ExRegisterExtensionSym = RTL_CONSTANT_STRING(L"ExRegisterExtension");
    UNICODE_STRING  ExUnregisterExtensionSym = RTL_CONSTANT_STRING(L"ExUnregisterExtension");

    g_pExRegisterExtension = (ExRegisterExtension)MmGetSystemRoutineAddress(&ExRegisterExtensionSym);
    g_pExUnregisterExtension = (ExUnregisterExtension)MmGetSystemRoutineAddress(&ExUnregisterExtensionSym);
    if ((NULL == g_pExRegisterExtension) || (NULL == g_pExUnregisterExtension)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "Failed to obtain needed routines!\n");

        return STATUS_NOT_FOUND;
    }

    NTSTATUS ntStatus = DoIt(DriverObject);
    if (NT_SUCCESS(ntStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "Did it! %08x\n", ntStatus);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "Didn't! %08x\n", ntStatus);
    }

    return STATUS_SUCCESS;
}