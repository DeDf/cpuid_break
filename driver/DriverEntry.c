//==============================================
#include "defs.h"

#define MEM_TAG 0x11111111

MSR msr;

PULONG  vmxStack[32];
PULONG  pVMXONRegion[32];
PULONG  pVMCSRegion[32];
PHYSICAL_ADDRESS physicalVMXONRegion[32];
PHYSICAL_ADDRESS physicalVMCSRegion[32];

ULONG current_cpu;
ULONG GuestStack;
ULONG GuestEip;
PVOID vmx_idt[32];
PVOID vmx_gdt[32];

WCHAR *szDevice  = L"\\DosDevices\\virtualmachine";
WCHAR *szSymlink = L"\\\\.\\virtualmachine";

VOID unloadme(IN PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING usSymlink;
    PKTHREAD cur_thread;
    ULONG VMX_Region_Size;
    UCHAR i;

    RtlInitUnicodeString(&usSymlink, szSymlink);
    IoDeleteSymbolicLink(&usSymlink);
    IoDeleteDevice(pDriverObject->DeviceObject);
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);

    cur_thread = PsGetCurrentThread();
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetAffinityThread(cur_thread, 1 << i);
        __asm{
            _emit   0x0F ;vmxoff
            _emit   0x01
            _emit   0xC4

            mov  ecx, IA32_VMX_BASIC
            rdmsr
            and  edx, 0FFFh  // unsigned szVmxOnRegion:12;
            mov  VMX_Region_Size, edx
        }

        KdPrint(("cpu[%x] VMX_Region_len = %x\n", VMX_Region_Size, i));

        MmFreeNonCachedMemory(pVMXONRegion[i], VMX_Region_Size);
        MmFreeNonCachedMemory(pVMCSRegion[i],  VMX_Region_Size);

        ExFreePool(vmxStack[i]);
        ExFreePool(vmx_idt[i]);
        ExFreePool(vmx_gdt[i]);
    }         
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegPath)
{
    NTSTATUS status;
    const PULONG local_apic = (PULONG)0xFFFE0020;
    //
    UCHAR vmx_on, bit_enabled;
    ULONG dummy, index;
    PKTHREAD cur_thread;
    MSR msr;
    IDT idt;
    GDT gdt;
    PIDT_ENTRY pidt_entry;
    PGDT_ENTRY pgdt_entry;
    PKTSS ptss;
    ULONG VmxRegionSize;
    //
    UNICODE_STRING us_device, us_symlink;
    PDEVICE_OBJECT pDeviceObject;
    UCHAR i;

    /*
    bit 2 has to be checked to verify that VMX is enabled in BIOS.
    otherwise, VMXON will cause #GP
    */
    __asm
    {
            mov     ecx, 3ah
            rdmsr
            bt      eax, 2
            setc    bit_enabled
    }

    if (bit_enabled)
        DbgPrint("vmx enabled in BIOS...\n");
    else{
        DbgPrint("vmx disabled in BIOS...\n");
        DbgPrint("Aborting...\n");
        return STATUS_UNSUCCESSFUL;
    }

    cur_thread = PsGetCurrentThread();
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetAffinityThread(cur_thread, 1 << i);
        cpu_id[i].LocalApicId = *local_apic;
        cpu_id[i].ProcessorNumber = i;

        __asm
        {
                mov     eax, 1
                cpuid
                bt      ecx, 5
                setc    al
                movzx   rax, al
        }

        if (vmx_on)
            DbgPrint("CPU [%d] supports VMX...\n", i);
        else
        {
            DbgPrint("CPU [%d] doesn't support VMX...\n", i);
            DbgPrint("Aborting...\n");
            return STATUS_UNSUCCESSFUL;
        }

        __asm sgdt gdt
        __asm sidt idt

        vmx_idt[i] = ExAllocatePoolWithTag(NonPagedPool, idt.Limit, MEM_TAG);
        vmx_gdt[i] = ExAllocatePoolWithTag(NonPagedPool, gdt.Limit, MEM_TAG);

        memcpy(vmx_idt[i], (PVOID)(idt.BaseLo + (idt.BaseHi << 16)), idt.Limit);
        memcpy(vmx_gdt[i], (PVOID)(gdt.BaseLo + (gdt.BaseHi << 16)), gdt.Limit);

        pidt_entry = (PIDT_ENTRY)vmx_idt[i];
        pgdt_entry = (PGDT_ENTRY)vmx_gdt[i];

        //I need also to reallocate TSS for tasks and NMI... 0x28 and 0x58 task segments...
        //FS may be as it is atm because KeGetCurrentProcessorNumber is using KPCR to
        //check on which processors it's running... 

        index = 0x28 >> 3;
        ptss = (PKTSS)ExAllocatePoolWithTag(NonPagedPool, GetSegmentLimit(0x28), MEM_TAG);
        memcpy((PVOID)ptss, (PVOID)GetSegmentBase(0x28), GetSegmentLimit(0x28));

        dummy = (ULONG)ptss;
        pgdt_entry[index].BaseLow = dummy & 0xFFFF;
        pgdt_entry[index].BaseMid = dummy >> 16;
        pgdt_entry[index].BaseHi  = dummy >> 24;

        index = 0x58 >> 3;
        ptss = (PKTSS)ExAllocatePoolWithTag(NonPagedPool, GetSegmentLimit(0x58), MEM_TAG);
        memcpy((PVOID)ptss, (PVOID)GetSegmentBase(0x58), GetSegmentLimit(0x58));

        dummy = (ULONG)ptss;
        pgdt_entry[index].BaseLow = dummy & 0xFFFF;
        pgdt_entry[index].BaseMid = dummy >> 16;
        pgdt_entry[index].BaseHi  = dummy >> 24;  

        dummy = (ULONG)ExAllocatePoolWithTag(NonPagedPool, 0x3000, MEM_TAG);
        ptss->Esp0 = dummy + 0x2FFC;    //stack for my NMI handler... 
        ptss->Esp  = dummy + 0x2FFC;    //stack for my NMI handler...

        //this NMI handler only occurs when I'm in vmx-root operation and signals
        //that NMI should be injected into guest using event injection...
        ptss->Eip  = (ULONG)&VMX_NMI;

        __asm
        {
                _emit   0x0F    ;mov eax, cr4
                _emit   0x20
                _emit   0xE0
                bts     eax, 13 ;cr4.VMXE = 1
                _emit   0x0F    ;mov cr4, eax
                _emit   0x22
                _emit   0xE0
        }

        ReadMSR(IA32_VMX_BASIC);

        VmxRegionSize = ((P_VMX_BASIC_MSR_HI)&msr.Hi)->VmxRegionSize;

        DbgPrint("VMX revision ID : %X\n", msr.Lo);
        DbgPrint("VMXON region size : %X\n", VmxRegionSize);

        switch (((P_VMX_BASIC_MSR_HI)&msr.Hi)->MemoryType)
        {
        case 0:
            DbgPrint("Memory type : Strong Uncacheable (UC)\n");
            break;
        case 6:
            DbgPrint("Memory type : Write Back (WB)\n");
            break;
        default:
            DbgPrint("Memory type not used : %X\n", ((P_VMX_BASIC_MSR_HI)&msr.Hi)->MemoryType);
            break;
        }                

        // VMXON region Size == VMCS region Size.
        pVMXONRegion[i] = MmAllocateNonCachedMemory(VmxRegionSize);
        pVMCSRegion[i]  = MmAllocateNonCachedMemory(VmxRegionSize);
        memset(pVMXONRegion[i], 0, VmxRegionSize);
        memset(pVMCSRegion[i],  0, VmxRegionSize);
        physicalVMXONRegion[i] = MmGetPhysicalAddress(pVMXONRegion[i]);
        physicalVMCSRegion[i]  = MmGetPhysicalAddress(pVMCSRegion[i]);
        *(pVMXONRegion[i]) = *(pVMCSRegion[i]) = msr.Lo;  // revision ID

        vmxStack[i] = ExAllocatePoolWithTag(NonPagedPool, 0x3000, MEM_TAG);
        (ULONG)vmxStack[i] = (ULONG)vmxStack[i] + 0x2FFC;

        current_cpu = MyKeGetCurrentProcessorNumber();
            __asm pushad
            __asm pushfd
            __asm mov GuestStack, esp
            __asm mov GuestEip, offset __guest_eip
            __asm cli
            RunVirtualMachine();

__guest_eip:     
        __asm popfd
        __asm popad
    }

    RtlInitUnicodeString(&us_device, szDevice);
    status = IoCreateDevice(pDriverObject,
        0,
        &us_device,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDeviceObject);

    RtlInitUnicodeString(&us_symlink, szSymlink);
    IoCreateSymbolicLink(&us_device, &us_symlink); 

    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MJ_CreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = MJ_CreateClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ServiceHandle;
    //pDriverObject->DriverUnload = unloadme;

    return STATUS_SUCCESS;
}

