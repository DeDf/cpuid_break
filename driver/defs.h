#include "ntifs.h"

__declspec(dllimport) NTSTATUS KeSetAffinityThread(IN PKTHREAD, IN KAFFINITY);

#define IA32_VMX_BASIC          0x480
#define IA32_VMX_PINBASED_CTLS  0x481
#define IA32_VMX_PROCBASED_CTLS 0x482
#define IA32_VMX_EXIT_CTLS      0x483
#define IA32_VMX_ENTRY_CTLS     0x484

#define IA32_SYSENTER_CS   0x174
#define IA32_SYSENTER_ESP  0x175
#define IA32_SYSENTER_EIP  0x176


typedef struct
{
    ULONG Lo;
    ULONG Hi;
}MSR, *PMSR;

typedef struct {
        unsigned VmxRegionSize:12;
        unsigned ClearBit:1;
        unsigned Reserved1:3;
        unsigned PhysicalWidth:1;
        unsigned DualMonitor:1;
        unsigned MemoryType:4;
        unsigned VmExitInformation:1;
        unsigned Reserved2:9;
}VMX_BASIC_MSR_HI, *P_VMX_BASIC_MSR_HI;

typedef struct {
        unsigned SegmentType:4;
        unsigned DescriptorType:1;
        unsigned Dpl:2;
        unsigned Present:1;
        unsigned Reserved1:4;
        unsigned Available:1;
        unsigned Reserved2:1;           //used only for CS segment
        unsigned DefaultOperationSize:1;
        unsigned Granularity:1;
        unsigned SegmentUnusable:1;
        unsigned Reserved3:15;
}SEGMENT_ACCESS_RIGHTS, *PSEGMENT_ACCESS_RIGHTS;
 
typedef struct {
        unsigned SegmentLimitLo:16;
        unsigned BaseLow:16;
        unsigned BaseMid:8;
        unsigned Type:4;
        unsigned DescriptorType:1;
        unsigned Dpl:2;
        unsigned Present:1;
        unsigned SegmentLimitHi:4;
        unsigned Available:1;
        unsigned L:1;                   //same as reserved2 in SEGMENT_ACCESS_RIGHTS
        unsigned DefaultOperationSize:1;
        unsigned Granularity:1;
        unsigned BaseHi:8;
}GDT_ENTRY, *PGDT_ENTRY;
        
typedef struct{
        unsigned OffsetLow:16;
        unsigned SegmentSelector:16;
        unsigned Reserved:5;
        unsigned Reverved1:3;
        unsigned Type:3;
        unsigned Size:1;
        unsigned Reserved2:1;
        unsigned Dpl:2;
        unsigned Present:1;
        unsigned OffsetHigh:16;
}IDT_ENTRY, *PIDT_ENTRY;

typedef struct{
        unsigned Limit:16;
        unsigned BaseLo:16;
        unsigned BaseHi:16;
}IDT, *PIDT, GDT, *PGDT;

typedef struct{
        unsigned NumberOfControlRegister:4;
        unsigned AccessType:2;
        unsigned LMSWOperandType:1;
        unsigned Reserved:1;
        unsigned Register:4;
        unsigned Reserved1:4;
        unsigned LMSWSourceData:8;
        unsigned Reserved2:16;
}MOV_CR_EQUALIFICATION, *PMOV_CR_EQUALIFICATION;   

typedef struct{
        unsigned Selector:16;
        unsigned Reserved:14;
        unsigned SourceOfTaskSwitch:2;
}TASK_SWITCH_EQUALIFICATION, *PTASK_SWITCH_EQUALIFICATION;

typedef struct{
        unsigned Vector:8;
        unsigned InteruptionType:3;
        unsigned DeliverErrorCode:1;
        unsigned NMIUnblocking:1;
        unsigned Reserved:18;
        unsigned Valid:1;
}INTERUPTION_INFORMATION_FIELD, *PINTERUPTION_INFORMATION_FIELD;



typedef struct{
        ULONG   regEdi;
        ULONG   regEsi;
        ULONG   regEbp;
        ULONG   regEsp;
        ULONG   regEbx;
        ULONG   regEdx;
        ULONG   regEcx;
        ULONG   regEax;
}PUSHAD_REGS, *PPUSHAD_REGS;

typedef struct _KiIoAccessMap{                                                                       
/*0x000*/     UINT8        DirectionMap[32];                                      
/*0x020*/     UINT8        IoMap[8196];                                           
}KiIoAccessMap, *PKiIoAccessMap;

typedef struct _KTSS{                                                                           
/*0x000*/      UINT16       Backlink;                                                  
/*0x002*/      UINT16       Reserved0;                                                 
/*0x004*/      ULONG32      Esp0;                                                      
/*0x008*/      UINT16       Ss0;                                                       
/*0x00A*/      UINT16       Reserved1;                                                 
/*0x00C*/      ULONG32      NotUsed1[4];                                               
/*0x01C*/      ULONG32      CR3;                                                       
/*0x020*/      ULONG32      Eip;                                                       
/*0x024*/      ULONG32      EFlags;                                                    
/*0x028*/      ULONG32      Eax;                                                       
/*0x02C*/      ULONG32      Ecx;                                                       
/*0x030*/      ULONG32      Edx;                                                       
/*0x034*/      ULONG32      Ebx;                                                       
/*0x038*/      ULONG32      Esp;                                                       
/*0x03C*/      ULONG32      Ebp;                                                       
/*0x040*/      ULONG32      Esi;                                                       
/*0x044*/      ULONG32      Edi;                                                       
/*0x048*/      UINT16       Es;                                                        
/*0x04A*/      UINT16       Reserved2;                                                 
/*0x04C*/      UINT16       Cs;                                                        
/*0x04E*/      UINT16       Reserved3;                                                 
/*0x050*/      UINT16       Ss;                                                        
/*0x052*/      UINT16       Reserved4;                                                 
/*0x054*/      UINT16       Ds;                                                        
/*0x056*/      UINT16       Reserved5;                                                 
/*0x058*/      UINT16       Fs;                                                        
/*0x05A*/      UINT16       Reserved6;                                                 
/*0x05C*/      UINT16       Gs;                                                        
/*0x05E*/      UINT16       Reserved7;                                                 
/*0x060*/      UINT16       LDT;                                                       
/*0x062*/      UINT16       Reserved8;                                                 
/*0x064*/      UINT16       Flags;                                                     
/*0x066*/      UINT16       IoMapBase;                                                 
/*0x068*/      struct _KiIoAccessMap IoMaps[1];                                        
/*0x208C*/     UINT8        IntDirectionMap[32];                                       
}KTSS, *PKTSS;

typedef struct {
    ULONG LocalApicId;
    ULONG ProcessorNumber;
}INTERNAL_PROCESSOR_ID, *PINTERNAL_PROCESSOR_ID;

extern INTERNAL_PROCESSOR_ID cpu_id[32];

//#define ccpu    KeGetCurrentProcessorNumber()
#define ccpu MyKeGetCurrentProcessorNumber()
#define SET_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#if DBG
#define DbgLog(format, value) { DbgPrint("%-50s cpu:[%X][%08X]\n", format, ccpu, value); }
#else
#define DbgLog(format, value)
#endif

ULONG GetCr4(VOID);

#define ReadMSR(msr_id) \
    _asm  mov  ecx, msr_id \
    _asm  rdmsr \
    _asm  mov  msr.Lo, eax \
    _asm  mov  msr.Hi, edx

VOID  WriteMSR(ULONG);
VOID  RunVirtualMachine(VOID);
BOOLEAN VmxON(ULONG);

BOOLEAN VmClear(ULONG);
VOID VmPtrld(ULONG);
VOID VmWrite(ULONG, ULONG);
ULONG VmRead(ULONG);
ULONG SegmentSelectorToAccessRights(ULONG);
ULONG GetSegmentLimit(ULONG);
ULONG GetSegmentBase(ULONG);
ULONG SegmentSelectorToAccessRightsGuest(ULONG);
ULONG GetSegmentLimitGuest(ULONG);
ULONG GetSegmentBaseGuest(ULONG);
ULONG GetSegmentBaseVMX(ULONG);
ULONG MyKeGetCurrentProcessorNumber(VOID);


VOID VM_Entry(VOID);
VOID InjectNMI(VOID);
VOID HandleCr(PPUSHAD_REGS, PMOV_CR_EQUALIFICATION);
VOID HandleTaskSwitch(PPSUAHD_REGS, PTASK_SWITCH_EQUALIFICATION);
ULONG HandleVMX(PPUSHAD_REGS);
VOID VMX_NMI(VOID);

VOID RaiseIrql(VOID);
VOID LowerIrql(VOID);

NTSTATUS ServiceHandle(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS MJ_CreateClose(IN PDEVICE_OBJECT, IN PIRP);
VOID ProcessNotifyRoutine(IN HANDLE, IN HANDLE, IN BOOLEAN);
