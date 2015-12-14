//Helper routines for vm driver

/*
        routines to get CPU number from Local APIC ID
                - InitMyKeGetCurrentProcessorNumber()
                  init internal structs used later on to extract
                  cpu number based on local APIC id, must be running
                  at PASSIVE_LEVEL
                - MyKeGetCurrentProcessorNumber()
                  returns CPU number based on local APIC id, it can
                  be called at any IRQL...
                  
        routines to raise/lower IRQL
                - RaiseIrql
                  raise IRQL to HIGH_LEVEL by directly setting TPR to 0xFF
                - LowerIrql
                  lower IRQL to old IRQL by directly setting TPR
                  Each call to RaiseIrql must be followed by LowerIrql
                  otherwise behaviour is undefined...
*/
#include "defs.h"

INTERNAL_PROCESSOR_ID cpu_id[32];

//this routine may run at any given IRQL...        
ULONG MyKeGetCurrentProcessorNumber(VOID)
{
    PULONG local_apic = (PULONG)0xFFFE0020;
    UCHAR i;

    for (i = 0; i < KeNumberProcessors; i++)
    {
        if (cpu_id[i].LocalApicId == *local_apic)
            return cpu_id[i].ProcessorNumber;
    }

    return 0;
}

ULONG old_tpr[32];

//internal procedures to raise and lower irql...
VOID HighLevel(VOID)
{
        PULONG tpr = (PULONG)0xFFFE0080;
        old_tpr[ccpu] = *tpr;
        *tpr = 0xFF;
}

VOID OldLevel(VOID)
{
        PULONG tpr = (PULONG)0xFFFE0080;
        *tpr = old_tpr[ccpu];
}

        
VOID __declspec(naked)RaiseIrql(VOID)
{
        __asm{
                pushad
                pushfd
                call    HighLevel
                popfd
                popad
                retn
        }
}

VOID __declspec(naked)LowerIrql(VOID)
{
        __asm{
                pushad
                pushfd
                call    OldLevel
                popfd
                popad
                retn
        }
}        
        