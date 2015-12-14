#include "defs.h"

extern MSR msr;
extern PVOID vmx_idt[32];
extern PVOID vmx_gdt[32];

__declspec(naked)
ULONG GetCr4(VOID)
{
    __asm
    {
        _emit   0x0F    ;mov eax, cr4
        _emit   0x20
        _emit   0xE0

        ret
    }
}

__declspec(naked)
VOID WriteMSR(ULONG msr_id)
{
        __asm
        {
                mov     eax, msr.Lo
                mov     edx, msr.Hi
                mov     ecx, [esp+4]
                wrmsr

                ret 4
        }
}

__declspec(naked)
BOOLEAN VmxON(ULONG PhysicalLow)
{
        __asm
        {
                push    0
                push    [esp+8]
                _emit   0xF3
                _emit   0x0F
                _emit   0xC7
                _emit   0x34
                _emit   0x24

                pushfd
                pop     eax
                add     esp, 8

                bt      eax, 0
                setc    al

                ret 4
        }
}

__declspec(naked)
BOOLEAN VmClear(ULONG PhysicalLow)
{
        __asm{
                push    0
                push    [esp+8]
                _emit   0x66
                _emit   0x0F
                _emit   0xC7
                _emit   0x34
                _emit   0x24
                
                pushfd
                pop     eax
                add     esp, 8
                
                bt      eax, 0
                setc    al
                bt      eax, 6
                adc     al,  0

                ret 4
        }
}

__declspec(naked)
VOID VmPtrld(ULONG PhysicalLow)
{
        __asm{
                push    0
                push    [esp+8]
                _emit   0x0F
                _emit   0xC7
                _emit   0x34
                _emit   0x24
                add     esp, 8

                ret 4
        }
}

__declspec(naked)
VOID VmWrite(ULONG vmcs_entry, ULONG value)
{
        __asm{
                mov     eax, [esp+4]
                mov     ecx, [esp+8]
                _emit   0x0F
                _emit   0x79
                _emit   0xC1

                ret 8
        }
}            
                
__declspec(naked)            
ULONG VmRead(ULONG vmcs_entry)
{
        __asm{
                mov     ecx, [esp+4]
                _emit   0x0F
                _emit   0x78
                _emit   0xC8

                ret 4
        }
}

ULONG SegmentSelectorToAccessRights(ULONG SegmentSelector)
{
        ULONG ret_value = 0;
        PSEGMENT_ACCESS_RIGHTS pAccessRights;
        PGDT_ENTRY pgdt_entry;
        GDT gdt_base;
        ULONG index;
        
        __asm sgdt gdt_base;
        
        index = SegmentSelector >> 3;
        
        pgdt_entry = (PGDT_ENTRY)(gdt_base.BaseLo + (gdt_base.BaseHi << 16));
        
        pAccessRights = (PSEGMENT_ACCESS_RIGHTS)&ret_value;
        
        __asm{
                pushad
                mov     eax, pgdt_entry
                mov     ecx, index
                shl     ecx, 3
                add     eax, ecx
                add     eax, 5
                mov     eax, [eax]
                and     eax, 0F0FFh
                mov     ret_value, eax
                popad
        }
                
        
        /*
        pAccessRights->SegmentType    = pgdt_entry[index].Type;
        pAccessRights->DescriptorType = pgdt_entry[index].DescriptorType;
        pAccessRights->Dpl            = pgdt_entry[index].Dpl;
        pAccessRights->Present        = pgdt_entry[index].Present;
        pAccessRights->Available      = pgdt_entry[index].Available;
        pAccessRights->DefaultOperationSize = pgdt_entry[index].DefaultOperationSize;
        */
        if (SegmentSelector == 0x30)
                pAccessRights->Granularity = 0; //pgdt_entry[index].Granularity;
        //if (SegmentSelector == 0x3B)
        //        pAccessRights->Granularity = 0;
          
        return ret_value;
}   

ULONG GetSegmentLimit(ULONG SegmentSelector)
{
    ULONG ret_value = 0;
    PGDT_ENTRY pgdt_entry;
    GDT gdt_base;
    ULONG index;

    __asm sgdt gdt_base;
    index = SegmentSelector >> 3;
    pgdt_entry = (PGDT_ENTRY)(gdt_base.BaseLo + (gdt_base.BaseHi << 16));

    ret_value = pgdt_entry[index].SegmentLimitLo + (pgdt_entry[index].SegmentLimitHi << 16);

    if (pgdt_entry[index].Granularity)
        ret_value *= 0x1000;

    return ret_value;
}

ULONG GetSegmentBase(ULONG SegmentSelector)
{
    ULONG ret_value = 0;
    PGDT_ENTRY pgdt_entry;
    GDT gdt_base;
    ULONG index;

    index = SegmentSelector >> 3;

    __asm sgdt gdt_base
        pgdt_entry = (PGDT_ENTRY)(gdt_base.BaseLo + (gdt_base.BaseHi << 16));

    ret_value = pgdt_entry[index].BaseLow + 
        (pgdt_entry[index].BaseMid << 16) + 
        (pgdt_entry[index].BaseHi << 24);

    return ret_value;
}

ULONG GetSegmentBaseVMX(ULONG SegmentSelector)
{
        ULONG ret_value = 0;
        PGDT_ENTRY pgdt_entry;
        GDT gdt_base;
        ULONG index;
        
        index = SegmentSelector >> 3;
        
        pgdt_entry = (PGDT_ENTRY)vmx_gdt[ccpu];
        
        ret_value = pgdt_entry[index].BaseLow + 
                    (pgdt_entry[index].BaseMid << 16) + 
                    (pgdt_entry[index].BaseHi << 24);
        
        return ret_value;
}

ULONG SegmentSelectorToAccessRightsGuest(ULONG SegmentSelector)
{
        ULONG ret_value = 0;
        PSEGMENT_ACCESS_RIGHTS pAccessRights;
        PGDT_ENTRY pgdt_entry;
        GDT gdt_base;
        ULONG index;
        
        index = SegmentSelector >> 3;
        
        pgdt_entry = (PGDT_ENTRY)VmRead(0x6816);
        
        pAccessRights = (PSEGMENT_ACCESS_RIGHTS)&ret_value;
        
        __asm{
                pushad
                mov     eax, pgdt_entry
                mov     ecx, index
                shl     ecx, 3
                add     eax, ecx
                add     eax, 5
                mov     eax, [eax]
                and     eax, 0F0FFh
                mov     ret_value, eax
                popad
        }
                
        
        /*
        pAccessRights->SegmentType = pgdt_entry[index].Type;
        pAccessRights->DescriptorType = pgdt_entry[index].DescriptorType;
        pAccessRights->Dpl = pgdt_entry[index].Dpl;
        pAccessRights->Present = pgdt_entry[index].Present;
        pAccessRights->Available = pgdt_entry[index].Available;
        pAccessRights->DefaultOperationSize = pgdt_entry[index].DefaultOperationSize;
        */
        if (SegmentSelector == 0x30)
                pAccessRights->Granularity = 0; //pgdt_entry[index].Granularity;

        //if (SegmentSelector == 0x3B)
        //        pAccessRights->Granularity = 0;
                     
        return ret_value;
}   

ULONG GetSegmentLimitGuest(ULONG SegmentSelector)
{
        ULONG ret_value = 0;
        PGDT_ENTRY pgdt_entry;
        GDT gdt_base;
        ULONG index;
        
        pgdt_entry = (PGDT_ENTRY)VmRead(0x6816);
        index = SegmentSelector >> 3;
        
        ret_value = pgdt_entry[index].SegmentLimitLo + (pgdt_entry[index].SegmentLimitHi << 16);
        
        if (pgdt_entry[index].Granularity)
                ret_value *= 0x1000;

        return ret_value;
}

ULONG GetSegmentBaseGuest(ULONG SegmentSelector)
{
        ULONG ret_value = 0;
        PGDT_ENTRY pgdt_entry;
        GDT gdt_base;
        ULONG index;
        
        index = SegmentSelector >> 3;
        
        pgdt_entry = (PGDT_ENTRY)VmRead(0x6816);
         
        ret_value = pgdt_entry[index].BaseLow + 
                    (pgdt_entry[index].BaseMid << 16) + 
                    (pgdt_entry[index].BaseHi << 24);
        
        return ret_value;
}             

/*
        Used to determine if in asymetric OS such as windows, NMI is 
        delivered to 2nd CPU while we are in vmx-root on 2nd cpu...
        This is possible as vm-exits occur constantly on windows due
        to mov cr3, eax in SwapContext... 

*/

VOID InjectNMI(VOID)
{
        ULONG dummy = 0;
        PINTERUPTION_INFORMATION_FIELD pinject_event =
            (PINTERUPTION_INFORMATION_FIELD)&dummy;
        
        //nmi was delivered from 2nd CPU while we were in vmx-root 
        //so inject NMI to this processor so it can be handled by
        //NMI in vmx-non-root code... 
             
        pinject_event->Vector = 2;
        pinject_event->InteruptionType  = 2;    //NMI
        pinject_event->DeliverErrorCode = 0;
        pinject_event->Valid = 1;
        VmWrite(0x4016, dummy); 
        
        //dummy = VmRead(0x4824);
        //__asm bts dummy, 3
        //VmWrite(0x4824, dummy); 
        //inject_nmi[ccpu] = 0;    
}

ULONG inject_nmi[32];      
UCHAR *logstr = "NMI executed from vmx-root\n";

__declspec(naked)
VOID VMX_NMI(VOID)
{
        __asm
        {
                cli
                pushad
                pushfd
                call    InjectNMI
                popfd
                popad
                iretd   
                jmp     VMX_NMI
        }
}

        
                
                
                
                
                
                