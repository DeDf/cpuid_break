#include "defs.h"

#define vmlaunch        __asm   _emit   0x0f\
                        __asm   _emit   0x01\
                        __asm   _emit   0xC2

#define vmresume        __asm   _emit   0x0f\
                        __asm   _emit   0x01\
                        __asm   _emit   0xC3

extern PULONG  pVMXONRegion[32];
extern PULONG  pVMCSRegion[32];
extern PULONG  vmxStack[32];
extern PHYSICAL_ADDRESS physicalVMXONRegion[32];
extern PHYSICAL_ADDRESS physicalVMCSRegion[32];
extern MSR msr;
extern ULONG current_cpu;
extern ULONG GuestStack;
extern ULONG GuestEip;
extern PVOID vmx_idt[32];
extern PVOID vmx_gdt[32];
extern ULONG inject_nmi[32];
extern ULONG traced_cr3;

ULONG  reg_eax;
IDT idt_base;
GDT gdt_base;
ULONG dummy;
PSEGMENT_ACCESS_RIGHTS pSegmentAccessRights;

VOID RunVirtualMachine()
{
        if (VmxON(physicalVMXONRegion[current_cpu].LowPart)){
                DbgPrint("CPU[%X] VmxON   Failed!\n", current_cpu);
                return;
        }
        
        if (VmClear(physicalVMCSRegion[current_cpu].LowPart)){
                DbgPrint("CPU[%X] VMCLEAR Failed!\n", current_cpu);
                return;
        }
        
        VmPtrld(physicalVMCSRegion[current_cpu].LowPart);
        
        /*
                Prepare VMCS for execution
        */

        //===============================
//         __asm   xor eax, eax
//         __asm   mov ax, es
//         __asm   mov dummy, eax
//         DbgLog("Guest ES Selector", dummy);
//         VmWrite(0x800, dummy);
        //===============================

// vmwrite eax, ecx
#define VMWRITE_OPCODE \
        _asm _emit 0x0F \
        _asm _emit 0x79 \
        _asm _emit 0xC1

#if DBG
#define MOV_DUMMY_ECX  __asm  mov dummy, ecx
#define XOR_ECX_ECX    __asm  xor ecx, ecx
#else
#define MOV_DUMMY_ECX
#define XOR_ECX_ECX
#endif
        
        __asm   xor ecx, ecx

        //H.1.1 16-Bit Guest-State Fields

        //Guest ES selector 000000000B 00000800H
        XOR_ECX_ECX
        __asm   mov eax, 0x800
        __asm   mov cx, es
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest ES Selector", dummy);
        
        //Guest CS selector 000000001B 00000802H
        XOR_ECX_ECX
        __asm   mov eax, 0x802
        __asm   mov cx, cs
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest CS Selector", dummy);
        
        //Guest SS selector 000000010B 00000804H
        XOR_ECX_ECX
        __asm   mov eax, 0x804
        __asm   mov cx, ss
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest SS selector", dummy);
        
        //Guest DS selector 000000011B 00000806H
        XOR_ECX_ECX
        __asm   mov eax, 0x806
        __asm   mov cx, ds
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest DS Selector", dummy);

        //Guest FS selector 000000100B 00000808H
        XOR_ECX_ECX
        __asm   mov eax, 0x808
        __asm   mov cx, fs
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest FS Selector", dummy);
        
        //Guest GS selector 000000101B 0000080AH
        XOR_ECX_ECX
        __asm   mov eax, 0x80A
        __asm   mov cx, gs
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest GS Selector", dummy);
        
        //Guest LDTR selector 000000110B 0000080CH
        XOR_ECX_ECX
        __asm   mov eax, 0x80C
        __asm   mov cx, 0
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest LDTR selector", dummy);
        
        //Guest TR selector 000000111B 0000080EH
        XOR_ECX_ECX
        __asm   mov eax, 0x80E
        __asm   str cx
        MOV_DUMMY_ECX
        VMWRITE_OPCODE
        DbgLog("Guest TR Selector", dummy);
                
        //H.1.2 16-Bit Host-State Fields
        /*
        22.2.3 Checks On Host Segment and Descriptor-Table Registers
        
        In the selector field for each of CS, SS, DS, ES, FS, GS, and TR, 
        the RPL (bits 1:0) and the TI flag (bit 2) must be 0.
        */
        __asm{
                xor     ecx, ecx

                // Host ES selector 000000000B 00000C00H
                ;mov     ax, es
                mov     cx, 10h
                and     cx, 0FFFCh
                mov     eax,0C00h
                VMWRITE_OPCODE
                
                // Host CS selector 000000001B 00000C02H
                ;mov     ax, cs
                mov     cx, 8
                and     cx, 0FFFCh
                mov     eax,0c02h
                VMWRITE_OPCODE
                
                // Host SS selector 000000010B 00000C04H
                ;mov     cx, ss
                mov     cx, 10h
                and     cx, 0FFFCh
                mov     eax,0c04h
                VMWRITE_OPCODE
                
                // Host DS selector 000000011B 00000C06H
                ;mov     cx, ds
                mov     cx, 10h
                and     cx, 0FFFCh
                mov     eax,0c06h
                VMWRITE_OPCODE
                
                // Host FS selector 000000100B 00000C08H
                mov     cx, fs
                and     cx, 0FFFCh
                mov     eax,0c08h
                VMWRITE_OPCODE
                
                // Host GS selector 000000101B 00000C0AH
                mov     cx, gs
                and     cx, 0FFFCh
                mov     eax,0c0Ah
                VMWRITE_OPCODE
                
                // Host TR selector 000000110B 00000C0CH
                str     cx
                and     cx, 0FFFCh
                mov     eax,0c0ch
                VMWRITE_OPCODE
        }
        
        //H.2.2 64-Bit Guest-State Fields
        /*
        VMCS link pointer (full) 000000000B 00002800H
        VMCS link pointer (high) 000000000B 00002801H
        Guest IA32_DEBUGCTL (full) 000000001B 00002802H
        Guest IA32_DEBUGCTL (high) 000000001B 00002803H
        */
        
        DbgLog("VMCS link pointer (full)", 0xFFFFFFFF);
        DbgLog("VMCS link pointer (high)", 0xFFFFFFFF);
        VmWrite(0x2800, 0xFFFFFFFF);
        VmWrite(0x2801, 0xFFFFFFFF);
        
        ReadMSR(0x1D9);
        
        DbgLog("Guest IA32_DEBUGCTL (full)", msr.Lo);
        DbgLog("Guest IA32_DEBUGCTL (high)", msr.Hi);
        VmWrite(0x2802, msr.Lo);
        VmWrite(0x2803, msr.Hi);    
        
        //H.3.1 32-Bit Control Fields
        
        /*
        Pin-based VM-execution controls 000000000B 00004000H
        Primary processor-based VM-execution controls 000000001B 00004002H
        Exception bitmap 000000010B 00004004H
        Page-fault error-code mask 000000011B 00004006H
        Page-fault error-code match 000000100B 00004008H
        CR3-target count 000000101B 0000400AH
        VM-exit controls 000000110B 0000400CH
        VM-exit MSR-store count 000000111B 0000400EH
        VM-exit MSR-load count 000001000B 00004010H
        VM-entry controls 000001001B 00004012H
        VM-entry MSR-load count 000001010B 00004014H
        VM-entry interruption-information field 000001011B 00004016H            <---- used for event injection...
        VM-entry exception error code 000001100B 00004018H                      <---- used for event injection...
        VM-entry instruction length 000001101B 0000401AH                        <---- used for event injection...
        */
        //determine Pin based settings...
        ReadMSR(IA32_VMX_PINBASED_CTLS);
        
        //Lo part gives allowed 0 setting bits...
        //Hi part gives allowed 1 setting bits...
        //as I don't set anything here then clear all bits in msr.Hi
        //__asm int 3
        msr.Hi &= msr.Lo;
        //set NMI exiting
        __asm bts msr.Hi, 3
        DbgLog("IA_32_VMX_PINBASED_CTLS", msr.Hi);
        VmWrite(0x4000, msr.Hi);
        
        //primary processor-based VM-execution... only need low part as nothing else is interesting here for me
        ReadMSR(IA32_VMX_PROCBASED_CTLS);
        msr.Hi &= msr.Lo;
        DbgLog("IA32_VMX_PROCBASED_CTLS", msr.Hi);
        VmWrite(0x4002, msr.Hi);        //this should disable secondary processor-based vm-execution controls due to 0 in 31bit...
        
        /*
                Exception bitmap is very usefull when writing VMX debugger as it's possible to cause VmExit on 
                certain exception which coder would like to control. Very usefull for x64 system ring0 debugging,
                as this fully bypasses windows Patch Guard...
        
        */
        DbgLog("Exception bitmap", 0);
        VmWrite(0x4004, 0);             
        
        DbgLog("Page fault error-code mask", 0);
        VmWrite(0x4006, 0);
        DbgLog("Page fault error-code match", 0);
        VmWrite(0x4008, 0);
        
        //mov to CR3 always generates vm_exit... heh
        //VmWrite(0x400A, 0);
        
        ReadMSR(IA32_VMX_EXIT_CTLS);
        msr.Hi &= msr.Lo;
        DbgLog("IA_32_VMX_EXIT_CTLS", msr.Hi);
        VmWrite(0x400C, msr.Hi);
        
        //vm-exit MSR-store and MSR-load count...
        //VmWrite(0x400E, 0);
        //VmWrite(0x4010, 0);
        
        ReadMSR(IA32_VMX_ENTRY_CTLS);
        msr.Hi &= msr.Lo;
        DbgLog("IA32_VMX_ENTRY_CTLS", msr.Hi);
        VmWrite(0x4012, msr.Hi);
        //DbgLog("VM_entry MSR load count", 0);
        //VmWrite(0x4014, 0);
        
        
        //H.3.3 32-Bit Guest-State Fields
        /*
        Guest ES limit 000000000B 00004800H
        Guest CS limit 000000001B 00004802H
        Guest SS limit 000000010B 00004804H
        Guest DS limit 000000011B 00004806H
        Guest FS limit 000000100B 00004808H
        Guest GS limit 000000101B 0000480AH
        Guest LDTR limit 000000110B 0000480CH
        Guest TR limit 000000111B 0000480EH
        Guest GDTR limit 000001000B 00004810H
        Guest IDTR limit 000001001B 00004812H
        Guest ES access rights 000001010B 00004814H
        Guest CS access rights 000001011B 00004816H
        Guest SS access rights 000001100B 00004818H
        Guest DS access rights 000001101B 0000481AH
        Guest FS access rights 000001110B 0000481CH
        Guest GS access rights 000001111B 0000481EH
        Guest LDTR access rights 000010000B 00004820H
        Guest TR access rights 000010001B 00004822H
        Guest interruptibility state 000010010B 00004824H               <----- blah, blah
        Guest activity state 000010011B 00004826H                       <----- blah, blah
        Guest SMBASE 000010100B 00004828H                               
        Guest IA32_SYSENTER_CS 000010101B 0000482AH
        */
        
        //Guest ES limit
        DbgLog("Guest ES limit", 0xFFFFFFFF);
        VmWrite(0x4800, 0xFFFFFFFF);
        //Gues CS limit
        DbgLog("Guest CS limit", 0xFFFFFFFF);
        VmWrite(0x4802, 0xFFFFFFFF);
        //guest SS limit
        DbgLog("Guest SS limit", 0xFFFFFFFF);
        VmWrite(0x4804, 0xFFFFFFFF);
        //guest DS limit
        DbgLog("Guest DS limit", 0xFFFFFFFF);
        VmWrite(0x4806, 0xFFFFFFFF);
        //guest FS limit
        __asm xor eax, eax
        __asm mov ax, fs
        __asm mov dummy, eax
        
        dummy = GetSegmentLimit(dummy);
        DbgLog("Guest FS limit", dummy);
        VmWrite(0x4808, dummy);
        
        //guest GS limit
        __asm   xor eax, eax
        __asm   mov ax, gs
        __asm   mov dummy, eax
        dummy = GetSegmentLimit(dummy);
        DbgLog("Guest GS limit", dummy);
        VmWrite(0x480A, 0xFFFFFFFF);                     //GS is not used on windows
        
        //LDTR limit
        //VmWrite(0x480C, 0);
        
        //TR limit
        __asm   xor eax, eax
        __asm   str ax
        __asm   mov dummy, eax
        
        dummy = GetSegmentLimit(dummy);
        DbgLog("Guest TR limit", dummy);
        VmWrite(0x480E, dummy);
        
        //ES Access rights
        __asm   xor eax, eax
        __asm   mov ax, es
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("ES Access rights", dummy);
        VmWrite(0x4814, dummy);
        //CS Access rights 0x4816
        
        __asm   xor eax, eax
        __asm   mov ax, cs
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("CS Access rights", dummy);
        VmWrite(0x4816, dummy);

        //SS Access rights 0x4818
        
        __asm   xor eax, eax
        __asm   mov ax, ss
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("SS Access rights", dummy);
        VmWrite(0x4818, dummy);


        //DS Access rights 0x481A
        __asm   xor eax, eax
        __asm   mov ax, ds
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("DS Access rights", dummy);
        VmWrite(0x481A, dummy);
        
        //FS access rights 0x481C
        __asm   xor eax, eax
        __asm   mov ax, fs
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("FS Access rights", dummy);
        VmWrite(0x481C, dummy);
        
        //Guest GS access rights 000001111B 0000481EH
        
        __asm   xor eax, eax
        __asm   mov ax, gs
        __asm   mov dummy, eax

        dummy = 0;
        pSegmentAccessRights = (PSEGMENT_ACCESS_RIGHTS)&dummy;
        
        pSegmentAccessRights->SegmentUnusable = 1;
                
        //dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("GS Access rights", dummy);
        VmWrite(0x481E, dummy);
        
        
        //LDTR access rights 0x4820
        dummy = 0;
        pSegmentAccessRights = (PSEGMENT_ACCESS_RIGHTS)&dummy;
        
        pSegmentAccessRights->SegmentUnusable = 1;
        DbgLog("LDTR Access rights", dummy);
        VmWrite(0x4820, dummy);
        
        //TR access rights 0x4822
        __asm   xor eax, eax
        __asm   str ax
        __asm   mov dummy, eax
        
        dummy = SegmentSelectorToAccessRights(dummy);
        DbgLog("TR Access rights", dummy);
        VmWrite(0x4822, dummy);
        

        
        __asm sgdt gdt_base
        __asm sidt idt_base
        //GDTR limit...
        dummy = gdt_base.Limit;
        DbgLog("Guest GDT Limit", dummy);
        VmWrite(0x4810,  dummy);
        
        //IDTR limit...
        dummy = idt_base.Limit;
        DbgLog("Guest IDT Limit", dummy);
        VmWrite(0x4812, dummy);
        
        //Guest IA32_SYSENTER_CS 000010101B 0000482AH
        ReadMSR(IA32_SYSENTER_CS);
        VmWrite(0x482A, msr.Lo);
        
        //H.3.4 32-Bit Host-State Field
        //Host IA32_SYSENTER_CS 000000000B 00004C00H
        
        ReadMSR(IA32_SYSENTER_CS);
        VmWrite(0x4C00, msr.Lo);
        
        /*
        Guest CR0 000000000B 00006800H
        Guest CR3 000000001B 00006802H
        Guest CR4 000000010B 00006804H
        Guest ES base 000000011B 00006806H
        Guest CS base 000000100B 00006808H
        Guest SS base 000000101B 0000680AH
        Guest DS base 000000110B 0000680CH
        Guest FS base 000000111B 0000680EH
        Guest GS base 000001000B 00006810H
        Guest LDTR base 000001001B 00006812H
        Guest TR base 000001010B 00006814H
        Guest GDTR base 000001011B 00006816H
        Guest IDTR base 000001100B 00006818H
        Guest DR7 000001101B 0000681AH
        Guest RSP 000001110B 0000681CH
        Guest RIP 000001111B 0000681EH
        Guest RFLAGS 000010000B 00006820H
        Guest pending debug exceptions 000010001B 00006822H
        Guest IA32_SYSENTER_ESP 000010010B 00006824H
        Guest IA32_SYSENTER_EIP 000010011B 00006826H
        */
        
        //Guest Cr0 0x6800
        
        __asm   mov eax, cr0
        __asm   mov dummy, eax
        DbgLog("Guest CR0", dummy);
        VmWrite(0x6800, dummy);
        
        //Guest Cr3 0x6802
        __asm   mov eax, cr3
        __asm   mov dummy, eax
        DbgLog("Guest CR3", dummy);
        VmWrite(0x6802, dummy);
        
        //Guest cr4 0x6804
        dummy = GetCr4();
        DbgLog("Guest CR4", dummy);
        VmWrite(0x6804, dummy);
        
        
        //        Guest ES base 000000011B 00006806H
        //        Guest CS base 000000100B 00006808H
        //        Guest SS base 000000101B 0000680AH
        //        Guest DS base 000000110B 0000680CH
        //        Guest FS base 000000111B 0000680EH
        //        Guest GS base 000001000B 00006810H
        
        __asm   xor eax, eax
        __asm   mov ax, es
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest ES base", dummy);
        VmWrite(0x6806, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, cs
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest CS base", dummy);
        VmWrite(0x6808, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, ss
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest SS base", dummy);
        VmWrite(0x680A, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, ds
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest DS base", dummy);
        VmWrite(0x680C, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, fs
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest FS base", dummy);
        VmWrite(0x680E, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, gs
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest GS base", dummy);
        VmWrite(0x6810, dummy);
        
        //Guest LDTR base 000001001B 00006812H
        //Guest TR base 000001010B 00006814H
        //Guest GDTR base 000001011B 00006816H
        //Guest IDTR base 000001100B 00006818H        

        //VmWrite(0x6812, 0);
        
        __asm   xor eax, eax
        __asm   str ax
        __asm   mov dummy, eax
        
        dummy = GetSegmentBase(dummy);
        DbgLog("Guest TR base", dummy);
        VmWrite(0x6814, dummy);
        
        dummy = gdt_base.BaseLo + (gdt_base.BaseHi << 16);
        DbgLog("Guest GDT base", dummy);
        VmWrite(0x6816, dummy);
        
        dummy = idt_base.BaseLo + (idt_base.BaseHi << 16);
        DbgLog("Guest IDT Base", dummy);
        VmWrite(0x6818, dummy);
        
        //Guest DR7 000001101B 0000681AH
        //Guest RSP 000001110B 0000681CH
        //Guest RIP 000001111B 0000681EH
        //Guest RFLAGS 000010000B 00006820H

        __asm   mov eax, dr7
        __asm   mov dummy, eax
        DbgLog("Guest DR7", dummy);
        VmWrite(0x681A, dummy);
        
        DbgLog("Guest RSP", GuestStack);
        VmWrite(0x681C, GuestStack);
        DbgLog("Guest RIP", GuestEip);
        VmWrite(0x681E, GuestEip);
        __asm pushfd
        __asm pop eax
        __asm mov dummy, eax
        
        DbgLog("Guest RFLAGS", dummy);
        VmWrite(0x6820, dummy);
        
        //Guest IA32_SYSENTER_ESP 000010010B 00006824H
        //Guest IA32_SYSENTER_EIP 000010011B 00006826H
        ReadMSR(IA32_SYSENTER_ESP);
        DbgLog("Guest IA32_SYSENTER_ESP", msr.Lo);
        VmWrite(0x6824, msr.Lo);
        ReadMSR(IA32_SYSENTER_EIP);
        DbgLog("Guest IA32_SYSENTER EIP", msr.Lo);
        VmWrite(0x6826, msr.Lo);
        
        /*
        Host CR0 000000000B 00006C00H
        Host CR3 000000001B 00006C02H
        Host CR4 000000010B 00006C04H
        Host FS base 000000011B 00006C06H
        Host GS base 000000100B 00006C08H
        Host TR base 000000101B 00006C0AH
        Host GDTR base 000000110B 00006C0CH
        Host IDTR base 000000111B 00006C0EH
        Host IA32_SYSENTER_ESP 000001000B 00006C10H
        Host IA32_SYSENTER_EIP 000001001B 00006C12H
        Host RSP 000001010B 00006C14H
        Host RIP 000001011B 00006C16H
        */
        
        __asm mov eax, cr0
        __asm mov dummy, eax
        DbgLog("Host CR0", dummy);
        VmWrite(0x6C00, dummy);
        
        __asm mov eax, cr3
        __asm mov dummy, eax
        DbgLog("Host CR3", dummy);
        VmWrite(0x6C02, dummy);
        
        dummy = GetCr4();
        DbgLog("Host CR4", dummy);
        VmWrite(0x6C04, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, fs
        __asm   mov dummy, eax
        
        dummy = GetSegmentBaseVMX(dummy);
        DbgLog("Host FS base", dummy);
        VmWrite(0x6C06, dummy);
        
        __asm   xor eax, eax
        __asm   mov ax, gs
        __asm   mov dummy, eax
        
        dummy = GetSegmentBaseVMX(dummy);
        DbgLog("Host GS base", dummy);
        VmWrite(0x6C08, dummy);
        
        __asm   xor eax, eax
        __asm   str ax
        __asm   mov dummy, eax
        dummy = GetSegmentBaseVMX(dummy);
        DbgLog("Host TR base", dummy);
        VmWrite(0x6C0A, dummy);
        
        dummy = gdt_base.BaseLo + (gdt_base.BaseHi << 16);
        DbgLog("Host GDT Base", dummy);
        //VmWrite(0x6C0C, dummy);
        VmWrite(0x6C0C, (ULONG)vmx_gdt[ccpu]);
        
        
        dummy = idt_base.BaseLo + (idt_base.BaseHi << 16);
        DbgLog("Host IDT Base", dummy);
        //VmWrite(0x6C0E, dummy);
        VmWrite(0x6C0E, (ULONG)vmx_idt[ccpu]);
        
        ReadMSR(IA32_SYSENTER_ESP);
        VmWrite(0x6C10, msr.Lo);
        ReadMSR(IA32_SYSENTER_EIP);
        VmWrite(0x6C12, msr.Lo);
        
        dummy = (ULONG)vmxStack[current_cpu];
        VmWrite(0x6C14, dummy);
        
        dummy = (ULONG)&VM_Entry;
        VmWrite(0x6C16, dummy);
        
        //Activity state...
        VmWrite(0x4826, 0);
        pVMCSRegion[ccpu][1] = 0;
        
        /*
        __asm int 3
        
        //set host and guest idt tables... 
        __asm sgdt gdt_base
        __asm sidt idt_base
        
        gdt_base.BaseLo  = (ULONG)vmx_gdt[ccpu] & 0xFFFF;
        gdt_base.BaseHi  = (ULONG)vmx_gdt[ccpu] >> 16;
        idt_base.BaseLo  = (ULONG)vmx_idt[ccpu] & 0xFFFF;
        idt_base.BaseHi  = (ULONG)vmx_idt[ccpu] >> 16;
        __asm lgdt gdt_base
        __asm lidt idt_base
        */
        
        vmlaunch
        
        DbgPrint("VM Launch failed... fuck...\n");
        dummy = VmRead(0x4400);
        DbgPrint("Error code : %.08X\n", dummy);
}


/*

Exit reason 000000001B 00004402H
VM-exit interruption information 000000010B 00004404H
VM-exit interruption error code 000000011B 00004406H
IDT-vectoring information field 000000100B 00004408H
IDT-vectoring error code 000000101B 0000440AH
VM-exit instruction length 000000110B 0000440CH
VM-exit instruction information 000000111B 0000440EH


Exit qualification 000000000B 00006400H
*/

ULONG ExitReason[32];
ULONG PrevExitReason[32];
ULONG ExitQualification[32];
ULONG ExitInstructionLength[32];
ULONG ExitEip[32];

PPUSHAD_REGS regs[32];

ULONG ExtractedCr[32];
ULONG GuestESP[32];
ULONG GuestEflags[32];
ULONG NewGuestEIP[32];
BOOLEAN NMI_Active[32];

PMOV_CR_EQUALIFICATION pmovcr[32];

VOID __declspec(naked) VM_Entry(VOID)
{
        __asm{
                cli
                call    RaiseIrql
                pushad
                call    dword ptr[MyKeGetCurrentProcessorNumber]
                mov     regs[eax*4], esp
                
                push    regs[eax*4]
                call    HandleVMX
                
                cmp     eax, 9                  ;task switch
                jne     __cpuid0
                popad
                jmp     resume
                
__cpuid0:       cmp     eax, 10                 ;cpuid...
                jne     __invd
                popad
                cmp     eax, 1
                jne     __nomodcpuid
                cpuid
                ;mov     eax, 0FC0h
                jmp     resume

__nomodcpuid:   cpuid
                jmp     resume
                
__invd:         cmp     eax, 13                 ;invd
                jne     __rdmsr
                popad
                invd
                jmp     resume
                  
__rdmsr:        cmp     eax, 31                 ;rdmsr
                jne     __wrmsr                 
                popad
                rdmsr
                jmp     resume
                
__wrmsr:        cmp     eax, 32                 ;wrmsr
                jne     __vmopcodes
                popad
                wrmsr
                jmp     resume
                
__vmopcodes:    cmp     eax, 18                 ;vmx opcodes
                jb      __checkcr
                cmp     eax, 27
                ja      __checkcr
                popad
                jmp     resume
                   
__checkcr:      cmp     eax, 28                 ;cr access
                jne     __nmi
                popad
                jmp     resume
                
__nmi:          cmp     eax, 0                  ;NMI exiting...
                jne     __nothandled
                popad
                jmp     resume

__nothandled:
                int 3h
                popad
                jmp     resume
                
resume:
                ;sti
                call    LowerIrql
        }
        vmresume
        __asm int 3
        ExitReason[ccpu] = VmRead(0x4402);
        __asm jmp VM_Entry
}
               
        /*
        Exit reason.
                ?Bits 15:0 of this field contain the basic exit reason. It is loaded with a number
                  indicating the general cause of the VM exit. Appendix I lists the numbers used
                  and their meaning.
        */
ULONG HandleVMX(PPUSHAD_REGS x86)
{
        PINTERUPTION_INFORMATION_FIELD pinject_event;
        PINTERUPTION_INFORMATION_FIELD pint;
        ULONG dummy;
         
        PrevExitReason[ccpu] = ExitReason[ccpu];
        ExitReason[ccpu] = VmRead(0x4402);
        ExitReason[ccpu] &= 0xFFFF;
        
        ExitQualification[ccpu] = VmRead(0x6400);
        
        NMI_Active[ccpu] = TRUE;
                
        
        //if (!NMI_Active[ccpu]) DbgLog("Exit reason", ExitReason[ccpu]);
        
        ExitQualification[ccpu] = VmRead(0x6400);
        //if (!NMI_Active[ccpu]) DbgLog("ExitQualification", ExitQualification[ccpu]);
        
        ExitInstructionLength[ccpu] = VmRead(0x440C);
        //if (!NMI_Active[ccpu]) DbgLog("ExitInstructionLength", ExitInstructionLength[ccpu]);
        
        ExitEip[ccpu] = VmRead(0x681E);
        //if (!NMI_Active[ccpu]) DbgLog("ExitEip", ExitEip[ccpu]);
        
        GuestESP[ccpu] = VmRead(0x681C);
        GuestEflags[ccpu] = VmRead(0x6820);
        
        
        NewGuestEIP[ccpu] = ExitEip[ccpu] + ExitInstructionLength[ccpu];

        VmWrite(0x681E, NewGuestEIP[ccpu]);

        //inject int 1 when steping over cpuid...
        //this is also for mov cr, reg when debugging in r0...
        if (GuestEflags[ccpu] & 0x100){
                dummy = 0;
                pinject_event = (PINTERUPTION_INFORMATION_FIELD)&dummy;     
                pinject_event->Vector = 1;
                pinject_event->InteruptionType = 3;
                pinject_event->DeliverErrorCode = 0;
                pinject_event->Valid = 1;
                VmWrite(0x4016, dummy);           
        }
        //*/
        //vmcall
        //vmclear
        //vmlaunch
        //vmptrld
        //vmptrst
        //vmread
        //vmresume
        //vmwrite
        //vmxoff
        //vmxon
        if (ExitReason[ccpu] >= 18 && ExitReason[ccpu] <= 27){
                //if (!NMI_Active[ccpu]) DbgLog("VMX instructions in vmx-non root... bypassing...", 0);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 9){
                //if (!NMI_Active[ccpu]) DbgLog("Handling Task Switch...", 0);
                HandleTaskSwitch(regs[ccpu], (PTASK_SWITCH_EQUALIFICATION)&ExitQualification[ccpu]);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 10){
                //if (!NMI_Active[ccpu]) DbgLog("Executing CPUID...", 0);
                //insert int3 to emulate break in context of specific process...
                if (ExitEip[ccpu] < 0x80000000){
                        //verify if this is correct process using cr3!!!!
                        ULONG guest_cr3 = VmRead(0x6802);
                        if (guest_cr3 == traced_cr3 && !(GuestEflags[ccpu] & 0x100)){
                                //determine if this is porper context, and we break there only if it's valid
                                //context... this is done so we can catch anti-dump trick, which involve cpuid...
                                dummy = 0;
                                pinject_event = (PINTERUPTION_INFORMATION_FIELD)&dummy;
                                pinject_event->Vector = 3;
                                pinject_event->InteruptionType = 4;             //software 
                                pinject_event->DeliverErrorCode = 0;
                                pinject_event->Valid = 1;
                                VmWrite(0x4016, dummy);
                                VmWrite(0x681E, ExitEip[ccpu]);
                                //vm_entry instruction length...
                                VmWrite(0x401A, ExitInstructionLength[ccpu]);    //softice properly catches int 3h
                        }
                }
                return ExitReason[ccpu];
        }
        
        
        if (ExitReason[ccpu] == 13){
                //if (!NMI_Active[ccpu]) DbgLog("Executing INVD", 0);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 31){
                //if (!NMI_Active[ccpu]) DbgLog("Executing RDMSR", 0);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 32){
                //if (!NMI_Active[ccpu]) DbgLog("Executing WRMSR", 0);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 28){
                //if (!NMI_Active[ccpu]) DbgLog("Executing mov cr", 0);
                HandleCr(regs[ccpu], (PMOV_CR_EQUALIFICATION)&ExitQualification[ccpu]);
                return ExitReason[ccpu];
        }
        
        if (ExitReason[ccpu] == 0){
                //VM-exit interruption information 000000010B 00004404H
                pint = (PINTERUPTION_INFORMATION_FIELD)&dummy;
                dummy = VmRead(0x4404);
                
                if (pint->InteruptionType == 2)
                        InjectNMI();
                VmWrite(0x681E, ExitEip[ccpu]);
                VmWrite(0x401A, ExitInstructionLength[ccpu]);   //not used when NMI...
                return ExitReason[ccpu];
        }
           
        return  ExitReason[ccpu]; 
}


VOID HandleCr(PPUSHAD_REGS x86, PMOV_CR_EQUALIFICATION pmovcr)
{
        ULONG   cr_value, reg32;
        
        switch (pmovcr->NumberOfControlRegister)
        {
        case 0:
            cr_value = VmRead(0x6800);      //cr0
            break;
        case 3:
            cr_value = VmRead(0x6802);      //cr3
            break;
        case 4: 
            cr_value = VmRead(0x6804);      //cr4
            break;
        default:
            _asm int 3h
        }
        
       switch (pmovcr->Register)
       {
       case 0:
           reg32 = x86->regEax;
           break;
       case 1:
           reg32 = x86->regEcx;
           break;
       case 2:
           reg32 = x86->regEdx;
           break;
       case 3:
           reg32 = x86->regEbx;
           break;
       case 4:
           reg32 = VmRead(0x681C);
           break;
       case 5:
           reg32 = x86->regEbp;
           break;
       case 6:
           reg32 = x86->regEsi;
           break;
       case 7:
           reg32 = x86->regEdi;
           break;
        }
        
        if (pmovcr->AccessType == 0)
        {
            switch (pmovcr->NumberOfControlRegister)
            {
            case 0:
                VmWrite(0x6800, reg32);         //cr0
                return;
            case 3:
                VmWrite(0x6802, reg32);         //cr3
                return;
            case 4:
                VmWrite(0x6804, reg32);         //cr4
            default:
                _asm int 3
                return;
            }  
        }      
                
        if (pmovcr->AccessType == 1)
        {
            switch (pmovcr->Register)
            {
            case 0:
                x86->regEax = cr_value;
                return;
            case 1:
                x86->regEcx = cr_value;
                return;
            case 2:
                x86->regEdx = cr_value;
                return;
            case 3:
                x86->regEbx = cr_value;
                return;
            case 4:
                VmWrite(0x681C, cr_value);
                return;
            case 5:
                x86->regEbp = cr_value;
                return;
            case 6:
                x86->regEsi = cr_value;
                return;
            case 7:
                x86->regEdi = cr_value;
                return;
            }
        }        
        
        return;
}

/*

        As this engine doesn't support MP system when SoftIce is active, I leave
        this code here as a refference on how TaskSwitch should be handled!!!!

*/
//this is required when using SoftICE on mp systems as Sice uses
//NMI to stop/resume other cpus...
//If a task switch causes a VM exit, none of the following are modified by the
//task switch: old task-state segment (TSS); new TSS; old TSS descriptor; new
//TSS descriptor; RFLAGS.NT or the TR register

void HandleTaskSwitch(PPUSHAD_REGS x86, PTASK_SWITCH_EQUALIFICATION ts)
{
        GDT gdt_base;
        PGDT_ENTRY pgdt_entry;
        PKTSS ptss, ptss_prev;
        ULONG index, index_prev, dummy;
        ULONG tr_old;
        
        //if (ts->SourceOfTaskSwitch != 3)
        //        return;
        
        //first all TSS has to be filed with current state to allow 
        //return to TASK!!!!...
        //__asm sgdt gdt_base
        //pgdt_entry = (PGDT_ENTRY)(gdt_base.BaseLo + (gdt_base.BaseHi << 16));        
        
        pgdt_entry = (PGDT_ENTRY)VmRead(0x6816);        //get GDT base for Guest...
        
        //Guest TR selector 000000111B 0000080EH
        tr_old = VmRead(0x80E);
        index_prev = tr_old >> 3;
        
        ptss_prev = (PKTSS)(pgdt_entry[index_prev].BaseLow +
                           (pgdt_entry[index_prev].BaseMid << 16) +
                           (pgdt_entry[index_prev].BaseHi << 24));
                    
        ptss_prev->Eax = x86->regEax;
        ptss_prev->Ecx = x86->regEcx;
        ptss_prev->Ebx = x86->regEbx;
        ptss_prev->Edx = x86->regEdx;
        ptss_prev->Ebp = x86->regEbp;
        ptss_prev->Esi = x86->regEsi;
        ptss_prev->Edi = x86->regEdi;
        
        //Guest RSP 000001110B 0000681CH
        ptss_prev->Esp = VmRead(0x681C);
        //Guest RIP 000001111B 0000681EH
        ptss_prev->Eip = VmRead(0x681E);
        ptss_prev->Eip -= VmRead(0x440C);       //<---- exit instruction length... blah...
                                                //      as it was set up earlier... so we have to
                                                //      sub it here...
                                                
        //Guest RFLAGS 000010000B 00006820H
        ptss_prev->EFlags = VmRead(0x6820);  
        //Guest CR3 000000001B 00006802H
        //ptss_prev->CR3 = VmRead(0x6802);
        
        //Guest ES selector 000000000B 00000800H
        ptss_prev->Es = (UINT16)VmRead(0x800);
        //Guest CS selector 000000001B 00000802H
        ptss_prev->Cs = (UINT16)VmRead(0x802);
        //Guest SS selector 000000010B 00000804H
        ptss_prev->Ss = (UINT16)VmRead(0x804);
        //Guest DS selector 000000011B 00000806H
        ptss_prev->Ds = (UINT16)VmRead(0x806);
        //Guest FS selector 000000100B 00000808H
        ptss_prev->Fs = (UINT16)VmRead(0x808);
        //Guest GS selector 000000101B 0000080AH
        ptss_prev->Gs = (UINT16)VmRead(0x80A);
        //Guest LDTR selector 000000110B 0000080CH
        ptss_prev->LDT = (UINT16)VmRead(0x80C);          
          
        //now clear busy flag from this task...
        if (ts->SourceOfTaskSwitch == 1)                //iret clears Busy flag in task...
                pgdt_entry[index_prev].Type = 9;        //so clear it... task switch only
                                                        //occurs here if NT flag is set...
                
        
        index = ts->Selector;
                
        index = index >> 3;
        
                
        ptss = (PKTSS)(pgdt_entry[index].BaseLow +
                      (pgdt_entry[index].BaseMid << 16) +
                      (pgdt_entry[index].BaseHi << 24));
        
        x86->regEax = ptss->Eax;
        x86->regEcx = ptss->Ecx;
        x86->regEdx = ptss->Edx;
        x86->regEbx = ptss->Ebx;
        x86->regEbp = ptss->Ebp;
        x86->regEsi = ptss->Esi;
        x86->regEdi = ptss->Edi;
        
        //issue sequence of VmWrites to properly set needed fields...
        //
        
        //Guest ES selector 000000000B 00000800H
        VmWrite(0x800, ptss->Es);
        //Guest CS selector 000000001B 00000802H
        VmWrite(0x802, ptss->Cs);
        //Guest SS selector 000000010B 00000804H
        VmWrite(0x804, ptss->Ss);
        //Guest DS selector 000000011B 00000806H
        VmWrite(0x806, ptss->Ds);
        //Guest FS selector 000000100B 00000808H
        VmWrite(0x808, ptss->Fs);
        //Guest GS selector 000000101B 0000080AH
        VmWrite(0x80A, ptss->Gs);
        //Guest LDTR selector 000000110B 0000080CH
        VmWrite(0x80C, ptss->LDT);
        //Guest TR selector 000000111B 0000080EH
        VmWrite(0x80E, ts->Selector);
        
        //set access rights...
        //Guest ES limit 000000000B 00004800H
        VmWrite(0x4800, 0xFFFFFFFF);
        //Guest CS limit 000000001B 00004802H
        VmWrite(0x4802, 0xFFFFFFFF);
        //Guest SS limit 000000010B 00004804H
        VmWrite(0x4804, 0xFFFFFFFF);
        //Guest DS limit 000000011B 00004806H
        VmWrite(0x4806, 0xFFFFFFFF);
        //Guest FS limit 000000100B 00004808H
        dummy = GetSegmentLimitGuest(ptss->Fs);
        VmWrite(0x4808, dummy);
        //Guest GS limit 000000101B 0000480AH
        VmWrite(0x480A, 0xFFFFFFFF);
        //Guest LDTR limit 000000110B 0000480CH
        VmWrite(0x480C, 0);
        //Guest TR limit 000000111B 0000480EH
        dummy = GetSegmentLimitGuest(ts->Selector);
        VmWrite(0x480E, dummy);
        
        //before setting Access Rights set TaskState to Busy...
        pgdt_entry[index].Type = 11;
        
        //Guest ES access rights 000001010B 00004814H
        dummy = SegmentSelectorToAccessRightsGuest(ptss->Es);
        VmWrite(0x4814, dummy);
        //Guest CS access rights 000001011B 00004816H
        dummy = SegmentSelectorToAccessRightsGuest(ptss->Cs);
        VmWrite(0x4816, dummy);
        //Guest SS access rights 000001100B 00004818H
        dummy = SegmentSelectorToAccessRightsGuest(ptss->Ss);
        VmWrite(0x4818, dummy);
        //Guest DS access rights 000001101B 0000481AH
        dummy = SegmentSelectorToAccessRightsGuest(ptss->Ds);
        VmWrite(0x481A, dummy);
        //Guest FS access rights 000001110B 0000481CH
        dummy = SegmentSelectorToAccessRightsGuest(ptss->Fs);
        VmWrite(0x481C, dummy);
        //Guest GS access rights 000001111B 0000481EH
        dummy = 0;
        __asm bts dummy, 16
        VmWrite(0x481E, dummy);
        //Guest LDTR access rights 000010000B 00004820H
        dummy = 0;
        __asm bts dummy, 16
        VmWrite(0x4820, dummy);
        //Guest TR access rights 000010001B 00004822H
        dummy = SegmentSelectorToAccessRightsGuest(ts->Selector);
        VmWrite(0x4822, dummy);
        
        //Guest ES base 000000011B 00006806H
        dummy = GetSegmentBaseGuest(ptss->Es);
        VmWrite(0x6806, dummy);
        //Guest CS base 000000100B 00006808H
        dummy = GetSegmentBaseGuest(ptss->Cs);
        VmWrite(0x6808, dummy);
        //Guest SS base 000000101B 0000680AH
        dummy = GetSegmentBaseGuest(ptss->Ss);
        VmWrite(0x680A, dummy);
        //Guest DS base 000000110B 0000680CH
        dummy = GetSegmentBaseGuest(ptss->Ds);
        VmWrite(0x680C, dummy);
        //Guest FS base 000000111B 0000680EH
        dummy = GetSegmentBaseGuest(ptss->Fs);
        VmWrite(0x680E, dummy);
        //Guest GS base 000001000B 00006810H
        dummy = GetSegmentBaseGuest(ptss->Gs);
        VmWrite(0x6810, dummy);
        //Guest LDTR base 000001001B 00006812H
        VmWrite(0x6812, 0);
        //Guest TR base 000001010B 00006814H
        dummy = GetSegmentBaseGuest(ts->Selector);
        VmWrite(0x6814, dummy);
        
        
        //set eflags, stack, cr3 and eip...
        //Guest RSP 000001110B 0000681CH
        VmWrite(0x681C, ptss->Esp);
        //Guest RIP 000001111B 0000681EH
        VmWrite(0x681E, ptss->Eip);
        //Guest RFLAGS 000010000B 00006820H
        if (ts->SourceOfTaskSwitch == 3)
        {               //is this task switch trough IDT...
                dummy = ptss->EFlags;                  
                __asm bts dummy, 14                     //set NT flag...
                __asm bts dummy, 1                      //set reserved bit just in case...
                VmWrite(0x6820, dummy);
        }
        else
        {
                dummy = ptss->EFlags;                  
                VmWrite(0x6820, dummy);
        }  
        
        
        //Guest interruptibility state 000010010B 00004824H
        //Guest activity state 000010011B 00004826H
        
        if (ts->SourceOfTaskSwitch == 1)
        {
                dummy = VmRead(0x4824);
                __asm btr dummy, 3
                VmWrite(0x4824, dummy);
        }else{
                dummy = VmRead(0x4824);
                __asm bts dummy, 3
                VmWrite(0x4824, dummy);
        }  
        
        
        //VmWrite(0x4826, 0);
        
        //Guest CR3 000000001B 00006802H
        VmWrite(0x6802, ptss->CR3);
        
        if (ts->SourceOfTaskSwitch == 3)
                ptss->Backlink = (UINT16)tr_old;        //iretd doesn't update backlink field...
        return;
}
