                cpuid break via hardware virtualisation
                
                
Not much to say, cpuid causes VM-Exit, so whenever cpuid occurs in our 
target, inject int 3 event into Guest.

i3here on - must be set in SoftICE

No MP support due to problem with NMI handling when SoftICE is active.
Disable MP in BIOS if you want to use this tool with SoftICE, as this
tool is designed to work with SoftICE and i3here on...


Requires Intel Hardware Virtualisation technology, and I have no idea
how this will work on AMD!!!!

Did you wonder about finding SecuROM cpuid stuff? Well here it is...

                                        (c) 2008 deroko of ARTeam


ps. there is some code which is designed aswell for MP systems, but
    due to not yet solved issue with NMI that code is not used. 
    Example of such code is ExitEip[ccpu] where ccpu is only
    shortcut for MyKeGetCurrentProcessorNumber() procedure, listed
    in kegetcurrentprocessornumber.c
    
    TaskSwitch code implemented in HandleTaskSwitch is never used
    on single core systems, as windows doesn't perfrom TaskSwitch
    at all (only when NMI or KiTrap08 is executed). 
    
NOTE: DRIVER IS NEVER UNLOADED, as at the time of releasing this
      code I didn't write that stuff yet. You may find some 
      leftovers in unloadme() in vm.c, but it's not done yet...
      
      
    
    