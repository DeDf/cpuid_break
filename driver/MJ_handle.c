#include "defs.h"

ULONG traced_cr3 = 0xFFFFFFFF;
HANDLE traced_pid;

NTSTATUS MJ_CreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

NTSTATUS ServiceHandle(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    PIO_STACK_LOCATION cur_sl = IoGetCurrentIrpStackLocation(pIrp);
    PEPROCESS peprocess;
    HANDLE process_id;
    PULONG_PTR handle;

    if (cur_sl->Parameters.DeviceIoControl.IoControlCode == SET_PID)
    {
        if (cur_sl->Parameters.DeviceIoControl.InputBufferLength != 4)
            status = STATUS_BUFFER_TOO_SMALL;
        else
        {
            handle = (PULONG_PTR)pIrp->AssociatedIrp.SystemBuffer;
            process_id = (HANDLE)*handle;
            status = PsLookupProcessByProcessId(process_id, &peprocess);
            if (status == STATUS_SUCCESS)
            {
                traced_pid = process_id;

                KeAttachProcess(peprocess);
                __asm mov eax, cr3
                __asm mov traced_cr3, eax
                KeDetachProcess();

                ObDereferenceObject(peprocess);
            }                                
        }
    }
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;       
    IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    if (ProcessId == traced_pid && Create == FALSE)
    {
        traced_cr3 = 0xFFFFFFFF;
        traced_pid = (HANDLE)0xFFFFFFFF;
    }
}