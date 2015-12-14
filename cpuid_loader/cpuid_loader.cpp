// cpuid_loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	STARTUPINFOW sinfo;
	PROCESS_INFORMATION pinfo;
	OPENFILENAME ofn;
	HANDLE hdevice;
	ULONG_PTR dummy;
	PWCHAR *argv;
	int argc;
	PWCHAR p_name;
	
	memset(&sinfo, 0, sizeof(STARTUPINFOW));
	memset(&pinfo, 0, sizeof(PROCESS_INFORMATION));
	memset(&ofn, 0, sizeof(OPENFILENAME));

	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc == 2){
			if (!CreateProcessW(argv[1], 0,0,0,0, CREATE_SUSPENDED, 0,0, &sinfo, &pinfo))
				return 0;
	}else{
			p_name = (PWCHAR)GlobalAlloc(GPTR, 4096);
			memset(p_name, 0, 4096);
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.lpstrFileTitle = p_name;
			ofn.nMaxFileTitle = 4096/2;
			ofn.lpstrFilter = L"Executable files\0*.exe\0\0";

			if (!GetOpenFileNameW(&ofn))
				return 0;
			if (!CreateProcessW(p_name, 0,0,0,0, CREATE_SUSPENDED, 0,0, &sinfo, &pinfo))
				return 0;
	}

	hdevice = CreateFileA("\\\\.\\virtualmachine", GENERIC_READ | GENERIC_WRITE, 0,0, OPEN_EXISTING, 0,0);

	DeviceIoControl(hdevice, SET_PID, &pinfo.dwProcessId, 4, NULL, 0, &dummy, 0);
	CloseHandle(hdevice);

	ResumeThread(pinfo.hThread);

	return 0;
}

