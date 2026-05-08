// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "Windows.h"

void MsgBoxPayload()
{
    MessageBoxA(NULL, "Hacked", "First DLL Pyload", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MsgBoxPayload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

