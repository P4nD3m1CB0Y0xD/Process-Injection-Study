void myMsgBox()
{
    MessageBoxA(NULL, "DLL Injection", "Malware", MB_OK);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myMsgBox();
    }
    return TRUE;
}
