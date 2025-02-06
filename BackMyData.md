# Initial Analysis
- Given a PE32 executable (the sample is from [VX-Underground](https://vx-underground.org/))

![image](https://github.com/user-attachments/assets/edd36d17-b5aa-42a0-a6c2-e86ed1bd818d)

- Having high entropy, we can suspect that this program might be packed

![image](https://github.com/user-attachments/assets/2a42b5b5-3bf7-43aa-8249-a9fec9433671)

# Detailed Analysis
- The Ransomware decrypted its setting by a using a custom made AES algorithm which is very similar to [this](https://github.com/pjok1122/AES-Optimization) with a harcoded key

![image](https://github.com/user-attachments/assets/63140000-a1a5-4346-89cd-4bc23db51433)

- Here are some decrypted data

![image](https://github.com/user-attachments/assets/5a343e11-be48-40fc-b3fd-be11dd6a4da1)

- It also try to open a non-existent file with the name as the above data in this function
```C
int __cdecl sub_87271B(int a1, int a2)
{
  LPVOID v2; // ebx
  const WCHAR *v3; // esi
  HANDLE FileW; // eax
  DWORD v5; // esi
  WCHAR *v6; // eax
  LPWSTR v7; // ebx
  int v9; // [esp+Ch] [ebp-1Ch]
  WCHAR *v10; // [esp+10h] [ebp-18h]
  void *lpMem; // [esp+14h] [ebp-14h]
  DWORD NumberOfBytesRead; // [esp+18h] [ebp-10h] BYREF
  HANDLE hFile; // [esp+1Ch] [ebp-Ch]
  LPWSTR lpWideCharStr; // [esp+20h] [ebp-8h]
  LPVOID lpBuffer; // [esp+24h] [ebp-4h]

  v9 = 0;
  NumberOfBytesRead = 0;
  lpBuffer = 0;
  lpWideCharStr = 0;
  v2 = call_to_heapalloc(0x20Au);
  lpMem = v2;
  v3 = (const WCHAR *)call_to_heapalloc(0x20Au);
  v10 = (WCHAR *)v3;
  if ( v3 )
  {
    if ( !v2 )
      goto LABEL_15;
    if ( sub_875B20((int)v2) )                  // Gen desktop path
    {
      if ( sub_8759F1((int)v3, 0x104u, 3) )     // C:\\Users\\<PC_Username>\\Desktop\\backm
      {
        FileW = CreateFileW(v3, GENERIC_READ, 0, 0, 3u, 0, 0);
        hFile = FileW;
        if ( FileW != (HANDLE)0xFFFFFFFF )
        {
          v5 = SetFilePointer(FileW, 0, 0, 2u);
          lpBuffer = call_to_heapalloc(v5);
          v6 = (WCHAR *)call_to_heapalloc(2 * v5 + 2);
          lpWideCharStr = v6;
          if ( lpBuffer
            && v6
            && !SetFilePointer(hFile, 0, 0, 0)
            && ReadFile(hFile, lpBuffer, v5, &NumberOfBytesRead, 0)
            && NumberOfBytesRead == v5 )
          {
            v7 = lpWideCharStr;
            v7[MultiByteToWideChar(0xFDE9u, 0, (LPCCH)lpBuffer, v5, lpWideCharStr, v5)] = 0;
            v9 = sub_872504(v7, a2);
          }
          CloseHandle(hFile);
        }
      }
    }
  }
  if ( lpMem )
    heapfree(lpMem);
LABEL_15:
  if ( v10 )
    heapfree(v10);
  if ( lpBuffer )
    heapfree(lpBuffer);
  if ( lpWideCharStr )
    heapfree(lpWideCharStr);
  return v9;
}
```
- The Ransomware also check if it is currently running with administrative privilege or not
```C
int sub_873E39()
{
  int v0; // esi
  HANDLE CurrentProcess; // eax
  int TokenInformation; // [esp+4h] [ebp-Ch] BYREF
  DWORD ReturnLength; // [esp+8h] [ebp-8h] BYREF
  HANDLE TokenHandle; // [esp+Ch] [ebp-4h] BYREF

  v0 = 0;
  TokenHandle = 0;
  if ( (unsigned __int8)GetVersion() < 6u )
    return 1;
  CurrentProcess = GetCurrentProcess();
  if ( OpenProcessToken(CurrentProcess, TOKEN_QUERY, &TokenHandle) )
  {
    ReturnLength = 4;
    if ( GetTokenInformation(TokenHandle, TokenElevation, &TokenInformation, 4u, &ReturnLength) )
      v0 = TokenInformation;
  }
  if ( TokenHandle )
    CloseHandle(TokenHandle);
  return v0;
}
```
