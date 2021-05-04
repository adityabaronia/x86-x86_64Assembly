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
