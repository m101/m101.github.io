bits 32

section .text
    global main

main:
    jmp short begin

key0: dd 0xa3bfc2af

; let's make some space for our buffer!
begin:
    sub esp, 0x100

; we init our buffer with value from 0 to 255
xor ecx, ecx
init_array:
    mov [esp+ecx], cl
    inc cl
    jnz init_array

; shuffle values in the array
xor eax, eax
mov edx, 0xdeadbeef
shuffle:
    add al, [esp+ecx]   ; al += array[ecx]
    add al, dl          ; index = al + dl
    ror edx, 0x8        ; every 4 rotations we get our original value ;)
    ; we swap values
    mov bl, [esp+ecx]   ; bl = array[ecx]
    mov bh, [esp+eax]   ; bh = array[ecx]
    mov [esp+eax], bl   ; array[eax] = bl
    mov [esp+ecx], bh   ; array[ecx] = bh
    inc cl              ; go forward in our array
    jnz shuffle

    jmp dword save_pc

get_encoded:
    mov ebx, esp                ; pointer ebx to ret address on stack
    add ebx, strict dword 0x4   ; address of array (ignoring the ret address on the stack ;))
    pop esp                     ; esp = program counter (point after the call to get_encoded)
    pop eax                     ; first 4 bytes after the call
    cmp eax, 0x41414141
    jnz exit

    pop eax                     ; next 4 bytes after the call
    cmp eax, 0x42424242
    jnz exit

    ; copy message to buffer in stack
    pop edx         ; get length of message 
    mov ecx, edx    ; ecx = len(msg)
    mov esi, esp    ; esi = &msg
    mov edi, ebx    ; edi = address of array
    sub edi, ecx    ; edi = ebx - len(msg) = start of dest area
    rep movsb       ; copying the message to the stack (writing over array)

; init for decoding encoded message
    mov esi, ebx    ; esi = &buffer
    mov ecx, edx    ; ecx = len(msg)
    mov edi, ebx    ; edi = &buffer
    sub edi, ecx    ; edi = ebx - len(msg) = start of dest area
    xor eax, eax
    xor ebx, ebx
    xor edx, edx

; loop for decoding the secret message
decode:
    inc al
    add bl, [esi+eax]   ; get one byte of encoded message
    mov dl, [esi+eax]   ; get one byte of encoded message
    mov dh, [esi+ebx]   ; get one byte of encoded message
    ; swap values back
    mov [esi+eax], dh
    mov [esi+ebx], dl
    add dl, dh          ; get index
    ; decode byte
    xor dh, dh          
    mov bl, [esi+edx]   ; get key
    mov dl, [edi]       ; get encoded byte
    xor dl, bl          ; decode byte
    ; save byte
    mov [edi], dl
    ; loop
    inc edi
    dec ecx
    jnz decode

exit:
    xor ebx, ebx
    mov eax, ebx
    inc al
    int 0x80

save_pc:
    nop
    nop
    call dword get_encoded

junk1: dd 0x41414141
junk2: dd 0x42424242
msg_length: dd 0x00000032
msg_encoded: db `\x91\xd8\xf1\x6d\x70\x20\x3a\xab\x67\x9a\x0b\xc4\x91\xfb\xc7\x66\x0f\xfc\xcd\xcc\xb4\x02\xfa\xd7\x77\xb4\x54\x38\xab\x1f\x0e\xe3\x8e\xd3\x0d\xeb\x99\xc3\x93\xfe\xd1\x2b\x1b\x11\xc6\x11\xef\xc8\xca\x2f`
