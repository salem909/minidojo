# 🛠️ Mini-DOJO Tools Guide

This guide explains all the tools available in your workspace and how to use them.

## 📦 Installed Tools Overview

Every workspace container comes pre-configured with a complete binary exploitation toolkit:

| Category | Tools |
|----------|-------|
| **Python** | Python 3, pip3, pwntools, ropper, capstone, keystone, unicorn |
| **Debuggers** | GDB, pwndbg, gdbserver |
| **Binary Analysis** | checksec, file, strings, objdump, readelf, nm, xxd |
| **Tracing** | strace, ltrace |
| **Network** | netcat, socat, curl, wget |
| **Editors** | vim, nano |
| **Compilers** | gcc, g++, make |
| **Utilities** | git, patchelf, binutils |

## 🐍 Python & Pwntools

### Verify Installation

```bash
# Check Python version
python3 --version

# Check pwntools
python3 -c "from pwn import *; print(pwnlib.__version__)"

# Check other libraries
python3 -c "import ropper; import capstone; import keystone; print('All libraries OK')"
```

### Basic Pwntools Usage

```python
from pwn import *

# Process interaction
p = process('/challenge/challenge')
p.sendline(b'input')
output = p.recvline()
p.interactive()

# Packing/Unpacking
addr = p64(0x4011e6)  # Pack 64-bit address
value = u64(b'\xe6\x11\x40\x00\x00\x00\x00\x00')  # Unpack

# Pattern generation (for finding offsets)
pattern = cyclic(200)
offset = cyclic_find(0x61616161)

# Shellcode
shellcode = asm(shellcraft.sh())

# ELF manipulation
elf = ELF('/challenge/challenge')
print(hex(elf.symbols['win']))
```

### Common Pwntools Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `p64(addr)` | Pack 64-bit address | `p64(0x401000)` |
| `p32(addr)` | Pack 32-bit address | `p32(0x401000)` |
| `u64(bytes)` | Unpack 64-bit | `u64(data[:8])` |
| `flat()` | Flatten payload | `flat([b'A'*8, p64(addr)])` |
| `cyclic()` | Generate pattern | `cyclic(100)` |
| `cyclic_find()` | Find offset | `cyclic_find(0x61616161)` |
| `asm()` | Assemble shellcode | `asm('mov rax, 0')` |
| `disasm()` | Disassemble bytes | `disasm(b'\x90\x90')` |

## 🐛 GDB with pwndbg

### Starting GDB

```bash
# Debug a binary
gdb /challenge/challenge

# With arguments
gdb --args /challenge/challenge arg1 arg2

# Attach to running process
gdb -p <pid>
```

### Essential pwndbg Commands

```gdb
# Breakpoints
break main          # Break at main
break *0x401000     # Break at address
info breakpoints    # List breakpoints
delete 1            # Delete breakpoint 1

# Execution
run                 # Start program
continue            # Continue execution
step                # Step into (single instruction)
next                # Step over
finish              # Run until function returns

# Examination
disass main         # Disassemble function
disass              # Disassemble current location
x/20wx $rsp         # Examine 20 words at stack pointer
x/s 0x401000        # Examine string at address

# pwndbg-specific
stack 20            # Show 20 stack entries
regs                # Show all registers
vmmap               # Show memory mappings
checksec            # Check binary protections
search "flag"       # Search memory for string
telescope $rsp 10   # Enhanced stack view
```

### Debugging Example

```bash
gdb /challenge/challenge

# Inside GDB:
(gdb) break vuln
(gdb) run
(gdb) disass
(gdb) stack 20
(gdb) info frame
(gdb) x/20wx $rsp
(gdb) continue
```

## 🔍 Binary Analysis Tools

### checksec - Check Binary Protections

```bash
checksec /challenge/challenge
```

Output explanation:
- **RELRO**: Relocation Read-Only (prevents GOT overwrite)
- **Stack Canary**: Stack protection
- **NX**: Non-executable stack
- **PIE**: Position Independent Executable (ASLR)

### file - Identify File Type

```bash
file /challenge/challenge
# Output: ELF 64-bit LSB executable, x86-64, dynamically linked...
```

### strings - Extract Printable Strings

```bash
# Find interesting strings
strings /challenge/challenge

# Search for specific strings
strings /challenge/challenge | grep flag
```

### objdump - Disassemble Binary

```bash
# Disassemble all
objdump -d /challenge/challenge

# Disassemble specific function
objdump -d /challenge/challenge | grep -A 20 "<win>"

# Show headers
objdump -h /challenge/challenge
```

### readelf - Display ELF Information

```bash
# Show headers
readelf -h /challenge/challenge

# Show sections
readelf -S /challenge/challenge

# Show symbols
readelf -s /challenge/challenge

# Show program headers
readelf -l /challenge/challenge
```

### nm - List Symbols

```bash
# List all symbols
nm /challenge/challenge

# List only functions
nm /challenge/challenge | grep " T "
```

## 🔬 Tracing Tools

### strace - Trace System Calls

```bash
# Trace all system calls
strace /challenge/challenge

# Trace specific calls
strace -e open,read,write /challenge/challenge

# Follow forks
strace -f /challenge/challenge
```

### ltrace - Trace Library Calls

```bash
# Trace library calls
ltrace /challenge/challenge

# Trace specific functions
ltrace -e malloc,free /challenge/challenge
```

## 🌐 Network Tools

### netcat - Network Swiss Army Knife

```bash
# Connect to a service
nc 127.0.0.1 1234

# Listen on a port
nc -lvp 1234

# Send file
nc 127.0.0.1 1234 < file.txt
```

### socat - Advanced Network Tool

```bash
# TCP relay
socat TCP-LISTEN:1234,reuseaddr,fork TCP:remote:5678

# Connect to service
socat - TCP:127.0.0.1:1234
```

## 📝 Text Editors

### vim - Quick Reference

```bash
vim file.txt

# Inside vim:
i           # Insert mode
Esc         # Normal mode
:w          # Save
:q          # Quit
:wq         # Save and quit
:q!         # Quit without saving
/search     # Search
dd          # Delete line
yy          # Copy line
p           # Paste
```

### nano - Simpler Editor

```bash
nano file.txt

# Controls shown at bottom:
Ctrl+O      # Save
Ctrl+X      # Exit
Ctrl+K      # Cut line
Ctrl+U      # Paste
Ctrl+W      # Search
```

## 🔧 Ropper - ROP Gadget Finder

```bash
# Find gadgets
ropper --file /challenge/challenge

# Search for specific gadgets
ropper --file /challenge/challenge --search "pop rdi"

# Find JOP gadgets
ropper --file /challenge/challenge --jop
```

## 💻 Complete Workflow Example

Here's a typical workflow for solving a challenge:

```bash
# 1. Analyze the binary
file /challenge/challenge
checksec /challenge/challenge
strings /challenge/challenge | grep -i flag

# 2. Run it to understand behavior
/challenge/challenge

# 3. Debug with GDB
gdb /challenge/challenge
# (gdb) disass main
# (gdb) disass win
# (gdb) quit

# 4. Create exploit with pwntools
cat > exploit.py << 'EOF'
#!/usr/bin/env python3
from pwn import *

p = process('/challenge/challenge')
p.recvuntil(b'win() function is located at: ')
win_addr = int(p.recvline().strip(), 16)

payload = b'A' * 72 + p64(win_addr)
p.sendline(payload)
p.interactive()
EOF

# 5. Run exploit
python3 exploit.py
# cat /flag
```

## 🆘 Quick Help

Inside your workspace, type:

```bash
help
```

This shows a quick reference of available tools and commands.

## 📚 Additional Resources

### Documentation
- [Pwntools Docs](https://docs.pwntools.com/)
- [pwndbg GitHub](https://github.com/pwndbg/pwndbg)
- [GDB Manual](https://sourceware.org/gdb/documentation/)

### Tutorials
- [Pwntools Tutorial](https://github.com/Gallopsled/pwntools-tutorial)
- [Binary Exploitation Notes](https://ir0nstone.gitbook.io/notes/)
- [Nightmare (Binary Exploitation Course)](https://guyinatuxedo.github.io/)

## ✅ Verification Checklist

After starting your workspace, verify all tools are available:

```bash
# Python & Libraries
python3 --version
python3 -c "from pwn import *"

# Debugger
gdb --version
gdb -q -ex "pwndbg" -ex "quit" /challenge/challenge 2>&1 | grep pwndbg

# Analysis Tools
checksec --version
file --version
objdump --version

# Editors
vim --version
nano --version

# Network
nc -h 2>&1 | head -1
socat -V 2>&1 | head -1
```

All commands should execute without errors.

---

**Need more help?** Check `/challenge/README.md` in your workspace for challenge-specific guidance!
