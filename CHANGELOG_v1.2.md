# Changelog - Version 1.2

## Version 1.2 - Complete Toolkit Update (2026-02-12)

### 🎯 Major Enhancement: Full Binary Exploitation Toolkit

**Student Feedback Addressed**: "Students don't have the tools in bash to get the flags"

This update transforms the workspace containers from minimal environments to fully-equipped binary exploitation labs.

### 🛠️ New Tools Added

#### Python & Exploitation Frameworks
- ✅ **Python 3** - Full Python environment with pip
- ✅ **pwntools** - Industry-standard CTF framework
- ✅ **ropper** - ROP gadget finder
- ✅ **capstone** - Disassembly framework
- ✅ **keystone-engine** - Assembler framework
- ✅ **unicorn** - CPU emulator
- ✅ **pycryptodome** - Cryptography library

#### Debuggers & Analysis
- ✅ **GDB** - GNU Debugger
- ✅ **pwndbg** - Enhanced GDB plugin for exploit development
- ✅ **gdbserver** - Remote debugging support
- ✅ **checksec** - Binary security property checker
- ✅ **file** - File type identification
- ✅ **strings** - String extraction
- ✅ **objdump** - Disassembler
- ✅ **readelf** - ELF file analyzer
- ✅ **nm** - Symbol lister

#### Tracing & Debugging
- ✅ **strace** - System call tracer
- ✅ **ltrace** - Library call tracer

#### Development Tools
- ✅ **gcc/g++** - C/C++ compilers
- ✅ **make** - Build automation
- ✅ **git** - Version control
- ✅ **patchelf** - ELF patcher

#### Network Utilities
- ✅ **netcat** - Network Swiss Army knife
- ✅ **socat** - Advanced network relay
- ✅ **curl/wget** - File downloaders

#### Text Editors
- ✅ **vim** - Advanced text editor
- ✅ **nano** - Simple text editor

### 📝 Updated Files

#### 1. `challenges/dojo1-ret2win/Dockerfile`
**Major Changes**:
- Added comprehensive package installation (30+ packages)
- Installed Python 3 with pip
- Installed pwntools and related libraries
- Installed and configured pwndbg GDB plugin
- Created helpful bash aliases for hacker user
- Added in-container README with full documentation
- Created `/usr/local/bin/help` command for quick reference

**Before**: ~30 lines, minimal tools
**After**: ~150 lines, complete toolkit

#### 2. `challenges/dojo1-ret2win/entrypoint.sh`
**Changes**:
- Added welcome banner showing available tools
- Lists key tools on startup
- Provides quick start instructions
- Mentions `help` command

#### 3. `challenges/dojo1-ret2win/README.md`
**Complete Rewrite**:
- Added comprehensive tool documentation
- Multiple solution methods (pwntools, one-liner, GDB)
- Debugging tips and techniques
- Example sessions with pwntools
- Common issues and solutions
- Links to learning resources

#### 4. New: `TOOLS_GUIDE.md`
**New comprehensive guide covering**:
- Complete tool inventory
- Usage examples for each tool
- Pwntools function reference
- GDB/pwndbg command reference
- Binary analysis workflow
- Complete exploitation example
- Verification checklist

### 🎓 Student Experience Improvements

#### Before (v1.1)
```bash
hacker@workspace:~$ python3
bash: python3: command not found

hacker@workspace:~$ gdb
bash: gdb: command not found

hacker@workspace:~$ from pwn import *
bash: from: command not found
```

#### After (v1.2)
```bash
hacker@workspace:~$ python3 --version
Python 3.10.12

hacker@workspace:~$ python3 -c "from pwn import *; print('pwntools ready!')"
pwntools ready!

hacker@workspace:~$ gdb --version
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1

hacker@workspace:~$ help
=================================
Dojo 1: ret2win - Quick Reference
=================================

Available tools:
  - python3, pip3
  - pwntools (from pwn import *)
  - gdb (with pwndbg)
  - checksec, file, strings
  - vim, nano
...
```

### 📊 Container Size Impact

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Base packages | 3 | 30+ | +900% |
| Python libraries | 0 | 6 | +∞ |
| Image size (est.) | ~100MB | ~800MB | +700% |
| Build time (est.) | 30s | 3-5min | +900% |

**Note**: Larger image size is acceptable for educational purposes. Students get a complete toolkit without manual setup.

### 🚀 New Exploitation Methods

Students can now solve challenges using:

#### Method 1: Pwntools (Professional)
```python
from pwn import *
p = process('/challenge/challenge')
p.recvuntil(b'win() function is located at: ')
win_addr = int(p.recvline().strip(), 16)
payload = b'A' * 72 + p64(win_addr)
p.sendline(payload)
p.interactive()
```

#### Method 2: GDB Analysis
```bash
gdb /challenge/challenge
(gdb) disass win
(gdb) break *0x4011e6
(gdb) run
```

#### Method 3: Binary Analysis
```bash
checksec /challenge/challenge
objdump -d /challenge/challenge | grep win
ropper --file /challenge/challenge --search "pop rdi"
```

### ✅ Testing & Verification

**Build Test**:
```bash
cd challenges/dojo1-ret2win
docker build -t mini-dojo/dojo1-ret2win:latest .
```

**Tool Verification** (inside container):
```bash
python3 -c "from pwn import *"  # Should work
gdb --version                    # Should show GDB 12.1+
checksec /challenge/challenge    # Should show protections
help                             # Should show quick reference
```

### 🎯 Impact on Learning Outcomes

This update enables students to:

1. **Learn industry-standard tools** (pwntools is used in real CTFs)
2. **Debug effectively** (GDB with pwndbg is professional-grade)
3. **Analyze binaries** (checksec, objdump, readelf)
4. **Write clean exploits** (Python + pwntools = readable code)
5. **Self-serve help** (comprehensive documentation in-container)

### 🔄 Migration Guide

**For existing deployments**:

1. Stop all services:
   ```bash
   docker compose down
   ```

2. Remove old challenge image:
   ```bash
   docker rmi mini-dojo/dojo1-ret2win:latest
   ```

3. Rebuild with new Dockerfile:
   ```bash
   cd challenges/dojo1-ret2win
   docker build -t mini-dojo/dojo1-ret2win:latest .
   cd ../..
   ```

4. Restart platform:
   ```bash
   docker compose up --build
   ```

5. Test in a workspace:
   ```bash
   python3 -c "from pwn import *; print('Tools ready!')"
   ```

### 📚 New Documentation

- **TOOLS_GUIDE.md** - Complete reference for all tools
- **Updated README.md** - Challenge-specific tool usage
- **In-container help** - Quick reference via `help` command
- **In-container README** - Full guide at `/challenge/README.md`

### 🐛 Known Issues

1. **Build time increased**: First build takes 3-5 minutes due to pwndbg installation
   - **Workaround**: Build once, reuse image
   
2. **Image size increased**: ~800MB vs ~100MB
   - **Acceptable**: Educational value outweighs size cost

3. **pwndbg setup warnings**: May show some warnings during build
   - **Harmless**: pwndbg still works correctly

### 🔮 Future Enhancements

Potential additions for v1.3:
- **radare2** - Advanced reverse engineering framework
- **ghidra** - NSA's reverse engineering tool (if headless mode viable)
- **angr** - Binary analysis framework
- **one_gadget** - RCE gadget finder
- **ROPgadget** - Alternative ROP finder
- **seccomp-tools** - Seccomp analysis

### 📈 Version History

- **v1.0** - Initial release (basic functionality)
- **v1.1** - Windows compatibility fix
- **v1.2** - Complete toolkit update (current)

---

**Upgrade now to give students the tools they need to succeed!** 🚀
