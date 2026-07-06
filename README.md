
# Advanced EDR/AV Evasion Framework
<img width="1024" height="1024" alt="winvi" src="https://github.com/user-attachments/assets/c2ca177e-b749-4dbf-8795-0effb90b53d4" />

## ByDoseUser

This is an advanced Windows user-mode evasion framework implementing multiple state-of-the-art techniques to bypass Endpoint Detection and Response (EDR) systems, antivirus software, and security monitoring tools. The framework combines various evasion methodologies including direct system calls, unhooking, ETW/AMSI patching, and sophisticated anti-analysis techniques.

## Key Features

### System Call Implementation
- **Hells Gate**: Dynamically retrieves system service numbers (SSNs) from ntdll export
- **Halos Gate**: Enhanced SSN retrieval with fallback mechanisms for hooked functions
- **Tartarus Gate**: Advanced SSN resolution supporting multiple function hooking patterns
- **Heavens Gate**: Supports both x86 and x64 WoW64 system calls via segment register manipulation
- **Indirect Syscall**: Executes syscalls via ntdll's `syscall` instruction for return address spoofing

### Anti-Analysis & Evasion
- **NTDLL Unhooking**: Restores ntdll to its original state from disk
- **ETW Patching**: Disables Event Tracing for Windows by patching `EtwEventWrite`
- **AMSI Bypass**: Patches `AmsiScanBuffer` to always return clean results
- **Hardware Breakpoint Clearing**: Removes debugger hardware breakpoints
- **Call Stack Spoofing**: Prevents detection through syscall return address analysis
- **Sleep Obfuscation**: Encrypts payload during sleep to evade memory scanning

### Process Injection Techniques
- **Module Stomping**: Injects payload into legitimate `.text` sections of loaded modules
- **Remote Process Injection**: Uses direct syscalls for allocation, writing, and thread creation
- **APC Injection**: Queues Asynchronous Procedure Calls for stealthier execution

### Anti-VM & Debugging Detection
- Hypervisor and VM detection via CPUID, MAC address analysis, and timing anomalies
- Registry and process enumeration for virtualization software signatures
- Debugger presence detection via PEB flags, `IsDebuggerPresent`, and hardware breakpoints
- Comprehensive anti-sandbox checks

### Chrome App-Bound Encryption Bypass
- Leverages COM elevation to decrypt Chrome's app-bound encrypted keys
- Demonstrates credential extraction capabilities from browser storage

## Build Instructions

### Prerequisites
- Microsoft Visual Studio 2022 or later with C++ support
- MASM (Microsoft Macro Assembler) for assembly compilation
- Windows SDK

### Compilation Steps

1. **Configure Assembly Build**:
   In Visual Studio, right-click the project → Build Dependencies → Build Customizations → Enable MASM

2. **Build Configuration**:
   ```
   Platform: x64 (required for syscall implementations)
   Configuration: Release or Debug
   ```

3. **Compile**:
   ```
   Build Solution (Ctrl+Shift+B)
   ```

### Manual Compilation (Command Line)
```cmd
ml64 /c /Fo syscalls.obj syscalls.asm
cl /EHsc /std:c++17 /Fe:EvasionFramework.exe main.cpp syscalls.obj
```

## Usage

```
EvasionFramework.exe [target_pid]
```

- **With PID**: Injects payload into specified process
- **Without PID**: Executes payload locally using module stomping or local execution

### Example
```cmd
EvasionFramework.exe 1234
```

## Configuration Flags

The framework includes compile-time configuration flags in `main.cpp`:

```cpp
#define CONFIG_ENABLE_HELLS_GATE 1      // Enable Hells Gate SSN resolution
#define CONFIG_ENABLE_HALOS_GATE 1       // Enable Halos Gate SSN resolution
#define CONFIG_ENABLE_TARTARUS_GATE 1    // Enable Tartarus Gate SSN resolution
#define CONFIG_ENABLE_NULLGATE 1         // Enable Null Gate technique
#define CONFIG_ENABLE_HEAVENS_GATE 1     // Enable Heavens Gate (WoW64)
#define CONFIG_ENABLE_INDIRECT_SYSCALL 1  // Use indirect syscall method
#define CONFIG_ENABLE_NTDLL_UNHOOKING 1   // Unhook ntdll from disk
#define CONFIG_ENABLE_ETW_PATCHING 1      // Disable ETW
#define CONFIG_ENABLE_AMSI_BYPASS 1       // Bypass AMSI
#define CONFIG_ENABLE_MODULE_STOMPING 1   // Inject into module .text
#define CONFIG_ENABLE_SLEEP_OBFUSCATION 1 // Encrypt during sleep
#define CONFIG_ENABLE_CALLSTACK_SPOOFING 1
#define CONFIG_ENABLE_HWBP_CLEARING 1     // Clear hardware breakpoints
#define CONFIG_ENABLE_ANTI_VM 1           // Enable VM detection
#define CONFIG_ENABLE_CHROME_ABE_BYPASS 1 // Bypass Chrome encryption
```

## Key Components

### `syscalls.asm`
- Contains MASM assembly implementations for syscall wrappers
- Implements `IndirectSyscall5/6` for executing system calls with indirect addressing
- `HeavensGateEntry/Exit` functions for x86/x64 transition
- References `g_ntdllGadget` for syscall instruction location

### `syscalls.h`
- Declarations for syscall wrapper functions
- Extern variables for system call table management
- Function prototypes for system call invocations

### `main.cpp`
- Core evasion framework logic
- Implements all evasion techniques and anti-analysis features
- Contains the payload (currently a minimal stub)
- Orchestrates the evasion chain based on configuration flags

## Technical Details

### Syscall Resolution
The framework uses multiple fallback strategies to obtain SSNs:
1. **Direct**: Reads from ntdll export stub if available
2. **Forward Scan**: Searches forward/backward for syscall stub if hooked
3. **JMP/Relative**: Handles redirection patterns (E9/EB instructions)
4. **Register Indirect**: Resolves via function address references

### NTDLL Unhooking
1. Maps clean ntdll from disk (`C:\Windows\System32\ntdll.dll`)
2. Identifies `.text` section in hooked ntdll
3. Overwrites with clean version using memory protection changes

### Payload Execution Flow
1. Anti-VM/anti-debug checks (if enabled)
2. Initialize syscall table using gate techniques
3. Unhook ntdll and patch ETW/AMSI
4. Clear hardware breakpoints
5. Attempt Chrome App-Bound Encryption bypass (if applicable)
6. Execute payload via:
   - Module stomping (preferred)
   - Remote process injection (if PID specified)
   - Sleep obfuscation then local execution

## Limitations & Considerations

- Requires x64 Windows 10/11 (build 19041+)
- Administrator privileges for most injection techniques
- `C:\Windows\System32\ntdll.dll` must be accessible for unhooking
- Some techniques require specific Windows versions or update levels
- Chome bypass requires Chrome installed and COM support

## Ethical Use Disclaimer

This framework is intended for legitimate security research, penetration testing engagements with proper authorization, and educational purposes. Unauthorized use against production systems or sensitive environments is strictly prohibited. Always ensure you have explicit written permission before deploying similar frameworks in any environment.

## References & Credits

- Hells Gate: [@smelly__vx](https://twitter.com/smelly__vx)
- Halos Gate: [@Jackson_T](https://twitter.com/Jackson_T)
- Tartarus Gate: [@TheRealWover](https://twitter.com/TheRealWover)
- Indirect Syscall: [@Cneelis](https://twitter.com/Cneelis)
- Various contributions from the malware analysis and offensive security community

---

**Version**: 1.0  
**Last Updated**: November 2023
