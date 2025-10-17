BSOD Dump Analyzer (Windows)

Single-file Python tool to analyze Windows crash dumps on many machines with zero prep.

Parses Minidumps (MDMP) in pure Python.

Auto-unwraps WER containers: .cab, .zip, .gz.

Detects full kernel dumps (e.g., PAGEDU64) and, when possible, self-installs WinDbg and converts them to a minidump for deeper analysis.

If WinDbg install is blocked, it still extracts BugCheck code + 4 params directly from the full-dump header.

Always writes a structured JSON report alongside the input.

Tested on Windows 10/11 x64 with Python 3.10+.

What it does

Minidump path

Auto-installs the minidump Python package into a local vendor folder.

Reads OS build, CPU arch, exception or bugcheck, maps exception address to a module when possible, and adds driver hints.

Full dump path (PAGE*/PAGEDU64/DUMP*)

Attempts UAC elevation and installs WinDbg via winget or Chocolatey.

Runs .dump /ma to create a minidump, then performs the same deep analysis.

If installation is blocked/offline, parses the full-dump header locally to extract BugCheck and parameters so you still get actionable data.

Containers

If a .cab, .zip, or .gz is provided, it extracts the contained .dmp and proceeds.

Quick start
python bsod_analyzer.py "C:\Windows\Minidump\123124-0001.dmp"


Other inputs:

# WER cabinet or zip
python bsod_analyzer.py "C:\Users\You\Desktop\Report.cab"

# Full dump: will try to self-install WinDbg, convert to minidump, and analyze
python bsod_analyzer.py "C:\Windows\MEMORY.DMP"


Output:

Console summary

JSON report next to input, for example:

C:\Windows\Minidump\123124-0001.analysis.json

Command-line options
usage: bsod_analyzer.py DUMP_OR_CONTAINER [--json PATH] [--symbols PATH]

positional arguments:
  DUMP_OR_CONTAINER     .dmp, .cab, .zip, or .gz

optional arguments:
  --json PATH           write JSON report to PATH instead of next to input
  --symbols PATH        _NT_SYMBOL_PATH for WinDbg operations


Notes:

When WinDbg is used, _NT_SYMBOL_PATH defaults to srv*C:\symbols*https://msdl.microsoft.com/download/symbols unless you pass --symbols.

Example console outputs

Minidump:

Minidump analysis
OS: Windows 10.0 build 19045
CPU: PROCESSOR_ARCHITECTURE_AMD64  Cores: 16
Exception: 0xC0000005 at 0x7FF9C123ABCD (TID 1234)
Faulting module: nvlddmkm.sys @ 0xFFFFF80212300000 (+0x1A3000)
Hints:
  - NVIDIA display driver. Clean reinstall with DDU, then latest WHQL.

Saved JSON report: C:\Windows\Minidump\123124-0001.analysis.json


Full dump, restricted machine (no WinDbg install allowed):

Full dump header (parsed locally)
BugCheck: 0x00000133 Params: 0x0, 0x501, 0x500, 0xFFFFF803362FB320
OS Version: 15.19041  CPUs: 16  MachineType: 34404

Saved JSON report: D:\dumps\MEMORY.analysis.json

JSON report shape

Minidump path:

{
  "dump_path": "C:\\Windows\\Minidump\\123124-0001.dmp",
  "timestamp": "2025-10-16T22:15:08.577936Z",
  "tool": "bsod_analyzer.py",
  "method": "minidump",
  "result": {
    "os": "Windows 10.0 build 19045",
    "cpu_arch": "PROCESSOR_ARCHITECTURE_AMD64",
    "cpu_count": 16,
    "exception_code": "0xC0000005",
    "exception_address": "0x7FF9C123ABCD",
    "faulting_module": "nvlddmkm.sys",
    "driver_hints": [
      "NVIDIA display driver. Clean reinstall with DDU, then latest WHQL."
    ]
  }
}


Full dump parsed locally:

{
  "dump_path": "D:\\Ai_Projects\\bsod_diag_script\\101225-6843-01.dmp",
  "method": "full_dump:PAGEDU64:local_header",
  "result": {
    "type": "full_dump_header",
    "signature": "PAGEDU64",
    "major_version": 15,
    "minor_version": 19041,
    "machine_image_type": 34404,
    "number_processors": 16,
    "bugcheck_code": "0x00000133",
    "bugcheck_params": ["0x0","0x501","0x500","0xFFFFF803362FB320"],
    "explanation": "DPC_WATCHDOG_VIOLATION: Long DPC/ISR latency; storage/GPU drivers or NVMe timeouts."
  }
}


When WinDbg is used for full dumps you’ll also see:

windbg_path

converted_minidump (temporary path)

windbg_head (first ~200 lines of analyzer output)

minidump_analysis (same fields as a native minidump)

Driver hints

The script flags common offenders by scanning fields and loaded modules for matches like:

nvlddmkm (NVIDIA display)

amdkmdag, atikmpag (AMD display)

igdkmd (Intel display)

stornvme, storport, iastor, nvme (storage)

rt640, realtek, ndis, tcpip (NIC stack)

fltmgr, wdflt, vendor AV/VPN filter drivers

These are suggestions, not proof, but paired with the stack and bugcheck they’re usually enough to act.

Making future crashes easier to parse

Force Windows to emit Small memory dumps (MDMP) so analysis works everywhere without WinDbg:

Run in elevated Command Prompt:

reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v MinidumpDir /t REG_EXPAND_SZ /d "%%SystemRoot%%\Minidump" /f

Permissions and installs

Minidump parsing is pure Python. The script auto-installs the minidump package into a local _thirdparty folder next to the script.

Converting full dumps requires WinDbg. The script will try to elevate with UAC and install via:

winget install --id Microsoft.WinDbg -e

winget install --id Microsoft.WindowsSDK -e

or Chocolatey equivalents if winget isn’t available.

On locked-down machines, installation may be denied. In that case the script still returns the bugcheck and parameters from the full-dump header.

Troubleshooting

The script says “not an MDMP” for a file from C:\Windows\Minidump
Windows can place full dumps in that folder. If the header starts with PAGEDU64 or PAGE, it’s a full kernel dump.

No internet or package manager blocked
You’ll still get bugcheck data from full dumps, but not full stack/module analysis.

Symbol resolution
If you use WinDbg and want to override the default symbol server, pass --symbols with your _NT_SYMBOL_PATH.

Security

No cloud upload. All processing is local. The script only reaches the network if it needs to install packages or fetch symbols from Microsoft’s public symbol server.

License

MIT-like. Use at your own risk.

Minimal example for CI
python -m pip install --upgrade pip
python bsod_analyzer.py "C:\Windows\Minidump\*.dmp" --json "artifact.json" || exit /b 0


The script always writes JSON even on partial failures so you can archive results.
