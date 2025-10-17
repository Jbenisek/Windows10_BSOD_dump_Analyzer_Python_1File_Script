#!/usr/bin/env python3
# bsod_analyzer.py
#
# Self-contained Windows dump analyzer for fleets:
# - Parses Minidump (MDMP) directly (auto-installs 'minidump' lib).
# - Auto-unpacks WER .cab/.zip/.gz containers.
# - If it's a full kernel dump (PAGEDU64), and WinDbg install is blocked,
#   parse the DUMP_HEADER64 prefix locally to get BugCheck + params anyway.
# - If allowed, auto-installs WinDbg (winget/choco) and converts full dump -> minidump for deeper analysis.
#
# This file makes its best effort to be "just run it" friendly on random systems.
#
import argparse
import ctypes
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from datetime import datetime
from pathlib import Path

# ---------------------- Explanations/Hints ----------------------
BUGCHECK_EXPLANATIONS = {
    0x0000009F: "DRIVER_POWER_STATE_FAILURE: Driver didn't handle a sleep/hibernate power transition.",
    0x000000D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL: Driver accessed invalid memory at high IRQL.",
    0x0000000A: "IRQL_NOT_LESS_OR_EQUAL: Kernel code touched invalid memory; often a bad driver or unstable RAM/OC.",
    0x0000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: Unhandled kernel exception, usually a buggy driver.",
    0x00000050: "PAGE_FAULT_IN_NONPAGED_AREA: Invalid memory reference; drivers, RAM, disk, or AV filter.",
    0x0000001E: "KMODE_EXCEPTION_NOT_HANDLED: Kernel exception not caught; drivers or hardware instability.",
    0x00000124: "WHEA_UNCORRECTABLE_ERROR: Hardware error (CPU/Memory/PCIe). Thermals/OC/firmware/PSU/hardware.",
    0x00000133: "DPC_WATCHDOG_VIOLATION: Long DPC/ISR latency; storage/GPU drivers or NVMe timeouts.",
    0x00000139: "KERNEL_SECURITY_CHECK_FAILURE: Structure corruption; drivers, memory, or stack issues.",
    0x0000003B: "SYSTEM_SERVICE_EXCEPTION: Exception in system service; graphics stack or filter drivers.",
    0x000000EF: "CRITICAL_PROCESS_DIED: Critical user-mode process died; storage or system file corruption.",
    0x000000C2: "BAD_POOL_CALLER: Pool misuse by a driver; AV/VPN/filesystem filters common.",
    0x0000007F: "UNEXPECTED_KERNEL_MODE_TRAP: Often double fault; overheating/OC/RAM or drivers.",
    0x00000154: "UNEXPECTED_STORE_EXCEPTION: Storage stack problem; SSD/HDD health/firmware/drivers.",
}

DRIVER_HINTS = [
    (re.compile(r"nvlddmkm", re.I), "NVIDIA display driver. Clean reinstall with DDU, then latest WHQL."),
    (re.compile(r"atikmpag|amdkmdag|amdkmdap", re.I), "AMD display driver. Clean reinstall; use stable driver."),
    (re.compile(r"igdkmd", re.I), "Intel display driver. Update via Intel Driver & Support Assistant."),
    (re.compile(r"rt6?40|realtek", re.I), "Realtek NIC. Update NIC driver; review power management."),
    (re.compile(r"ndis|tcpip", re.I), "Network stack. Update NIC/Wi-Fi/VPN filter drivers."),
    (re.compile(r"storport|stornvme|iastor|nvstor|amdsata|nvme", re.I), "Storage stack. Update SATA/NVMe drivers and SSD firmware."),
    (re.compile(r"dxgkrnl|dxgmms", re.I), "DirectX graphics kernel. GPU drivers or 3D workloads involved."),
    (re.compile(r"ntfs", re.I), "NTFS filesystem. Run chkdsk and check disk health/cables."),
    (re.compile(r"clfs|fltmgr|wdflt|wdfilter|klif|tap|asw|avg", re.I), "Filter drivers (AV/VPN). Remove or update security/VPN software."),
]

# ---------------------- Admin helpers ----------------------
def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def relaunch_elevated(extra_args: list[str]) -> None:
    """Relaunch the script with elevation and exit current process."""
    params = " ".join([f'"{a}"' for a in [str(Path(sys.argv[0]).resolve())] + extra_args])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        print(f"Elevation failed: {e}", file=sys.stderr)
        sys.exit(5)
    sys.exit(0)

# ---------------------- Basic IO helpers ----------------------
def read_magic(path: Path, n=8) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)

def is_mdmp(path: Path) -> bool:
    try:
        return read_magic(path, 4) == b"MDMP"
    except Exception:
        return False

def detect_full_dump_signature(path: Path) -> str | None:
    try:
        b8 = read_magic(path, 8)
    except Exception:
        return None
    try:
        s = b8.decode("ascii", errors="ignore")
    except Exception:
        s = ""
    if s.startswith("PAGE") or s.startswith("PAGED"):
        return s or "PAGE*"
    if s.startswith("DUMP"):
        return s or "DUMP*"
    return None

# ---------------------- Container unwrap ----------------------
def try_unpack_wrapper(src: Path) -> Path | None:
    """If src is a CAB/ZIP/GZIP, extract and return a contained .dmp path; else None."""
    tmpdir = Path(tempfile.mkdtemp(prefix="dump_unpack_"))
    try:
        magic = read_magic(src, 4)
    except Exception:
        return None

    # CAB
    if magic == b"MSCF":
        expand = shutil.which("expand")
        if expand:
            try:
                subprocess.check_call([expand, "-F:*", str(src), str(tmpdir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                return None
        else:
            seven = shutil.which("7z") or shutil.which("7za")
            if not seven:
                return None
            try:
                subprocess.check_call([seven, "x", "-y", str(src), f"-o{tmpdir}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                return None
        dmps = list(tmpdir.rglob("*.dmp"))
        return dmps[0] if dmps else None

    # ZIP
    if magic == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(src, "r") as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".dmp"):
                        out = tmpdir / Path(name).name
                        with zf.open(name) as zfi, open(out, "wb") as o:
                            shutil.copyfileobj(zfi, o)
                        return out
        except Exception:
            return None

    # GZIP
    try:
        m2 = read_magic(src, 2)
    except Exception:
        m2 = b""
    if m2 == b"\x1f\x8b":
        try:
            with gzip.open(src, "rb") as g:
                data = g.read()
            out = tmpdir / (src.stem + ".dmp")
            with open(out, "wb") as f:
                f.write(data)
            return out if out.exists() else None
        except Exception:
            return None

    return None

# ---------------------- WinDbg discovery / install ----------------------
def candidate_windbg_paths() -> list[str]:
    return [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\kd.exe",
        r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe",
    ]

def find_windbg() -> str | None:
    for p in candidate_windbg_paths():
        if Path(p).exists():
            return p
    for exe in ("kd.exe", "cdb.exe", "windbg.exe"):
        found = shutil.which(exe)
        if found:
            return found
    return None

def try_install_windbg() -> str | None:
    """Attempt to install WinDbg/Debugging Tools using winget or choco. Returns path or None."""
    # Require admin for installers
    if not is_admin():
        extra = sys.argv[1:] + ["--elevated-install"]
        relaunch_elevated(extra)

    winget = shutil.which("winget")
    if winget:
        cmds = [
            [winget, "install", "--id", "Microsoft.WinDbg", "-e", "--accept-package-agreements", "--accept-source-agreements"],
            [winget, "install", "--id", "Microsoft.WindowsSDK", "-e", "--accept-package-agreements", "--accept-source-agreements"],
        ]
        for cmd in cmds:
            try:
                subprocess.check_call(cmd)
                p = find_windbg()
                if p:
                    return p
            except Exception:
                pass

    choco = shutil.which("choco")
    if choco:
        cmds = [
            [choco, "install", "windbg", "-y", "--no-progress"],
            [choco, "install", "windows-sdk-10.1", "-y", "--no-progress"],
        ]
        for cmd in cmds:
            try:
                subprocess.check_call(cmd)
                p = find_windbg()
                if p:
                    return p
            except Exception:
                pass

    return find_windbg()

# ---------------------- Python 'minidump' availability ----------------------
def ensure_minidump():
    try:
        from minidump.minidumpfile import MinidumpFile  # type: ignore
        return True
    except Exception:
        pass
    vendor_dir = Path(__file__).with_name("_thirdparty")
    vendor_dir.mkdir(exist_ok=True)
    if str(vendor_dir) not in sys.path:
        sys.path.insert(0, str(vendor_dir))
    try:
        from minidump.minidumpfile import MinidumpFile  # type: ignore
        return True
    except Exception:
        pass
    pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check",
               "--no-warn-script-location", "--target", str(vendor_dir), "minidump"]
    try:
        subprocess.check_call(pip_cmd)
    except Exception:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "minidump"])
        except Exception:
            return False
    try:
        from minidump.minidumpfile import MinidumpFile  # type: ignore
        return True
    except Exception:
        return False

# ---------------------- Analysis helpers ----------------------
def map_addr_to_module(modules, addr: int):
    for m in modules:
        try:
            base = getattr(m, "baseaddress", None) or getattr(m, "BaseOfImage", None)
            size = getattr(m, "size", None) or getattr(m, "SizeOfImage", None)
            name = getattr(m, "name", None) or getattr(m, "ModuleName", None)
            if base is None or size is None:
                continue
            if base <= addr < base + size:
                return name, base, size
        except Exception:
            continue
    return None, None, None

def collect_driver_hints(*fields: str):
    suspects = set()
    for rx, hint in DRIVER_HINTS:
        for v in fields:
            if v and rx.search(v):
                suspects.add(hint)
    return sorted(suspects) if suspects else []

# ---------------------- Minidump analysis ----------------------
def analyze_minidump(dmp_path: Path) -> dict:
    if not ensure_minidump():
        return {"error": "Could not import or auto-install 'minidump' package."}
    from minidump.minidumpfile import MinidumpFile  # type: ignore

    try:
        md = MinidumpFile.parse(str(dmp_path))
    except Exception as e:
        return {"error": f"Failed to parse minidump: {e}"}

    result: dict = {"type": "minidump"}

    # System info
    try:
        sysinfo = md.get_system_info()
        if sysinfo:
            major = getattr(sysinfo, "MajorVersion", None)
            minor = getattr(sysinfo, "MinorVersion", None)
            build = getattr(sysinfo, "BuildNumber", None)
            arch  = str(getattr(sysinfo, "ProcessorArchitecture", ""))
            np    = getattr(sysinfo, "NumberOfProcessors", None)
            result["os"] = f"Windows {major}.{minor} build {build}" if None not in (major, minor, build) else "Windows (version unknown)"
            result["cpu_arch"] = arch
            result["cpu_count"] = np
    except Exception:
        pass

    # Exception or bugcheck
    exc_code = None
    exc_addr = None
    exc_tid  = None
    try:
        exc = md.get_exception_stream()
        if exc:
            exc_code = getattr(exc.ExceptionRecord, "ExceptionCode", None)
            exc_addr = getattr(exc.ExceptionRecord, "ExceptionAddress", None)
            exc_tid  = getattr(exc, "ThreadId", None)
    except Exception:
        pass

    bugcheck = None
    if exc_code is None:
        try:
            get_bc = getattr(md, "get_bugcheck_information", None)
            if callable(get_bc):
                bugcheck = get_bc()
            else:
                bc_stream = md.get_stream(26)  # BugCheckInformationStream
                bugcheck = bc_stream
        except Exception:
            bugcheck = None

    if exc_code is not None:
        result["exception_code"] = f"0x{exc_code:08X}"
        if exc_addr is not None:
            result["exception_address"] = f"0x{exc_addr:X}"
        if exc_tid is not None:
            result["exception_thread_id"] = exc_tid
    elif bugcheck is not None:
        try:
            code = getattr(bugcheck, "BugCheckCode", None) or getattr(bugcheck, "bugcheck_code", None)
            params = []
            for k in ("Parameter1", "Parameter2", "Parameter3", "Parameter4", "param1", "param2", "param3", "param4"):
                v = getattr(bugcheck, k, None)
                if v is not None:
                    params.append(f"0x{int(v):X}")
            result["bugcheck_code"] = f"0x{int(code):08X}" if code is not None else None
            result["bugcheck_params"] = params
            if isinstance(code, int) and code in BUGCHECK_EXPLANATIONS:
                result["explanation"] = BUGCHECK_EXPLANATIONS[code]
        except Exception:
            result["bugcheck_code"] = None

    # Modules/threads
    try:
        mods = list(md.modules.modules) if md.modules else []
        result["modules"] = [getattr(m, "name", None) or getattr(m, "ModuleName", None) for m in mods[:50]]
    except Exception:
        mods = []
    try:
        tl = list(md.threads.threads) if md.threads else []
        result["thread_ids"] = [getattr(t, "ThreadId", None) for t in tl[:50]]
    except Exception:
        pass

    if exc_addr is not None and mods:
        name, base, size = map_addr_to_module(mods, exc_addr)
        if name:
            result["faulting_module"] = name
            result["faulting_module_base"] = f"0x{base:X}"
            result["faulting_module_size"] = f"0x{size:X}"
            result["driver_hints"] = collect_driver_hints(name)
    else:
        if "modules" in result:
            joined = " ".join([n for n in result["modules"] if n])
            hints = collect_driver_hints(joined)
            if hints:
                result["driver_hints"] = hints

    return result

def summarize_minidump(data: dict) -> str:
    lines = ["Minidump analysis"]
    if data.get("os"):
        lines.append(f"OS: {data['os']}")
    if data.get("cpu_arch"):
        lines.append(f"CPU: {data['cpu_arch']}  Cores: {data.get('cpu_count')}")
    if "exception_code" in data:
        lines.append(f"Exception: {data['exception_code']} at {data.get('exception_address')} (TID {data.get('exception_thread_id')})")
    if "bugcheck_code" in data:
        lines.append(f"BugCheck: {data['bugcheck_code']} Params: {', '.join(data.get('bugcheck_params', []))}")
        if data.get("explanation"):
            lines.append(f"Explanation: {data['explanation']}")
    if data.get("faulting_module"):
        lines.append(f"Faulting module: {data['faulting_module']} @ {data.get('faulting_module_base')} (+{data.get('faulting_module_size')})")
    if hints := data.get("driver_hints"):
        lines.append("Hints:")
        for h in hints:
            lines.append(f"  - {h}")
    if mods := data.get("modules"):
        lines.append("Loaded modules (top):")
        for m in mods[:20]:
            lines.append(f"  - {m}")
    if tids := data.get("thread_ids"):
        lines.append("Thread IDs (top): " + ", ".join(str(t) for t in tids[:20] if t is not None))
    return "\n".join(lines)

# ---------------------- Full dump header parse (no WinDbg needed) ----------------------
class DUMP_HEADER64_PREFIX(ctypes.Structure):
    _fields_ = [
        ("Signature", ctypes.c_uint32),           # 'PAGE'
        ("ValidDump", ctypes.c_uint32),           # 'DU64'
        ("MajorVersion", ctypes.c_uint32),
        ("MinorVersion", ctypes.c_uint32),
        ("DirectoryTableBase", ctypes.c_uint64),
        ("PfnDataBase", ctypes.c_uint64),
        ("PsLoadedModuleList", ctypes.c_uint64),
        ("PsActiveProcessHead", ctypes.c_uint64),
        ("MachineImageType", ctypes.c_uint32),
        ("NumberProcessors", ctypes.c_uint32),
        ("BugCheckCode", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),                # alignment to 8
        ("BugCheckParameter1", ctypes.c_uint64),
        ("BugCheckParameter2", ctypes.c_uint64),
        ("BugCheckParameter3", ctypes.c_uint64),
        ("BugCheckParameter4", ctypes.c_uint64),
    ]

def parse_full_dump_header(dmp_path: Path) -> dict:
    """Parse key fields from 64-bit kernel dump header (PAGEDU64)."""
    try:
        with open(dmp_path, "rb") as f:
            header = f.read(ctypes.sizeof(DUMP_HEADER64_PREFIX))
    except Exception as e:
        return {"error": f"Failed to read dump header: {e}"}

    if len(header) < ctypes.sizeof(DUMP_HEADER64_PREFIX):
        return {"error": "Dump header too small to parse."}

    h = DUMP_HEADER64_PREFIX.from_buffer_copy(header)
    sig = header[0:4]
    val = header[4:8]
    if not (sig == b"PAGE" and val == b"DU64"):
        return {"error": f"Not a recognized 64-bit kernel dump header (first 8 bytes: {sig+val!r})."}

    res = {
        "type": "full_dump_header",
        "signature": "PAGEDU64",
        "major_version": int(h.MajorVersion),
        "minor_version": int(h.MinorVersion),
        "machine_image_type": int(h.MachineImageType),
        "number_processors": int(h.NumberProcessors),
        "bugcheck_code": f"0x{int(h.BugCheckCode):08X}",
        "bugcheck_params": [
            f"0x{int(h.BugCheckParameter1):X}",
            f"0x{int(h.BugCheckParameter2):X}",
            f"0x{int(h.BugCheckParameter3):X}",
            f"0x{int(h.BugCheckParameter4):X}",
        ],
    }
    code = int(h.BugCheckCode)
    if code in BUGCHECK_EXPLANATIONS:
        res["explanation"] = BUGCHECK_EXPLANATIONS[code]
    return res

def summarize_full_header(data: dict) -> str:
    lines = ["Full dump header (parsed locally)"]
    if "bugcheck_code" in data:
        lines.append(f"BugCheck: {data['bugcheck_code']} Params: {', '.join(data.get('bugcheck_params', []))}")
    lines.append(f"OS Version: {data.get('major_version')}.{data.get('minor_version')}  CPUs: {data.get('number_processors')}  MachineType: {data.get('machine_image_type')}")
    if data.get("explanation"):
        lines.append(f"Explanation: {data['explanation']}")
    return "\n".join(lines)

# ---------------------- kd/cdb conversion and analyze ----------------------
def ensure_windbg_available(allow_install=True) -> str | None:
    p = find_windbg()
    if p:
        return p
    if allow_install:
        return try_install_windbg()
    return None

def kd_convert_to_minidump(kd_path: str, src_dump: Path) -> Path | None:
    out_dir = Path(tempfile.mkdtemp(prefix="minidump_from_full_"))
    out_dmp = out_dir / (src_dump.stem + ".minidump.dmp")
    cmds = f'.dump /ma "{out_dmp}"; q'
    env = os.environ.copy()
    env.setdefault("_NT_SYMBOL_PATH", r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols")
    try:
        if kd_path.lower().endswith("windbg.exe"):
            cmd = [kd_path, "-z", str(src_dump), "-c", cmds, "-Q"]
        else:
            cmd = [kd_path, "-z", str(src_dump), "-c", cmds]
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=env, text=True, errors="replace")
    except subprocess.CalledProcessError:
        pass
    except Exception:
        return None
    return out_dmp if out_dmp.exists() else None

def kd_analyze_text(kd_path: str, src_dump: Path) -> str:
    cmds = "!analyze -v; .ecxr; kv; lm; q"
    env = os.environ.copy()
    env.setdefault("_NT_SYMBOL_PATH", r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols")
    try:
        if kd_path.lower().endswith("windbg.exe"):
            cmd = [kd_path, "-z", str(src_dump), "-c", cmds, "-Q"]
        else:
            cmd = [kd_path, "-z", str(src_dump), "-c", cmds]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=env, text=True, errors="replace")
        return out
    except Exception as e:
        return f"WinDbg analyze failed: {e}"

def parse_windbg_output(txt: str) -> dict:
    data = {
        "bugcheck_code": None,
        "bugcheck_params": [],
        "probably_caused_by": None,
        "module_name": None,
        "image_name": None,
        "process_name": None,
        "failure_bucket_id": None,
        "stack_text": None,
        "raw_length": len(txt),
    }
    m = re.search(r"BugCheck\s+([0-9A-Fa-fx]+)\s*,\s*\{([^\}]+)\}", txt)
    if m:
        code_str = m.group(1)
        try:
            data["bugcheck_code"] = int(code_str, 16 if code_str.lower().startswith("0x") else 10)
        except Exception:
            data["bugcheck_code"] = None
        params = [p.strip() for p in m.group(2).split(",")]
        data["bugcheck_params"] = params
    m = re.search(r"Probably caused by\s*:\s*([^\s]+)", txt)
    if m:
        data["probably_caused_by"] = m.group(1).strip()
    m = re.search(r"MODULE_NAME\s*:\s*(\S+)", txt)
    if m:
        data["module_name"] = m.group(1).strip()
    m = re.search(r"IMAGE_NAME\s*:\s*(\S+)", txt)
    if m:
        data["image_name"] = m.group(1).strip()
    m = re.search(r"PROCESS_NAME\s*:\s*(\S+)", txt)
    if m:
        data["process_name"] = m.group(1).strip()
    m = re.search(r"FAILURE_BUCKET_ID\s*:\s*(.+)", txt)
    if m:
        data["failure_bucket_id"] = m.group(1).strip()
    m = re.search(r"STACK_TEXT:\s*(?:\n+-+\n)?(?P<stack>(?:.*\n){1,200})\n\s*\n", txt)
    if m:
        data["stack_text"] = "\n".join([line.rstrip() for line in m.group("stack").splitlines() if line.strip()])
    code = data["bugcheck_code"]
    if isinstance(code, int) and code in BUGCHECK_EXPLANATIONS:
        data["explanation"] = BUGCHECK_EXPLANATIONS[code]
    elif isinstance(code, int):
        data["explanation"] = "Unknown bugcheck code or not in common set."
    else:
        data["explanation"] = "Bugcheck not detected."
    suspects = set()
    for rx, hint in DRIVER_HINTS:
        for field in ("probably_caused_by", "module_name", "image_name", "stack_text", "failure_bucket_id"):
            v = data.get(field)
            if isinstance(v, str) and rx.search(v or ""):
                suspects.add(hint)
    data["driver_hints"] = sorted(suspects) if suspects else []
    return data

# ---------------------- Reporting ----------------------
def write_json_report(out_path: Path, payload: dict) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

# ---------------------- Main ----------------------
def main():
    ap = argparse.ArgumentParser(description="Analyze Windows dumps. Auto-installs minidump lib; optionally installs WinDbg; can parse full dump header without WinDbg.")
    ap.add_argument("dump", type=str, help="Path to .dmp or container (.cab/.zip/.gz)")
    ap.add_argument("--json", type=str, default=None, help="Optional path for JSON report")
    ap.add_argument("--symbols", type=str, default=None, help="_NT_SYMBOL_PATH for WinDbg operations")
    ap.add_argument("--elevated-install", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    src_path = Path(args.dump).expanduser().resolve()
    if not src_path.exists():
        print(f"File not found: {src_path}", file=sys.stderr)
        sys.exit(2)

    # Unwrap container if needed
    working_path = src_path
    if not is_mdmp(working_path):
        unwrapped = try_unpack_wrapper(working_path)
        if unwrapped and unwrapped.exists():
            working_path = unwrapped

    report = {
        "dump_path": str(src_path),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tool": "bsod_analyzer.py",
        "method": None,
        "result": {},
    }

    # Try minidump first
    if is_mdmp(working_path):
        report["method"] = "minidump"
        result = analyze_minidump(working_path)
        report["result"] = result
        if "error" in result:
            print(f"Minidump parse error: {result['error']}", file=sys.stderr)
        else:
            print(summarize_minidump(result))
    else:
        # Not MDMP -> full dump or other
        sig = detect_full_dump_signature(working_path) or "unknown"
        # Attempt WinDbg route
        kd = ensure_windbg_available(allow_install=True)
        if kd:
            report["method"] = f"full_dump:{sig}:windbg"
            mdmp = kd_convert_to_minidump(kd, working_path)
            kd_head = kd_analyze_text(kd, working_path)
            if mdmp and mdmp.exists():
                mdmp_result = analyze_minidump(mdmp)
                report["result"] = {
                    "windbg_path": kd,
                    "converted_minidump": str(mdmp),
                    "windbg_head": "\n".join(kd_head.splitlines()[:200]) if isinstance(kd_head, str) else None,
                    "minidump_analysis": mdmp_result,
                }
                if "error" in mdmp_result:
                    print("WinDbg conversion done; parsing of minidump failed.", file=sys.stderr)
                else:
                    print(summarize_minidump(mdmp_result))
            else:
                parsed = parse_windbg_output(kd_head) if isinstance(kd_head, str) else {"error": "No kd output"}
                parsed["windbg_path"] = kd
                report["result"] = parsed
                lines = ["Kernel dump analysis via WinDbg"]
                if parsed.get("bugcheck_code") is not None:
                    lines.append(f'BugCheck: 0x{parsed["bugcheck_code"]:08X}')
                if parsed.get("probably_caused_by"):
                    lines.append(f'Probably caused by: {parsed["probably_caused_by"]}')
                if parsed.get("explanation"):
                    lines.append(f'Explanation: {parsed["explanation"]}')
                if parsed.get("driver_hints"):
                    lines.append("Hints:")
                    for h in parsed["driver_hints"]:
                        lines.append(f"  - {h}")
                print("\n".join(lines))
        else:
            # No WinDbg available -> parse header directly to at least get bugcheck
            report["method"] = f"full_dump:{sig}:local_header"
            header_info = parse_full_dump_header(working_path)
            report["result"] = header_info
            if "error" in header_info:
                first8 = ""
                try:
                    first8 = " ".join(f"{b:02X}" for b in read_magic(working_path, 8))
                except Exception:
                    first8 = "unreadable"
                report["result"] = {
                    "error": header_info["error"],
                    "signature": sig,
                    "magic_first_bytes": first8,
                    "next_steps": [
                        "Could not acquire WinDbg automatically and local header parse failed. Ensure the dump is not corrupted.",
                        "If policy blocks installers, enable Small memory dump (256 KB) to produce MDMP files: System Properties > Advanced > Startup and Recovery.",
                    ],
                }
                print("Failed to parse full dump header and cannot install WinDbg.", file=sys.stderr)
            else:
                print(summarize_full_header(header_info))

    out_json = Path(args.json) if args.json else src_path.with_suffix(".analysis.json")
    try:
        write_json_report(out_json, report)
        print(f"\nSaved JSON report: {out_json}")
    except Exception as e:
        print(f"Failed to write JSON report: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
