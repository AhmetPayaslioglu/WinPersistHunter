import os
import re
import math
import json
import ctypes
import subprocess
import winreg
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List

# --------------------------------------------------------------------------
# Path / extension heuristics
# --------------------------------------------------------------------------

# Path tokens that — by themselves — are mildly suspicious but NOT enough to
# emit a detection. Many legitimate Electron apps live in AppData.
MILDLY_SUSPICIOUS_TOKENS = [
    "\\appdata\\",
    "\\programdata\\",
]

# Path tokens that are *strongly* suspicious — malware-typical drop sites.
STRONGLY_SUSPICIOUS_TOKENS = [
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
    "\\windows\\tasks\\",
    "\\windows\\debug\\",
    "\\windows\\addins\\",
]

LOLBINS = {
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "cscript.exe", "wscript.exe", "powershell.exe",
    "pwsh.exe", "hh.exe", "ieexec.exe", "msiexec.exe", "forfiles.exe",
    "cmstp.exe", "scriptrunner.exe", "odbcconf.exe", "pcalua.exe",
    "presentationhost.exe", "msxsl.exe", "csi.exe", "rcsi.exe",
    "ie4uinit.exe", "extexport.exe", "extrac32.exe", "makecab.exe",
    "esentutl.exe",
}

POWERSHELL_OBFUSCATION_FLAGS = [
    "-enc", "-encodedcommand", " -e ", "frombase64string", "iex ",
    "invoke-expression", "downloadstring", "downloadfile",
    "-w hidden", "-windowstyle hidden", "bypass",
    "[char[]]", "[convert]::", "scriptblock::create",
    "new-object net.webclient", "-ec ", "-en ",
]

SCRIPTING_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
                        ".jse", ".wsf", ".wsh", ".hta", ".scr"}

RTLO_CHARS = ["‮", "‭", "‫", "‪"]

# Recency thresholds in days
RECENT_DAYS = 30
VERY_RECENT_DAYS = 7

# Windows FILETIME → Unix offset in 100-ns intervals
FT_EPOCH_OFFSET = 116444736000000000

# Known-good install roots — paths under these are not interesting on their own
TRUSTED_ROOTS = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
]


# --------------------------------------------------------------------------
# Subprocess / PowerShell — encoding-safe
# --------------------------------------------------------------------------

def run_powershell(script: str, timeout: int = 30) -> str:
    """Run a PowerShell command and return stdout as a UTF-8 string.

    Forces both Python-side and PowerShell-side encoding to UTF-8 to avoid
    cp1254 / cp1252 charmap errors on non-English Windows hosts.
    """
    prelude = (
        "$ErrorActionPreference='SilentlyContinue';"
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "$OutputEncoding=[System.Text.Encoding]::UTF8;"
    )
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-OutputFormat", "Text", "-Command", prelude + script],
            capture_output=True, timeout=timeout
        )
        return (r.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Lightweight helpers
# --------------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def expand_env(path: str) -> str:
    if not path:
        return path
    try:
        return os.path.expandvars(path)
    except Exception:
        return path


def extract_executable(command: str) -> Optional[str]:
    if not command:
        return None
    s = command.strip()
    if s.startswith('"'):
        m = re.match(r'"([^"]+)"', s)
        if m:
            return m.group(1)
    parts = s.split()
    return parts[0] if parts else None


def in_trusted_root(path: str) -> bool:
    if not path:
        return False
    p = expand_env(path).lower().lstrip('"').lstrip()
    return any(p.startswith(r) for r in TRUSTED_ROOTS)


def is_mildly_suspicious_path(path: str) -> bool:
    if not path:
        return False
    p = path.lower()
    return any(tok in p for tok in MILDLY_SUSPICIOUS_TOKENS)


def is_strongly_suspicious_path(path: str) -> bool:
    if not path:
        return False
    p = path.lower()
    return any(tok in p for tok in STRONGLY_SUSPICIOUS_TOKENS)


def is_lolbin(command: str) -> Optional[str]:
    if not command:
        return None
    cmd = command.lower()
    exe = extract_executable(cmd) or ""
    exe_base = os.path.basename(exe).lower()
    if exe_base in LOLBINS:
        return exe_base
    for b in LOLBINS:
        if " " + b in cmd or "\\" + b in cmd:
            return b
    return None


def has_powershell_obfuscation(command: str) -> List[str]:
    if not command:
        return []
    c = " " + command.lower() + " "
    return [f.strip() for f in POWERSHELL_OBFUSCATION_FLAGS if f in c]


def has_rtlo(s: str) -> bool:
    if not s:
        return False
    return any(ch in s for ch in RTLO_CHARS)


def has_double_extension(path: str) -> bool:
    if not path:
        return False
    name = os.path.basename(path).lower()
    parts = name.split(".")
    if len(parts) < 3:
        return False
    common_doc = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg",
                  "png", "txt", "zip", "rar"}
    risky_exec = {"exe", "scr", "com", "bat", "cmd", "lnk", "vbs", "js",
                  "hta", "ps1", "wsf", "jse"}
    return parts[-2] in common_doc and parts[-1] in risky_exec


def is_scripting_ext(path: str) -> bool:
    if not path:
        return False
    return Path(path).suffix.lower() in SCRIPTING_EXTENSIONS


def file_exists(path: str) -> bool:
    if not path:
        return False
    try:
        return Path(expand_env(path)).exists()
    except Exception:
        return False


def reg_key_mtime(key) -> Optional[datetime]:
    try:
        _, _, ft = winreg.QueryInfoKey(key)
        if not ft:
            return None
        secs = (ft - FT_EPOCH_OFFSET) / 10_000_000
        if secs <= 0:
            return None
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    except Exception:
        return None


def file_mtime(path: str) -> Optional[datetime]:
    try:
        p = Path(expand_env(path))
        if not p.exists():
            return None
        return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
    except Exception:
        return None


def recency_label(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    now = datetime.now(timezone.utc)
    age = now - dt
    if age <= timedelta(days=VERY_RECENT_DAYS):
        return "very_recent"
    if age <= timedelta(days=RECENT_DAYS):
        return "recent"
    return None


# --------------------------------------------------------------------------
# The single most important gate: real suspicion signals.
# A finding without at least one of these is, by default, NOT worth emitting.
# --------------------------------------------------------------------------

def suspicion_signals(command: str, name: str = "") -> List[str]:
    """Return high-confidence suspicion signals present in command/name.

    If the invoked executable is in a trusted install root (C:\\Windows,
    Program Files, etc.) we only check for genuinely malicious-only signals
    (RTLO, double extension) — arguments to a legitimate signed binary are
    not interesting on their own (browsers carry long --feature flags etc).
    """
    out = []
    if not command and not name:
        return out
    exe = extract_executable(command) or ""

    # Trusted, real-binary invocation → quiet branch.
    if exe and in_trusted_root(exe):
        if has_rtlo(name) or has_rtlo(command):
            out.append("rtlo_character")
        if has_double_extension(name) or has_double_extension(exe):
            out.append("double_extension")
        return out

    lol = is_lolbin(command)
    if lol:
        out.append(f"lolbin:{lol}")

    obf = has_powershell_obfuscation(command)
    if obf:
        out.append("ps_obfuscation:" + ",".join(obf[:3]))

    if has_rtlo(name) or has_rtlo(command):
        out.append("rtlo_character")

    if has_double_extension(name) or has_double_extension(exe):
        out.append("double_extension")

    if is_scripting_ext(exe):
        out.append("scripting_ext:" + Path(exe).suffix.lower())

    if is_strongly_suspicious_path(exe):
        out.append("strong_path")

    if command and shannon_entropy(command) > 5.2 and len(command) > 150 and \
       not in_trusted_root(exe):
        out.append("high_entropy_command")

    return out
