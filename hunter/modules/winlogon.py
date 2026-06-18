import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
NOTIFY_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"

EXPECTED = {
    "shell": "explorer.exe",
    "userinit": r"c:\windows\system32\userinit.exe,",
}


class WinlogonHunter(HunterModule):
    name = "winlogon"
    technique_id = "T1547.004"
    technique_name = "Winlogon Helper DLL"
    artifact = "Winlogon registry value"
    description = (
        "Values under HKLM\\...\\Winlogon. Shell/Userinit are executed by "
        "winlogon.exe during user logon; sub-key Notify hosts legacy DLL "
        "notification packages also loaded at logon."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY) as k:
                for vname, expected in EXPECTED.items():
                    try:
                        v, _ = winreg.QueryValueEx(k, vname.title())
                    except OSError:
                        continue
                    if str(v).strip().lower() != expected:
                        out.append(self.make_detection(
                            location=f"HKLM\\{WINLOGON_KEY}",
                            name=vname.title(),
                            value=str(v),
                            reasons=[f"{vname.title()} differs from default ('{expected}')"],
                            metadata={"rare_technique": True, "expected": expected},
                        ))
                # GinaDLL deprecated; System / UserinitMprLogonScript have no
                # legitimate default value. Taskman + VmApplet have legit
                # defaults so they are checked elsewhere or ignored.
                for extra in ("GinaDLL", "System", "UserinitMprLogonScript"):
                    try:
                        v, _ = winreg.QueryValueEx(k, extra)
                        out.append(self.make_detection(
                            location=f"HKLM\\{WINLOGON_KEY}",
                            name=extra, value=str(v),
                            reasons=[f"Unusual Winlogon value '{extra}' present (should be absent)"],
                            metadata={"rare_technique": True},
                        ))
                    except OSError:
                        continue
        except OSError:
            pass

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NOTIFY_KEY) as nk:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(nk, i)
                        i += 1
                    except OSError:
                        break
                    out.append(self.make_detection(
                        location=f"HKLM\\{NOTIFY_KEY}\\{sub}",
                        name=sub, value="(Notify package present)",
                        reasons=["Winlogon Notify package present (legacy persistence)"],
                        metadata={"rare_technique": True},
                    ))
        except OSError:
            pass
        return out
