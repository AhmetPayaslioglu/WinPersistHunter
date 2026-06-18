import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SILENT_EXIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
ACCESSIBILITY_BINS = {"sethc.exe", "utilman.exe", "magnify.exe", "narrator.exe",
                      "osk.exe", "displayswitch.exe", "atbroker.exe"}


class IFEOHunter(HunterModule):
    name = "ifeo"
    technique_id = "T1546.012"
    technique_name = "Image File Execution Options Injection"
    artifact = "Image File Execution Options key"
    description = (
        "An IFEO subkey for a given EXE. When set, the 'Debugger' value is "
        "launched in place of the target executable; GlobalFlag+SilentProcessExit "
        "MonitorProcess pair launches a monitor on the target's exit. Both "
        "patterns are essentially never used legitimately."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY) as root:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            debugger = self._q(k, "Debugger")
                            gflags = self._q(k, "GlobalFlag")
                            if debugger:
                                reasons = ["IFEO Debugger value is set"]
                                if sub.lower() in ACCESSIBILITY_BINS:
                                    reasons.append(
                                        "Accessibility binary targeted (sticky-keys backdoor pattern)")
                                out.append(self.make_detection(
                                    location=f"HKLM\\{IFEO_KEY}\\{sub}",
                                    name=sub, value=str(debugger),
                                    reasons=reasons,
                                    metadata={"rare_technique": True,
                                              "recency": utils.recency_label(utils.reg_key_mtime(k))},
                                ))
                            if isinstance(gflags, int) and gflags & 0x200:
                                # Pair with SilentProcessExit MonitorProcess if present
                                monitor = None
                                try:
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                                        f"{SILENT_EXIT_KEY}\\{sub}") as sk:
                                        monitor = self._q(sk, "MonitorProcess")
                                except OSError:
                                    pass
                                if monitor:
                                    out.append(self.make_detection(
                                        location=f"HKLM\\{SILENT_EXIT_KEY}\\{sub}",
                                        name=f"{sub} (SilentProcessExit)",
                                        value=str(monitor),
                                        reasons=["GlobalFlag=0x200 + SilentProcessExit MonitorProcess set"],
                                        metadata={"rare_technique": True},
                                    ))
                    except OSError:
                        continue
        except OSError:
            pass
        return out

    @staticmethod
    def _q(k, name):
        try:
            v, _ = winreg.QueryValueEx(k, name)
            return v
        except OSError:
            return None
