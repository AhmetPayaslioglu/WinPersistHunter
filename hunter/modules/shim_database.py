import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

PATHS = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
]


class ShimDatabaseHunter(HunterModule):
    name = "shim_database"
    technique_id = "T1546.011"
    technique_name = "Event Triggered Execution: Application Shimming"
    artifact = "Custom application shim database (SDB)"
    description = (
        "An installed shim database (.sdb) registered under AppCompatFlags. "
        "Shims hook process startup; custom ones are uncommon and have been "
        "used by groups like FIN7 / Carbanak for in-process persistence."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        for path in PATHS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(k, i)
                            i += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(k, sub) as sk:
                                desc = self._q(sk, "DatabaseDescription")
                                dbpath = self._q(sk, "DatabasePath")
                                out.append(self.make_detection(
                                    location=f"HKLM\\{path}\\{sub}",
                                    name=str(desc) or sub,
                                    value=str(dbpath or sub),
                                    reasons=["Custom shim database installed"],
                                    metadata={"rare_technique": True,
                                              "recency": utils.recency_label(utils.reg_key_mtime(sk))},
                                ))
                        except OSError:
                            continue
            except OSError:
                continue
        return out

    @staticmethod
    def _q(k, name):
        try:
            v, _ = winreg.QueryValueEx(k, name)
            return v
        except OSError:
            return None
