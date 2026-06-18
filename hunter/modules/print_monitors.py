import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

MON_KEY = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
DEFAULT_MONITORS = {
    "Local Port", "Standard TCP/IP Port", "USB Monitor", "WSD Port",
    "Microsoft Shared Fax Monitor", "BJ Language Monitor",
    "Microsoft Print to PDF", "Appmon", "PJL Language Monitor",
    "Microsoft XPS Port Monitor",
}


class PrintMonitorsHunter(HunterModule):
    name = "print_monitors"
    technique_id = "T1547.010"
    technique_name = "Port Monitors / Print Monitors"
    artifact = "Print monitor DLL"
    description = (
        "Subkey of HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors "
        "with a Driver value naming a DLL the Print Spooler loads at startup "
        "as SYSTEM. Non-default monitors are a stealthy DLL-load + SYSTEM "
        "persistence vector (T1547.010)."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MON_KEY) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    if sub in DEFAULT_MONITORS:
                        continue
                    try:
                        with winreg.OpenKey(k, sub) as sk:
                            try:
                                driver, _ = winreg.QueryValueEx(sk, "Driver")
                            except OSError:
                                continue
                            out.append(self.make_detection(
                                location=f"HKLM\\{MON_KEY}\\{sub}",
                                name=sub, value=str(driver),
                                reasons=[f"Non-default print monitor: {sub}"],
                                metadata={"rare_technique": True,
                                          "recency": utils.recency_label(utils.reg_key_mtime(sk))},
                            ))
                    except OSError:
                        continue
        except OSError:
            pass
        return out
