import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

KEY = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
DEFAULT = {"NtpClient", "NtpServer", "VMICTimeProvider"}


class TimeProvidersHunter(HunterModule):
    name = "time_providers"
    technique_id = "T1547.003"
    technique_name = "Boot or Logon Autostart Execution: Time Providers"
    artifact = "W32Time provider DLL"
    description = (
        "Subkey of HKLM\\...\\W32Time\\TimeProviders listing a DllName that "
        "the Windows Time Service loads at startup. Default providers are "
        "NtpClient, NtpServer, and (on VMs) VMICTimeProvider — any other "
        "entry is a DLL-load persistence vector."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    if sub in DEFAULT:
                        continue
                    try:
                        with winreg.OpenKey(k, sub) as sk:
                            dll = self._q(sk, "DllName")
                            if not dll:
                                continue
                            out.append(self.make_detection(
                                location=f"HKLM\\{KEY}\\{sub}",
                                name=sub, value=str(dll),
                                reasons=[f"Non-default time provider: {sub}"],
                                metadata={"rare_technique": True,
                                          "recency": utils.recency_label(utils.reg_key_mtime(sk))},
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
