import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

KEY = r"SOFTWARE\Microsoft\Netsh"

DEFAULT_HELPERS = {
    "authfwcfg", "dhcpcmonitor", "dot3cfg", "fwcfg", "hnetmon", "ifmon",
    "nettrace", "netiohlp", "nshhttp", "nshipsec", "nshwfp", "p2pnetsh",
    "rasmontr", "rpcnsh", "wcnnetsh", "whhelper", "wlancfg", "wshelper",
    "wwancfg", "mpsnsh", "naphlpr", "nshipv6", "peerdistsh", "wfpdiag",
    "nshhyperv", "netshell",
}


class NetshHelperHunter(HunterModule):
    name = "netsh_helper"
    technique_id = "T1546.007"
    technique_name = "Event Triggered Execution: Netsh Helper DLL"
    artifact = "Netsh helper DLL registration"
    description = (
        "REG_SZ values under HKLM\\SOFTWARE\\Microsoft\\Netsh. Each value "
        "names a DLL loaded by netsh.exe on startup — invoking netsh.exe "
        "(very common) loads every registered helper, making this a stealthy "
        "DLL-load persistence point."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        i += 1
                    except OSError:
                        break
                    base = str(value).lower().replace(".dll", "").rsplit("\\", 1)[-1]
                    if base in DEFAULT_HELPERS:
                        continue
                    out.append(self.make_detection(
                        location=f"HKLM\\{KEY}",
                        name=str(name), value=str(value),
                        reasons=[f"Non-default netsh helper DLL: {base}"],
                        metadata={"rare_technique": True,
                                  "recency": utils.recency_label(utils.reg_key_mtime(k))},
                    ))
        except OSError:
            pass
        return out
