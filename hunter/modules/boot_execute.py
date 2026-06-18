import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

SM_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"
DEFAULT_BOOTEXEC = {"autocheck autochk *"}


class BootExecuteHunter(HunterModule):
    name = "boot_execute"
    technique_id = "T1547.001"
    technique_name = "Session Manager BootExecute"
    artifact = "Session Manager native-image execution list"
    description = (
        "REG_MULTI_SZ values under HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
        "Session Manager. BootExecute lists native applications run by smss.exe "
        "before Win32 starts; SetupExecute / Execute / S0InitialCommand are "
        "related extension points expected to be empty on a clean system."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SM_KEY) as k:
                for vname in ("BootExecute", "SetupExecute", "Execute",
                              "S0InitialCommand"):
                    try:
                        v, _ = winreg.QueryValueEx(k, vname)
                    except OSError:
                        continue
                    if isinstance(v, list):
                        items = [x for x in v if x]
                    elif isinstance(v, str) and v.strip():
                        items = [v]
                    else:
                        items = []
                    for item in items:
                        low = item.strip().lower()
                        if vname == "BootExecute" and low in DEFAULT_BOOTEXEC:
                            continue
                        # SetupExecute/Execute/S0InitialCommand should be empty
                        out.append(self.make_detection(
                            location=f"HKLM\\{SM_KEY}",
                            name=vname, value=str(item),
                            reasons=[f"Non-default Session Manager {vname} entry"],
                            metadata={"rare_technique": True},
                        ))
        except OSError:
            pass
        return out
