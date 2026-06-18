import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

RUN_LOCATIONS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
]

HIVE_NAME = {
    winreg.HKEY_LOCAL_MACHINE: "HKLM",
    winreg.HKEY_CURRENT_USER: "HKCU",
}


class RunKeysHunter(HunterModule):
    name = "run_keys"
    technique_id = "T1547.001"
    technique_name = "Registry Run Keys / Startup Folder"
    artifact = "Registry Run-key value"
    description = (
        "A REG_SZ value under a Run/RunOnce/RunOnceEx key whose data is "
        "executed each time the associated user (HKCU) or any user (HKLM) "
        "logs on. One of the most abused persistence locations on Windows."
    )

    def run(self) -> List[Detection]:
        detections: List[Detection] = []
        for hive, subkey in RUN_LOCATIONS:
            try:
                with winreg.OpenKey(hive, subkey, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                            i += 1
                        except OSError:
                            break
                        value = str(value)
                        signals = utils.suspicion_signals(value, str(name))
                        if not signals:
                            continue
                        meta = {"hive": HIVE_NAME.get(hive, "?"),
                                "signals": signals}
                        detections.append(self.make_detection(
                            location=f"{HIVE_NAME.get(hive,'?')}\\{subkey}",
                            name=str(name),
                            value=value,
                            metadata=meta,
                        ))
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return detections
