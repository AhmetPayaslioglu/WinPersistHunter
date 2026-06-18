import winreg
from typing import List, Set
from ..base import HunterModule, Detection
from .. import utils


def _clsids_under(hive, root_path) -> Set[str]:
    found = set()
    try:
        with winreg.OpenKey(hive, root_path) as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                    i += 1
                except OSError:
                    break
                if name.startswith("{") and name.endswith("}"):
                    found.add(name.lower())
    except OSError:
        pass
    return found


def _read_default(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            try:
                v, _ = winreg.QueryValueEx(k, "")
            except OSError:
                v = None
            return v, utils.reg_key_mtime(k)
    except OSError:
        return None, None


class COMHijackHunter(HunterModule):
    name = "com_hijack"
    technique_id = "T1546.015"
    technique_name = "Event Triggered Execution: Component Object Model Hijacking"
    artifact = "HKCU COM CLSID server registration"
    description = (
        "Per-user CLSID registration under HKCU\\Software\\Classes\\CLSID. "
        "Windows resolves CLSIDs in HKCU before HKLM, so an HKCU entry for a "
        "system-known CLSID hijacks every COM instantiation by that user."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        hklm = _clsids_under(winreg.HKEY_LOCAL_MACHINE, r"Software\Classes\CLSID")
        hkcu = _clsids_under(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID")
        # Only the CLSIDs where HKCU shadows HKLM are interesting.
        shadows = hkcu & hklm
        for clsid in shadows:
            for server in ("InprocServer32", "LocalServer32", "TreatAs"):
                path = rf"Software\Classes\CLSID\{clsid}\{server}"
                v, mtime = _read_default(winreg.HKEY_CURRENT_USER, path)
                if not v:
                    continue
                # Note: the "HKCU shadows HKLM" reason is added by scoring.py
                # via the hkcu_overrides_hklm metadata flag — do not duplicate it here.
                reasons = []
                if server == "TreatAs":
                    reasons.append("TreatAs redirect — CLSID identity remap")
                out.append(self.make_detection(
                    location=f"HKCU\\{path}",
                    name=f"{clsid} {server}",
                    value=str(v),
                    reasons=reasons,
                    metadata={"hkcu_overrides_hklm": True,
                              "clsid": clsid, "server_type": server,
                              "recency": utils.recency_label(mtime)},
                ))
        return out
