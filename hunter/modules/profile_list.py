import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


class ProfileListHunter(HunterModule):
    name = "profile_list"
    technique_id = "T1556"
    technique_name = "User Profile Path Redirection"
    artifact = "ProfileImagePath registry value"
    description = (
        "Each user SID under HKLM\\...\\ProfileList carries a "
        "ProfileImagePath that points to that user's profile directory. "
        "A path outside C:\\Users redirects the user's HKCU hive and home "
        "folder — used for stealthy per-user persistence and impersonation."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY) as root:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    if not sub.startswith("S-1-5-21"):
                        continue  # only real interactive users
                    try:
                        with winreg.OpenKey(root, sub) as sk:
                            try:
                                pth, _ = winreg.QueryValueEx(sk, "ProfileImagePath")
                            except OSError:
                                continue
                            low = (pth or "").lower()
                            if low.startswith("c:\\users\\") or \
                               low.startswith("%systemdrive%\\users\\"):
                                continue
                            reasons = [f"Profile path outside C:\\Users: {pth}"]
                            if utils.is_strongly_suspicious_path(pth):
                                reasons.append("Profile path in malware-typical location")
                            out.append(self.make_detection(
                                location=f"HKLM\\{KEY}\\{sub}",
                                name=sub, value=str(pth),
                                reasons=reasons,
                                metadata={"rare_technique": True,
                                          "recency": utils.recency_label(utils.reg_key_mtime(sk))},
                            ))
                    except OSError:
                        continue
        except OSError:
            pass
        return out
