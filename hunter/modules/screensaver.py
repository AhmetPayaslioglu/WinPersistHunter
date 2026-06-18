import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

DEFAULT_SCREENSAVERS = {
    "scrnsave.scr", "logon.scr", "bubbles.scr", "mystify.scr",
    "ribbons.scr", "ssText3d.scr", "PhotoScreensaver.scr",
}


class ScreensaverHunter(HunterModule):
    name = "screensaver"
    technique_id = "T1546.002"
    technique_name = "Event Triggered Execution: Screensaver"
    artifact = "User screensaver setting"
    description = (
        "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE — the executable launched "
        "as a screensaver after the configured idle timeout. Any .scr is a "
        "real PE, so this is a viable persistence + execution vector."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as k:
                try:
                    scr, _ = winreg.QueryValueEx(k, "SCRNSAVE.EXE")
                except OSError:
                    return out
                if not scr:
                    return out
                base = scr.lower().rsplit("\\", 1)[-1]
                # Bare default screensaver in C:\Windows is uninteresting.
                if base in DEFAULT_SCREENSAVERS and \
                   utils.in_trusted_root(scr):
                    return out
                reasons = []
                if not utils.in_trusted_root(scr):
                    reasons.append(f"Screensaver path outside Windows/Program Files: {scr}")
                if utils.is_strongly_suspicious_path(scr):
                    reasons.append("Screensaver in malware-typical location")
                if not reasons:
                    return out
                out.append(self.make_detection(
                    location=r"HKCU\Control Panel\Desktop",
                    name="SCRNSAVE.EXE", value=str(scr),
                    reasons=reasons,
                    metadata={"rare_technique": True},
                ))
        except OSError:
            pass
        return out
