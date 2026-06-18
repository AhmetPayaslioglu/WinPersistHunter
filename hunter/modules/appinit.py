import winreg
from typing import List
from ..base import HunterModule, Detection
from ..base import Detection as _D  # noqa
from .. import utils

LOCATIONS = [
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs",
     "T1546.010", "AppInit DLLs",
     "DLLs listed here are loaded into every user32-linked process at startup."),
    (r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs",
     "T1546.010", "AppInit DLLs (Wow64)",
     "32-bit AppInit_DLLs — injected into every Wow64 user32-linked process."),
    (r"SYSTEM\CurrentControlSet\Control\Session Manager", "AppCertDLLs",
     "T1546.009", "AppCert DLLs",
     "DLLs loaded into every process that calls CreateProcess/LoadLibrary."),
    (r"SYSTEM\CurrentControlSet\Control\Lsa", "Authentication Packages",
     "T1547.002", "LSA Authentication Package",
     "DLLs loaded by LSA at boot for user authentication."),
    (r"SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages",
     "T1547.005", "LSA Security Support Provider",
     "SSP DLLs loaded by LSA — can intercept credentials."),
    (r"SYSTEM\CurrentControlSet\Control\Lsa", "Notification Packages",
     "T1547.002", "LSA Notification Package",
     "DLLs notified by LSA on password changes — can capture cleartext."),
]

KNOWN_LSA = {
    "authentication packages": {"msv1_0"},
    "security packages": {"kerberos", "msv1_0", "schannel", "wdigest",
                          "tspkg", "pku2u", "cloudap", "negoexts"},
    "notification packages": {"scecli", "rassfm"},
}


class AppInitLSAHunter(HunterModule):
    name = "appinit_lsa"
    technique_id = "T1546"
    technique_name = "Event Triggered Execution (AppInit / LSA Packages)"
    artifact = "AppInit_DLLs / AppCertDLLs / LSA package"
    description = (
        "Registry values that name DLLs which are loaded into many processes "
        "at startup or by LSA. Non-default entries are rare and high-signal."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        for subkey, value_name, tid, tname, desc in LOCATIONS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as k:
                    try:
                        v, _ = winreg.QueryValueEx(k, value_name)
                    except OSError:
                        continue
            except OSError:
                continue

            items = []
            if isinstance(v, list):
                items = [s for s in v if s]
            elif isinstance(v, str):
                items = [s.strip() for s in v.replace("\x00", " ").split() if s.strip()]
            # Drop bogus empty/quote-only entries from REG_MULTI_SZ parsing.
            items = [it for it in items
                     if any(ch.isalnum() for ch in it.strip('"\''))]

            known = KNOWN_LSA.get(value_name.lower(), set())
            for item in items:
                low = item.lower().replace(".dll", "")
                reasons = []
                if known:
                    if low in known:
                        continue  # default — skip
                    reasons.append(f"Non-default {value_name} entry: {item}")
                else:
                    # AppInit / AppCert: any non-empty value is unusual
                    reasons.append(f"{value_name} value present (default is empty)")
                out.append(Detection(
                    technique_id=tid, technique_name=tname,
                    module=self.name, artifact=self.artifact,
                    description=desc,
                    location=f"HKLM\\{subkey}\\{value_name}",
                    name=value_name, value=item,
                    reasons=reasons,
                    metadata={"rare_technique": True},
                ))
        return out
