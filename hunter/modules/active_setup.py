import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

KEYS = [
    r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
]


class ActiveSetupHunter(HunterModule):
    name = "active_setup"
    technique_id = "T1547.014"
    technique_name = "Boot or Logon Autostart Execution: Active Setup"
    artifact = "Active Setup Installed Component"
    description = (
        "Subkey of HKLM\\...\\Active Setup\\Installed Components with a "
        "StubPath value. The system runs StubPath once per user, the first "
        "time that user logs on, if their HKCU 'Version' differs from HKLM's."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        for root_key in KEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_key) as root:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(root, i)
                            i += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(root, sub) as k:
                                stub = self._q(k, "StubPath")
                                name = self._q(k, "") or sub
                                if not stub:
                                    continue
                                stub_s = str(stub).strip()
                                # Many Microsoft components store opcode-style
                                # StubPaths ("U", "/UserInstall"). Only emit
                                # when the StubPath looks like a real command
                                # invocation (contains an executable extension).
                                sl = stub_s.lower()
                                if not any(ext in sl for ext in
                                           (".exe", ".dll", ".bat", ".cmd",
                                            ".ps1", ".vbs", ".js", ".scr")):
                                    continue
                                exe = utils.extract_executable(stub_s) or ""
                                if utils.in_trusted_root(exe):
                                    continue
                                reasons = ["Non-Windows Active Setup StubPath (runs once per user)"]
                                signals = utils.suspicion_signals(str(stub), str(name))
                                if signals:
                                    reasons.append("Signals: " + ", ".join(signals))
                                out.append(self.make_detection(
                                    location=f"HKLM\\{root_key}\\{sub}",
                                    name=str(name) or sub,
                                    value=str(stub),
                                    reasons=reasons,
                                    metadata={"component_guid": sub,
                                              "recency": utils.recency_label(utils.reg_key_mtime(k))},
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
