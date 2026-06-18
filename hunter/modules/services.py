import os
import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


class ServicesHunter(HunterModule):
    name = "services"
    technique_id = "T1543.003"
    technique_name = "Create or Modify System Process: Windows Service"
    artifact = "Windows Service registry entry"
    description = (
        "A subkey of HKLM\\SYSTEM\\CurrentControlSet\\Services. ImagePath "
        "(or ServiceDll under Parameters) is launched by the Service Control "
        "Manager at boot/logon according to the Start value."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY)
        except OSError:
            return out
        with root:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(root, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root, svc) as sk:
                        image_path = self._val(sk, "ImagePath")
                        service_dll = self._val_in_subkey(sk, "Parameters", "ServiceDll")
                        start = self._val(sk, "Start")
                        stype = self._val(sk, "Type")
                        if not image_path and not service_dll:
                            continue
                        target = service_dll or image_path
                        if not target:
                            continue

                        reasons = []
                        # Unquoted path with spaces (classic privesc + persistence)
                        t = str(target).strip()
                        if not t.startswith('"') and " " in t and ".exe" in t.lower():
                            head = t.lower().split(".exe", 1)[0]
                            if " " in head and not utils.in_trusted_root(t):
                                reasons.append("Unquoted ImagePath containing spaces")

                        exe = utils.extract_executable(t) or ""

                        # ServiceDll context is semantically distinct from the
                        # generic "path under AppData" signal scoring adds, so we
                        # keep the explicit ServiceDll reason. The generic exe
                        # path / LOLBin reasons are added by scoring.py and are
                        # not duplicated here.
                        if service_dll:
                            sd = str(service_dll)
                            if utils.is_strongly_suspicious_path(sd) or \
                               utils.is_mildly_suspicious_path(sd):
                                reasons.append(
                                    f"ServiceDll in user-writable location: {sd}")

                        # We still need to TRIGGER scoring on the exe path / LOLBin
                        # signals — emit a detection if any of the gating checks fire.
                        triggered = bool(reasons) \
                            or utils.is_strongly_suspicious_path(exe) \
                            or (utils.is_mildly_suspicious_path(exe) and not utils.in_trusted_root(exe)) \
                            or (utils.is_lolbin(t) and not utils.in_trusted_root(exe))

                        if not triggered:
                            continue

                        recency = utils.recency_label(utils.reg_key_mtime(sk))

                        out.append(self.make_detection(
                            location=f"HKLM\\{SERVICES_KEY}\\{svc}",
                            name=svc,
                            value=str(target),
                            reasons=reasons,
                            metadata={
                                "image_path": image_path,
                                "service_dll": service_dll,
                                "start": start,
                                "type": stype,
                                "recency": recency,
                            },
                        ))
                except OSError:
                    continue
        return out

    @staticmethod
    def _val(key, name):
        try:
            v, _ = winreg.QueryValueEx(key, name)
            return v
        except OSError:
            return None

    @staticmethod
    def _val_in_subkey(key, subkey, name):
        try:
            with winreg.OpenKey(key, subkey) as sk:
                v, _ = winreg.QueryValueEx(sk, name)
                return v
        except OSError:
            return None
