import json
from typing import List
from ..base import HunterModule, Detection
from .. import utils


class AppxPackagesHunter(HunterModule):
    name = "appx_packages"
    technique_id = "T1546"
    technique_name = "Sideloaded / Developer AppX Package"
    artifact = "AppX/MSIX package registration"
    description = (
        "An installed AppX/MSIX package whose SignatureKind is Developer or "
        "None — i.e. side-loaded, not from the Microsoft Store. Such packages "
        "can register background tasks and protocol handlers that act as "
        "persistence."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        script = (
            "Get-AppxPackage -AllUsers | "
            "Where-Object { $_.SignatureKind -eq 'Developer' -or $_.SignatureKind -eq 'None' } | "
            "Select-Object Name,Publisher,InstallLocation,SignatureKind,PackageFullName | "
            "ConvertTo-Json -Depth 3 -Compress"
        )
        text = utils.run_powershell(script, timeout=45).strip()
        if not text:
            return out
        try:
            data = json.loads(text)
        except Exception:
            return out
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            kind = pkg.get("SignatureKind", "")
            loc = pkg.get("InstallLocation", "") or ""
            # WindowsApps under Program Files = store install path; skip those.
            if "\\program files\\windowsapps" in loc.lower():
                continue
            reasons = [f"AppX package with SignatureKind={kind}"]
            if utils.is_strongly_suspicious_path(loc) or \
               utils.is_mildly_suspicious_path(loc):
                reasons.append(f"InstallLocation in user-writable path: {loc}")
            out.append(self.make_detection(
                location=loc or "(unknown)",
                name=str(pkg.get("Name") or pkg.get("PackageFullName") or "(unnamed)"),
                value=str(pkg.get("Publisher") or ""),
                reasons=reasons,
                metadata={"rare_technique": True, "signature_kind": kind},
            ))
        return out
