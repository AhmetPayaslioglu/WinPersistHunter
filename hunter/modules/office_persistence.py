import os
import glob
import winreg
from typing import List
from ..base import HunterModule, Detection
from .. import utils

OFFICE_APPS = ("Word", "Excel", "PowerPoint", "Outlook", "Access", "Visio")

OFFICE_INSTALL_ROOTS = [
    "c:\\program files\\microsoft office\\",
    "c:\\program files (x86)\\microsoft office\\",
    "c:\\program files\\common files\\microsoft shared\\",
    "c:\\program files (x86)\\common files\\microsoft shared\\",
]

# Add-in ProgID prefixes shipped by Microsoft (Teams, Skype/Lync, OneNote,
# SharePoint, OneDrive, Power*, Outlook native). Skipping these eliminates
# the bulk of clean-system false positives.
MICROSOFT_ADDIN_PREFIXES = (
    "microsoft.", "teamsaddin.", "ucaddin.", "onenote.", "sharepoint.",
    "onedrive.", "powerpivot", "powerquery", "powerview", "lync",
    "skypeformsui", "outlookchange", "officefilevalidation",
    "ms.outlook",
)


def _is_office_default_path(p: str) -> bool:
    if not p:
        return False
    low = p.lower()
    return any(low.startswith(r) for r in OFFICE_INSTALL_ROOTS)


class OfficePersistenceHunter(HunterModule):
    name = "office_persistence"
    technique_id = "T1137"
    technique_name = "Office Application Startup"
    artifact = "Office add-in / startup template"
    description = (
        "Microsoft Office loads add-ins listed under HKCU/HKLM "
        "Software\\Microsoft\\Office\\<app>\\Addins on startup; Word/Excel "
        "also load every document under their STARTUP / XLSTART / AddIns "
        "folders, plus Normal.dotm and Outlook's VbaProject.OTM."
    )

    def run(self) -> List[Detection]:
        out = []
        out.extend(self._addins())
        out.extend(self._templates())
        out.extend(self._outlook())
        return out

    def _addins(self) -> List[Detection]:
        out = []
        for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for app in OFFICE_APPS:
                for office_root in (r"Software\Microsoft\Office",
                                    r"Software\Wow6432Node\Microsoft\Office"):
                    path = rf"{office_root}\{app}\Addins"
                    try:
                        with winreg.OpenKey(hive, path) as k:
                            i = 0
                            while True:
                                try:
                                    sub = winreg.EnumKey(k, i)
                                    i += 1
                                except OSError:
                                    break
                                try:
                                    with winreg.OpenKey(k, sub) as ak:
                                        lb = self._q(ak, "LoadBehavior")
                                        friendly = self._q(ak, "FriendlyName") or sub
                                        manifest = self._q(ak, "Manifest") or ""
                                        if lb not in (3, 9):
                                            continue
                                        if _is_office_default_path(manifest):
                                            continue
                                        sub_low = sub.lower()
                                        if any(sub_low.startswith(p)
                                               for p in MICROSOFT_ADDIN_PREFIXES):
                                            continue
                                        mtime = utils.reg_key_mtime(ak)
                                        out.append(self.make_detection(
                                            location=f"{label}\\{path}\\{sub}",
                                            name=str(friendly),
                                            value=str(manifest or sub),
                                            reasons=[f"{app} add-in auto-loads (LoadBehavior={lb})"],
                                            metadata={"app": app,
                                                      "recency": utils.recency_label(mtime)},
                                        ))
                                except OSError:
                                    continue
                    except OSError:
                        continue
        return out

    def _templates(self) -> List[Detection]:
        out = []
        # Only emit when the user has macro-bearing content. Empty folders skipped.
        candidates = [
            (r"%APPDATA%\Microsoft\Templates\Normal.dotm", "Word global template"),
            (r"%APPDATA%\Microsoft\Templates\NormalEmail.dotm", "Outlook global template"),
            (r"%APPDATA%\Microsoft\Excel\XLSTART", "Excel XLSTART folder"),
            (r"%APPDATA%\Microsoft\Word\STARTUP", "Word STARTUP folder"),
            (r"%APPDATA%\Microsoft\AddIns", "Office AddIns folder"),
        ]
        for c, label in candidates:
            p = os.path.expandvars(c)
            if not os.path.exists(p):
                continue
            if os.path.isdir(p):
                for entry in os.listdir(p):
                    full = os.path.join(p, entry)
                    if entry.lower().endswith((".xlam", ".xla", ".dotm", ".ppam", ".wll", ".xll")):
                        mtime = utils.recency_label(utils.file_mtime(full))
                        if mtime != "very_recent":
                            continue
                        out.append(self.make_detection(
                            location=p, name=entry, value=full,
                            reasons=[f"Recently added file in {label}"],
                            metadata={"recency": mtime},
                        ))
            else:
                rec = utils.recency_label(utils.file_mtime(p))
                if rec != "very_recent":
                    continue
                out.append(self.make_detection(
                    location=os.path.dirname(p), name=os.path.basename(p), value=p,
                    reasons=[f"{label} modified in the last 7 days"],
                    metadata={"recency": rec, "rare_technique": True},
                ))
        return out

    def _outlook(self) -> List[Detection]:
        out = []
        otm = os.path.expandvars(r"%APPDATA%\Microsoft\Outlook\VbaProject.OTM")
        if os.path.isfile(otm):
            out.append(self.make_detection(
                location=os.path.dirname(otm), name="VbaProject.OTM", value=otm,
                reasons=["Outlook VBA project present — T1137.001 vector"],
                metadata={"rare_technique": True,
                          "recency": utils.recency_label(utils.file_mtime(otm))},
            ))
        forms = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\FORMS")
        if os.path.isdir(forms):
            for f in glob.glob(os.path.join(forms, "**", "*.fdm"), recursive=True):
                out.append(self.make_detection(
                    location=forms, name=os.path.basename(f), value=f,
                    reasons=["Outlook custom form (T1137.003)"],
                    metadata={"rare_technique": True},
                ))
        return out

    @staticmethod
    def _q(k, name):
        try:
            v, _ = winreg.QueryValueEx(k, name)
            return v
        except OSError:
            return None
