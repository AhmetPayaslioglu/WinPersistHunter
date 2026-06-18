import os
import json
import glob
from typing import List
from ..base import HunterModule, Detection

CHROMIUM_PROFILES = [
    r"%LOCALAPPDATA%\Google\Chrome\User Data",
    r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
    r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
]

TRUSTED_UPDATE_URLS = (
    "clients2.google.com",
    "edge.microsoft.com",
    "extensionupdater.brave.com",
)

RISKY_PERMS = {
    "<all_urls>", "tabs", "webRequest", "webRequestBlocking",
    "cookies", "debugger", "proxy", "nativeMessaging",
    "downloads", "history", "management",
}


class BrowserExtensionsHunter(HunterModule):
    name = "browser_extensions"
    technique_id = "T1176"
    technique_name = "Browser Extensions"
    artifact = "Chromium browser extension"
    description = (
        "An extension recorded in a Chromium-family profile (Chrome / Edge / "
        "Brave). Stored under extensions.settings in the profile's Preferences "
        "JSON. Extensions persist across sessions and can intercept browsing."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        for base in CHROMIUM_PROFILES:
            base_p = os.path.expandvars(base)
            if not os.path.isdir(base_p):
                continue
            for prefs in glob.glob(os.path.join(base_p, "*", "Preferences")):
                try:
                    with open(prefs, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    continue
                exts = ((data.get("extensions") or {}).get("settings") or {})
                for ext_id, info in exts.items():
                    if not isinstance(info, dict):
                        continue
                    # Skip component extensions Chrome itself bundles
                    if info.get("location") in (5, 10):  # COMPONENT, EXTERNAL_COMPONENT
                        continue
                    manifest = info.get("manifest", {}) or {}
                    name = manifest.get("name") or info.get("path") or ext_id
                    path = info.get("path", "")
                    update_url = manifest.get("update_url") or info.get("update_url", "")
                    from_webstore = info.get("from_webstore", False)
                    install_time = info.get("install_time")
                    reasons = []
                    if not from_webstore and not info.get("was_installed_by_default"):
                        if update_url and not any(t in update_url for t in TRUSTED_UPDATE_URLS):
                            reasons.append(f"Side-loaded, update URL: {update_url}")
                        elif not update_url:
                            reasons.append("Side-loaded extension with no update URL")
                    perms = manifest.get("permissions") or []
                    risky = [p for p in perms if isinstance(p, str) and p in RISKY_PERMS]
                    if risky and reasons:
                        reasons.append(f"High-risk permissions: {', '.join(risky[:4])}")
                    if not reasons:
                        continue
                    out.append(self.make_detection(
                        location=prefs,
                        name=str(name),
                        value=str(path or update_url or "(no path)"),
                        reasons=reasons,
                        metadata={"browser_profile": prefs, "ext_id": ext_id,
                                  "install_time": install_time,
                                  "rare_technique": False},
                    ))
        return out
