import os
import json
import hashlib
import winreg
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Set, Optional
from ..base import HunterModule, Detection
from .. import utils

KEY = r"SYSTEM\CurrentControlSet\Services"
LOLDRIVERS_FEED = "https://www.loldrivers.io/api/drivers.json"
CACHE_FILE = Path(os.path.expandvars(
    r"%LOCALAPPDATA%\WinPersistHunter\loldrivers.json"))


def _hash_file(path: str, algo: str = "sha256") -> Optional[str]:
    try:
        p = Path(utils.expand_env(path))
        if not p.is_file():
            return None
        h = hashlib.new(algo)
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except Exception:
        return None


def _load_loldrivers(offline: bool) -> Set[str]:
    hashes: Set[str] = set()
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            for entry in data:
                for s in entry.get("KnownVulnerableSamples", []) or []:
                    for k in ("SHA256", "SHA1", "MD5"):
                        v = s.get(k)
                        if v:
                            hashes.add(v.lower())
        except Exception:
            pass
    if offline or hashes:
        return hashes
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(LOLDRIVERS_FEED, timeout=10) as r:
            payload = r.read()
        CACHE_FILE.write_bytes(payload)
        data = json.loads(payload.decode("utf-8"))
        for entry in data:
            for s in entry.get("KnownVulnerableSamples", []) or []:
                for k in ("SHA256", "SHA1", "MD5"):
                    v = s.get(k)
                    if v:
                        hashes.add(v.lower())
    except (urllib.error.URLError, Exception):
        pass
    return hashes


def _resolve_image_path(image: str) -> str:
    p = image
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        p = "C:\\Windows\\" + p[12:]
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        p = "C:\\Windows\\" + p
    elif low.startswith("\\??\\"):
        p = p[4:]
    elif p.startswith("\\\\"):
        pass
    elif not (len(p) > 2 and p[1] == ":"):
        p = os.path.join("C:\\Windows\\System32\\drivers", p)
    return p


class DriversHunter(HunterModule):
    name = "drivers"
    technique_id = "T1543.003"
    technique_name = "Create or Modify System Process: Driver (BYOVD)"
    artifact = "Kernel-mode driver service entry"
    description = (
        "A service registry entry whose Type is 1 (kernel driver) or 2 "
        "(file system driver). At Start <= 2 the driver is loaded by the "
        "kernel during boot. Adversaries register vulnerable signed drivers "
        "to gain kernel execution (BYOVD)."
    )

    def __init__(self, offline_feed: bool = False, hash_all: bool = False):
        self.offline_feed = offline_feed
        self.hash_all = hash_all

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        bad = _load_loldrivers(self.offline_feed)
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY)
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
                        stype = self._q(sk, "Type")
                        if stype not in (1, 2):
                            continue
                        image = self._q(sk, "ImagePath")
                        if not image:
                            continue
                        resolved = _resolve_image_path(str(image))
                        mtime = utils.reg_key_mtime(sk)
                        recency = utils.recency_label(mtime)
                        start = self._q(sk, "Start")
                        reasons = []
                        meta = {"start": start, "type": stype,
                                "recency": recency}
                        is_trusted = utils.in_trusted_root(resolved)

                        # Hash if we have a BYOVD list, or hash_all requested.
                        h = None
                        byovd = False
                        if bad or self.hash_all:
                            h = _hash_file(resolved)
                            if h:
                                meta["sha256"] = h
                                if h in bad:
                                    # scoring.py emits the BYOVD reason from this flag.
                                    meta["byovd"] = True
                                    byovd = True

                        if not is_trusted:
                            reasons.append(f"Driver ImagePath outside Windows/Program Files: {resolved}")

                        # recency / BYOVD reasons added by scoring.py via the
                        # metadata flags. We still gate emission on them here.
                        trigger_recent = recency == "very_recent" and not is_trusted

                        if not reasons and not trigger_recent and not byovd:
                            continue  # Routine signed Microsoft driver — skip.

                        out.append(self.make_detection(
                            location=f"HKLM\\{KEY}\\{svc}",
                            name=svc, value=str(image),
                            reasons=reasons, metadata=meta,
                        ))
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
