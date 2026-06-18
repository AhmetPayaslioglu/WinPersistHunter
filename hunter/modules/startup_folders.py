import os
import struct
from pathlib import Path
from typing import List, Optional
from ..base import HunterModule, Detection
from .. import utils

USER_STARTUP = os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
ALL_USERS_STARTUP = os.path.expandvars(
    r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")


def parse_lnk_target(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 0x4C or data[0:4] != b"\x4c\x00\x00\x00":
            return None
        flags = struct.unpack("<I", data[0x14:0x18])[0]
        offset = 0x4C
        if flags & 0x1:
            idlist_size = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2 + idlist_size
        if not (flags & 0x2):
            return None
        li_size = struct.unpack("<I", data[offset:offset+4])[0]
        li_data = data[offset:offset+li_size]
        if len(li_data) < 16:
            return None
        local_base_path_offset = struct.unpack("<I", li_data[16:20])[0]
        if local_base_path_offset == 0:
            return None
        raw = li_data[local_base_path_offset:]
        end = raw.find(b"\x00")
        return raw[:end].decode("latin-1", errors="replace") if end != -1 else None
    except Exception:
        return None


class StartupFoldersHunter(HunterModule):
    name = "startup_folders"
    technique_id = "T1547.001"
    technique_name = "Registry Run Keys / Startup Folder"
    artifact = "Startup folder entry (.lnk / executable)"
    description = (
        "Files placed under the per-user or all-users Startup folder "
        "(%APPDATA%\\...\\Startup, %ProgramData%\\...\\Startup) are launched "
        "for the user on logon by Explorer."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        for folder in (USER_STARTUP, ALL_USERS_STARTUP):
            if not os.path.isdir(folder):
                continue
            for entry in Path(folder).iterdir():
                if entry.name.lower() == "desktop.ini":
                    continue
                target = None
                if entry.suffix.lower() == ".lnk":
                    target = parse_lnk_target(str(entry))
                value = target or str(entry)
                reasons = []
                signals = utils.suspicion_signals(value, entry.name)
                if signals:
                    reasons.append("Suspicion signals: " + ", ".join(signals))
                if utils.is_scripting_ext(str(entry)):
                    reasons.append(f"Startup entry is a script: {entry.suffix}")
                if not reasons:
                    continue
                out.append(self.make_detection(
                    location=folder,
                    name=entry.name,
                    value=value,
                    reasons=reasons,
                    metadata={"lnk_target": target,
                              "recency": utils.recency_label(utils.file_mtime(str(entry)))},
                ))
        return out
