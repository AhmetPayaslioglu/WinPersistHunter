import os
import glob
import xml.etree.ElementTree as ET
from typing import List
from ..base import HunterModule, Detection
from .. import utils

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
TASKS_ROOT = r"C:\Windows\System32\Tasks"


def _is_microsoft_task(path: str, author: str, uri: str) -> bool:
    """Tasks shipped with Windows live under Tasks\Microsoft\... — skip those.
    Tasks authored by 'Microsoft' SID/account are also skipped.
    """
    rel = path.replace(TASKS_ROOT, "").lstrip("\\").lower()
    if rel.startswith("microsoft\\"):
        return True
    if uri and uri.lower().lstrip("\\").startswith("microsoft\\"):
        return True
    al = (author or "").lower()
    if "microsoft" in al or al.startswith("ms-"):
        return True
    return False


class ScheduledTasksHunter(HunterModule):
    name = "scheduled_tasks"
    technique_id = "T1053.005"
    technique_name = "Scheduled Task"
    artifact = "Windows Scheduled Task definition (.xml)"
    description = (
        "An XML task definition under C:\\Windows\\System32\\Tasks. The task "
        "is registered with the Task Scheduler service and executes its "
        "<Actions> whenever a <Triggers> condition is met (logon, boot, time)."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        if not os.path.isdir(TASKS_ROOT):
            return out
        for path in glob.glob(os.path.join(TASKS_ROOT, "**", "*"), recursive=True):
            if not os.path.isfile(path):
                continue
            try:
                tree = ET.parse(path)
            except (ET.ParseError, OSError, PermissionError):
                continue
            root = tree.getroot()
            author = self._text(root, ".//t:Author") or ""
            uri = self._text(root, ".//t:URI") or path.replace(TASKS_ROOT, "")
            if _is_microsoft_task(path, author, uri):
                continue
            hidden = (self._text(root, ".//t:Hidden") or "").lower() == "true"
            triggers = [t.tag.split("}")[-1] for t in root.findall(".//t:Triggers/*", NS)]
            mtime = utils.file_mtime(path)
            recency = utils.recency_label(mtime)
            for act in root.findall(".//t:Actions/t:Exec", NS):
                cmd = self._text(act, "t:Command") or ""
                args = self._text(act, "t:Arguments") or ""
                full = (cmd + " " + args).strip()
                signals = utils.suspicion_signals(full, uri)
                reasons = []
                rare = False
                if hidden:
                    reasons.append("Task is marked Hidden")
                    rare = True
                if signals:
                    reasons.append("Action exhibits: " + ", ".join(signals))
                if recency == "very_recent":
                    reasons.append("Task file modified in the last 7 days")
                if not reasons:
                    continue
                out.append(self.make_detection(
                    location=path,
                    name=uri,
                    value=full,
                    reasons=reasons,
                    metadata={
                        "author": author,
                        "hidden": hidden,
                        "triggers": triggers,
                        "recency": recency,
                        "rare_technique": rare,
                    },
                ))
        return out

    @staticmethod
    def _text(elem, xpath):
        node = elem.find(xpath, NS)
        return node.text if node is not None else None
