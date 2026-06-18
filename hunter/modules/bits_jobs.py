import json
from typing import List
from ..base import HunterModule, Detection
from .. import utils


class BITSJobsHunter(HunterModule):
    name = "bits_jobs"
    technique_id = "T1197"
    technique_name = "BITS Jobs"
    artifact = "Background Intelligent Transfer Service job"
    description = (
        "A BITS transfer queued for all users. BITS jobs survive reboots and "
        "can specify NotifyCmdLine — a command line executed when the "
        "transfer completes or errors, providing both persistence and "
        "stealthy command execution."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        script = (
            "$j = Get-BitsTransfer -AllUsers | "
            "Select-Object DisplayName,JobState,OwnerAccount,NotifyCmdLine,"
            "NotifyFlags,TransferType,CreationTime; "
            "if($j){ $j | ConvertTo-Json -Depth 3 -Compress }"
        )
        text = utils.run_powershell(script, timeout=30).strip()
        if not text:
            return out
        try:
            data = json.loads(text)
        except Exception:
            return out
        if isinstance(data, dict):
            data = [data]
        for job in data:
            notify = (job.get("NotifyCmdLine") or "").strip()
            display = job.get("DisplayName") or ""
            if not notify:
                continue  # Only NotifyCmdLine-bearing jobs are interesting.
            reasons = ["BITS job with NotifyCmdLine set — fires command on transfer event"]
            signals = utils.suspicion_signals(notify, str(display))
            if signals:
                reasons.append("Signals: " + ", ".join(signals))
            out.append(self.make_detection(
                location="BITS",
                name=str(display) or "(unnamed job)",
                value=notify,
                reasons=reasons,
                metadata={"job_state": job.get("JobState"),
                          "rare_technique": True},
            ))
        return out
