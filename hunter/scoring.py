from .base import Detection
from . import utils

SEVERITY_THRESHOLDS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (10, "low"),
    (0, "info"),
]


def score_detection(d: Detection) -> Detection:
    """Score a detection based on the signals already attached to it plus
    a few command/path heuristics. We try hard NOT to add noisy reasons here
    — modules are expected to gate emission so that whatever reaches scoring
    is already at least mildly interesting.
    """
    score = 0
    reasons = list(d.reasons)
    command = d.value or ""
    exe = utils.extract_executable(command) or ""

    # Strong vs mild path signals
    if utils.is_strongly_suspicious_path(exe):
        score += 25
        reasons.append(f"Path in malware-typical location: {exe}")
    elif utils.is_mildly_suspicious_path(exe):
        score += 8
        reasons.append(f"Path under AppData/ProgramData: {exe}")

    lol = utils.is_lolbin(command)
    if lol:
        score += 20
        reasons.append(f"Uses LOLBin: {lol}")

    obf = utils.has_powershell_obfuscation(command)
    if obf:
        score += 25
        reasons.append(f"PowerShell obfuscation tokens: {', '.join(obf[:3])}")

    if command and utils.shannon_entropy(command) > 5.0 and len(command) > 100:
        score += 15
        reasons.append("High command entropy on long command line")

    if utils.has_rtlo(d.name) or utils.has_rtlo(d.value):
        score += 45
        reasons.append("RTLO (right-to-left override) character — filename masking")

    if utils.has_double_extension(d.name) or utils.has_double_extension(exe):
        score += 25
        reasons.append("Double extension (e.g. invoice.pdf.exe)")

    if utils.is_scripting_ext(exe):
        score += 10
        reasons.append(f"Scripting extension: {exe}")

    md = d.metadata
    if md.get("hkcu_overrides_hklm"):
        score += 35
        reasons.append("HKCU CLSID shadows HKLM (COM hijack pattern)")
    if md.get("byovd"):
        score += 65
        reasons.append("Driver matches loldrivers.io BYOVD list")
    if md.get("rare_technique"):
        score += 15
        reasons.append("Rarely used technique (low false-positive rate)")
    if md.get("recency") == "very_recent":
        score += 15
        reasons.append("Artifact created/modified in the last 7 days")
    elif md.get("recency") == "recent":
        score += 5
        reasons.append("Artifact created/modified in the last 30 days")
    if md.get("cluster_size", 0) >= 2:
        score += 25
        reasons.append(
            f"Same artifact also referenced by: "
            f"{', '.join(m for m in md.get('cluster_modules', []) if m != d.module)}"
        )

    d.score = min(score, 100)
    d.reasons = reasons
    d.severity = severity_for(d.score)
    return d


def severity_for(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"
