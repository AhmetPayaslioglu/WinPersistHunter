from collections import defaultdict
from typing import List
from .base import Detection
from . import utils


def annotate_clusters(detections: List[Detection]) -> List[Detection]:
    """Find the same executable referenced across multiple persistence modules.

    Sets metadata['cluster_size'] and metadata['cluster_modules'] on each
    detection that participates in a multi-module cluster. Runs purely in
    memory on a single scan's output — no persistent state.
    """
    buckets = defaultdict(list)
    for d in detections:
        exe = utils.extract_executable(d.value) or ""
        exe = exe.strip().strip('"').lower()
        if not exe or len(exe) < 4:
            continue
        buckets[exe].append(d)

    for exe, group in buckets.items():
        modules = {d.module for d in group}
        if len(modules) < 2:
            continue
        for d in group:
            d.metadata["cluster_size"] = len(modules)
            d.metadata["cluster_modules"] = sorted(modules)
            d.reasons.append(
                f"Artifact also referenced by: {', '.join(sorted(modules - {d.module}))}"
            )
    return detections
