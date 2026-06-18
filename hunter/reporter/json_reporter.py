import json
from typing import List
from ..base import Detection


def write_json(path: str, detections: List[Detection], meta: dict) -> None:
    payload = {
        "meta": meta,
        "detections": [d.to_dict() for d in detections],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
