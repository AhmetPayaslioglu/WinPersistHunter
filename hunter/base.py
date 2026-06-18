from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List


@dataclass
class Detection:
    technique_id: str
    technique_name: str
    module: str
    artifact: str          # short label, e.g. "Registry Run key value"
    description: str       # one-line explanation of WHAT this artifact does
    location: str
    name: str
    value: str
    score: int = 0
    severity: str = "info"
    reasons: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class HunterModule:
    name: str = "base"
    technique_id: str = ""
    technique_name: str = ""
    artifact: str = ""
    description: str = ""

    def run(self) -> List[Detection]:
        raise NotImplementedError

    def make_detection(self, location: str, name: str, value: str,
                       artifact: str = "", description: str = "", **kw) -> Detection:
        return Detection(
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            module=self.name,
            artifact=artifact or self.artifact,
            description=description or self.description,
            location=location,
            name=name,
            value=value,
            **kw,
        )
