from dataclasses import dataclass
from datetime import datetime

ALLOWED_ZONES = {"user", "server", "database", "management", "dmz", "backup", "lab"}


def parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return ts


@dataclass(frozen=True)
class Flow:
    flow_id: str
    timestamp: datetime
    src_asset: str
    dst_asset: str
    src_zone: str
    dst_zone: str
    protocol: str
    dst_port: int
    bytes_out: int
    user: str = ""
    approved: bool = False

    @classmethod
    def from_dict(cls, row: dict) -> "Flow":
        required = ("flow_id", "timestamp", "src_asset", "dst_asset", "src_zone", "dst_zone", "protocol", "dst_port", "bytes_out")
        missing = [k for k in required if k not in row]
        if missing:
            raise ValueError("missing required fields: " + ", ".join(missing))
        sz, dz = str(row["src_zone"]).lower(), str(row["dst_zone"]).lower()
        if sz not in ALLOWED_ZONES or dz not in ALLOWED_ZONES:
            raise ValueError("unsupported zone")
        port, size = int(row["dst_port"]), int(row["bytes_out"])
        if not 1 <= port <= 65535 or size < 0:
            raise ValueError("invalid port or byte count")
        return cls(str(row["flow_id"]), parse_ts(str(row["timestamp"])), str(row["src_asset"]), str(row["dst_asset"]), sz, dz, str(row["protocol"]).lower(), port, size, str(row.get("user", "")), bool(row.get("approved", False)))


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    score: int
    entity: str
    evidence_ids: tuple[str, ...]
    attack: tuple[str, ...]
    rationale: str
    remediation: str
    validation: str
