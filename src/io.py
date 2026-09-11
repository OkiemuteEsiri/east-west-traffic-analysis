import json
from pathlib import Path
from .models import Flow


def load_flows(path: str) -> list[Flow]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    flows = [Flow.from_dict(x) for x in raw]
    ids = [f.flow_id for f in flows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate flow_id")
    return flows
