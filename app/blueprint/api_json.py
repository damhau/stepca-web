from dataclasses import asdict, is_dataclass
from datetime import datetime


def as_json(value):
    """Records as JSON-ready data, with dates in ISO 8601."""
    if is_dataclass(value) and not isinstance(value, type):
        return as_json(asdict(value))
    if isinstance(value, dict):
        return {key: as_json(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [as_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value
