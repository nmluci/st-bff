from __future__ import annotations

from typing import Any, List, Dict
from datetime import datetime
from dataclasses import dataclass


@dataclass
class SecuredData:
    payload: str
    iv: str

    def toJSON(self):
        return {
            "payload": self.payload,
            "iv": self.payload
        }


@dataclass
class MetaResponse:
    data: Any | List[Any] = None
    error: Dict[str, Any] | None = None

    def toJSON(self):
        return {
            "data": self.data,
            "error": self.error
        }
