from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, field_validator, model_validator, ValidationError

class Event(BaseModel):
    type: str
    location: str
    deviceId: str
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    state: Optional[str] = None  # for door: "open" or "close"
    db: Optional[float] = None  # for noise: decibels

    class Config:
        extra = "allow"  # allow extra fields (future-proofing)

class SampleInput(BaseModel):
    events: List[Event] = Field(default_factory=list)
    systemMode: str = "home"
    time: str

    @field_validator("time", mode="before")
    @classmethod
    def validate_time(cls, v: str) -> str:
        if not v:
            raise ValueError("time field is required")
        try:
            # Parse and normalize to UTC Zulu
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"Invalid ISO 8601 time format: {v}") from e

    @model_validator(mode="before")
    @classmethod
    def check_required_fields(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(values, dict):
            required = {"events", "systemMode", "time"}
            missing = required - set(values.keys())
            if missing:
                raise ValueError(f"Missing required fields: {missing}")
        return values

    class Config:
        extra = "forbid"  # reject unknown top-level fields
