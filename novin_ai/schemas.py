from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Any, Dict

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict


class Event(BaseModel):
    """A single sensor/event record. Extra fields are allowed for forward-compatibility."""
    type: str
    location: str
    deviceId: str
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    state: Optional[str] = None  # for door: "open" or "close"
    db: Optional[float] = None  # for noise: decibels

    model_config = ConfigDict(extra="allow")  # allow extra fields


class SampleInput(BaseModel):
    """Top-level input expected by predict(). Strict: extra top-level fields are rejected."""
    events: List[Event] = Field(default_factory=list)
    systemMode: str = "home"
    time: str

    model_config = ConfigDict(extra="forbid")  # reject unknown top-level fields

    @field_validator("time", mode="before")
    def _validate_time(cls, v: Any) -> str:
        """
        Accept either an ISO8601 string or a datetime; normalize to Z-suffixed ISO string.
        Runs in 'before' mode to normalize raw inputs.
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            raise ValueError("time field is required")

        if isinstance(v, datetime):
            dt = v
        else:
            # coerce to string and attempt to parse ISO formats, accepting 'Z'
            try:
                dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            except Exception as e:
                raise ValueError(f"Invalid ISO 8601 time format: {v}") from e

        # normalize to Z style
        return dt.isoformat().replace("+00:00", "Z")

    @model_validator(mode="before")
    def _check_required_fields(cls, values: Any) -> Any:
        """
        Ensure required top-level keys are present in the raw input mapping.
        model_validator(mode='before') receives the raw dict-like input before parsing.
        """
        if isinstance(values, dict):
            required = {"events", "systemMode", "time"}
            missing = required - set(values.keys())
            if missing:
                raise ValueError(f"Missing required fields: {missing}")
        return values
