"""Data schemas and validation for Novin AI."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict


class EventType(str, Enum):
    """Supported event types."""
    MOTION = "motion"
    CONTACT = "contact"
    GLASS_BREAK = "glass_break"
    SMOKE = "smoke"
    WATER_LEAK = "water_leak"
    NOISE = "noise"
    FACE = "face"
    PACKAGE = "package"
    TEMPERATURE = "temperature"


class SystemMode(str, Enum):
    """Supported system modes."""
    HOME = "home"
    AWAY = "away"
    NIGHT = "night"
    VACATION = "vacation"


class ThreatLevel(str, Enum):
    """Supported threat levels."""
    IGNORE = "ignore"
    STANDARD = "standard"
    ELEVATED = "elevated"
    CRITICAL = "critical"


class Event(BaseModel):
    """A single security event from a sensor or system."""
    type: str = Field(..., description="Type of the event (e.g., motion, contact)")
    deviceId: str = Field(..., description="Unique identifier for the device")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    
    # Optional fields with descriptions
    location: Optional[str] = Field(None, description="Location/zone of the event")
    confidence: Optional[float] = Field(
        None, 
        ge=0.0, 
        le=1.0, 
        description="Confidence score of the event detection (0.0 to 1.0)"
    )
    value: Optional[Union[bool, int, float, str]] = Field(
        None, 
        description="Event-specific value (e.g., temperature, noise level)"
    )
    
    # Allow arbitrary fields but type them as Any
    model_config = ConfigDict(extra="allow")
    
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate and normalize timestamp to ISO 8601 format."""
        try:
            # Try parsing to validate
            dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
            return dt.isoformat()
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid timestamp format: {v}. Expected ISO 8601 format") from e


class SecuritySample(BaseModel):
    """A single sample for security classification."""
    events: List[Event] = Field(
        default_factory=list,
        description="List of security events in this sample"
    )
    systemMode: SystemMode = Field(
        ...,
        description="Current system mode (home, away, night, vacation)"
    )
    time: str = Field(
        ...,
        description="ISO 8601 timestamp of the sample"
    )
    
    # For labeled data (training)
    threatLevel: Optional[ThreatLevel] = Field(
        None,
        description="Ground truth threat level (for training data)"
    )
    
    @property
    def timestamp(self) -> datetime:
        """Return the sample time as a datetime object."""
        return datetime.fromisoformat(self.time.replace('Z', '+00:00'))


class PredictionResult(BaseModel):
    """Result of a prediction."""
    threatLevel: ThreatLevel = Field(..., description="Predicted threat level")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score of the prediction"
    )
    explanation: str = Field(..., description="Human-readable explanation")
    dev_trace: List[str] = Field(
        default_factory=list,
        description="Developer trace for debugging"
    )
    user_trace: List[str] = Field(
        default_factory=list,
        description="User-visible trace of reasoning"
    )
    
    model_config = ConfigDict(use_enum_values=True)


class OntologyConfig(BaseModel):
    """Device ontology configuration."""
    tags_by_device_id: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Mapping of device IDs to their tags"
    )
    
    def get_tags(self, device_id: str) -> List[str]:
        """Get tags for a device ID."""
        return self.tags_by_device_id.get(device_id, [])
    
    @classmethod
    def from_json(cls, json_str: str) -> 'OntologyConfig':
        """Create from JSON string."""
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("JSON must be an object with device_id -> tags mapping")
        return cls(tags_by_device_id=data)
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.tags_by_device_id, indent=2)


# Re-export enums for convenience
__all__ = [
    'Event',
    'SecuritySample',
    'PredictionResult',
    'OntologyConfig',
    'EventType',
    'SystemMode',
    'ThreatLevel',
]
