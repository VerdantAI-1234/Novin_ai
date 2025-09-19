"""
Event Schema Module

Defines the security event data structures and validation schemas
for the security reasoner system.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum
import json


class EventType(Enum):
    """Security event types"""
    INTRUSION = "intrusion"
    MALWARE = "malware"
    PHISHING = "phishing"
    ANOMALY = "anomaly"
    BREACH = "breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    COMPLIANCE_VIOLATION = "compliance_violation"


class SeverityLevel(Enum):
    """Event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """
    Core security event data structure.
    
    Represents a single security event with all relevant metadata
    and contextual information for threat analysis.
    """
    event_id: str
    timestamp: datetime
    event_type: EventType
    severity: SeverityLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    description: str = ""
    raw_data: Dict[str, Any] = None
    confidence_score: float = 1.0
    tags: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values for mutable fields"""
        if self.raw_data is None:
            self.raw_data = {}
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation"""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user_id": self.user_id,
            "description": self.description,
            "raw_data": self.raw_data,
            "confidence_score": self.confidence_score,
            "tags": self.tags,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityEvent:
        """Create SecurityEvent from dictionary"""
        return cls(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            event_type=EventType(data["event_type"]),
            severity=SeverityLevel(data["severity"]),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            user_id=data.get("user_id"),
            description=data.get("description", ""),
            raw_data=data.get("raw_data", {}),
            confidence_score=data.get("confidence_score", 1.0),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )


class EventSchema:
    """
    Schema validation and management for security events.
    
    Provides validation, normalization, and transformation
    capabilities for incoming security event data.
    """
    
    @staticmethod
    def validate_event(event_data: Dict[str, Any]) -> bool:
        """
        Validate event data against security event schema.
        
        Args:
            event_data: Raw event data dictionary
            
        Returns:
            bool: True if valid, False otherwise
        """
        required_fields = ["event_id", "timestamp", "event_type", "severity"]
        
        # Check required fields
        for field in required_fields:
            if field not in event_data:
                return False
        
        # Validate event type
        try:
            EventType(event_data["event_type"])
        except ValueError:
            return False
        
        # Validate severity
        try:
            SeverityLevel(event_data["severity"])
        except ValueError:
            return False
        
        # Validate confidence score
        confidence = event_data.get("confidence_score", 1.0)
        if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
            return False
        
        return True
    
    @staticmethod
    def normalize_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize event data to standard format.
        
        Args:
            event_data: Raw event data dictionary
            
        Returns:
            Dict[str, Any]: Normalized event data
        """
        normalized = event_data.copy()
        
        # Ensure timestamp is in ISO format
        if "timestamp" in normalized:
            if isinstance(normalized["timestamp"], str):
                try:
                    dt = datetime.fromisoformat(normalized["timestamp"].replace("Z", "+00:00"))
                    normalized["timestamp"] = dt.isoformat()
                except ValueError:
                    normalized["timestamp"] = datetime.now().isoformat()
        
        # Normalize confidence score
        if "confidence_score" not in normalized:
            normalized["confidence_score"] = 1.0
        else:
            confidence = normalized["confidence_score"]
            normalized["confidence_score"] = max(0.0, min(1.0, float(confidence)))
        
        # Ensure lists are initialized
        if "tags" not in normalized:
            normalized["tags"] = []
        if "metadata" not in normalized:
            normalized["metadata"] = {}
        if "raw_data" not in normalized:
            normalized["raw_data"] = {}
        
        return normalized
    
    @staticmethod
    def transform_legacy_event(legacy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform legacy event format to current schema.
        
        Args:
            legacy_data: Legacy event data dictionary
            
        Returns:
            Dict[str, Any]: Transformed event data
        """
        # Map legacy fields to current schema
        field_mapping = {
            "id": "event_id",
            "time": "timestamp",
            "type": "event_type",
            "level": "severity",
            "source": "source_ip",
            "target": "destination_ip",
            "user": "user_id",
            "message": "description",
            "data": "raw_data",
            "confidence": "confidence_score"
        }
        
        transformed = {}
        for legacy_field, current_field in field_mapping.items():
            if legacy_field in legacy_data:
                transformed[current_field] = legacy_data[legacy_field]
        
        # Add missing required fields with defaults
        if "event_id" not in transformed:
            transformed["event_id"] = f"legacy_{datetime.now().timestamp()}"
        if "timestamp" not in transformed:
            transformed["timestamp"] = datetime.now().isoformat()
        if "event_type" not in transformed:
            transformed["event_type"] = EventType.ANOMALY.value
        if "severity" not in transformed:
            transformed["severity"] = SeverityLevel.MEDIUM.value
        
        return transformed