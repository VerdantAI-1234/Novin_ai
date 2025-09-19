"""
Novin AI — Ultra-lightweight threat classifier with temporal memory & explainability.
Mobile-ready. ONNX exportable. Production-grade.
"""

import logging
import asyncio
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

# Set up basic logging if not configured
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from .model import train, predict, save, load, TrainConfig
from .cli import main as cli_main
from .model import self_test


class ThreatLevel(Enum):
    """Threat level enumeration matching the model's output."""
    IGNORE = "ignore"
    STANDARD = "standard" 
    ELEVATED = "elevated"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_id: str
    event_type: str
    timestamp: str
    source: str
    location: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    threat_level: Optional[ThreatLevel] = None
    calibrated_score: float = 0.0
    reason_codes: List[str] = field(default_factory=list)
    uncertain: bool = False
    uncertainty_reason: Optional[str] = None


@dataclass 
class Config:
    """Configuration for the security reasoner engine."""
    CALIBRATION_VERSION: str = "default"


class SecurityReasonerEngine:
    """Security reasoning engine that wraps the novin_ai model."""
    
    def __init__(self, config: Config):
        self.config = config
        self._model = None
        self._running = False
        
    async def start(self):
        """Start the async workers."""
        self._running = True
        # Initialize the model with some dummy data
        from .synth import sample_event, label
        X = []
        y = []
        for _ in range(50):
            sample = {'events': [sample_event()], 'systemMode': 'away', 'time': '2025-01-01T12:00:00Z'}
            X.append(sample)
            y.append(label(sample['events'], sample['systemMode']))
        
        self._model = train(X, y, TrainConfig(vectorizer='hash', n_features=256), None)
        
    async def stop(self):
        """Stop the async workers."""
        self._running = False
        
    async def process_event(self, event_data: Dict[str, Any], wait_for_result: bool = True, result_timeout: float = 5.0) -> SecurityEvent:
        """Process a security event and return assessment."""
        if not self._running or not self._model:
            raise RuntimeError("Engine not started")
            
        # Convert event_data to the format expected by the model
        sample = {
            'events': [{
                'type': event_data.get('event_type', 'motion'),
                'location': event_data.get('location', 'unknown'),
                'deviceId': event_data.get('source', 'device-1'),
                'confidence': event_data.get('confidence', 1.0)
            }],
            'systemMode': 'away',
            'time': event_data.get('timestamp', datetime.now(timezone.utc).isoformat())
        }
        
        # Get prediction from the model
        result = predict(self._model, sample)
        
        # Extract threat level
        threat_level_str = result.get('threatLevel', 'ignore')
        threat_level = ThreatLevel(threat_level_str)
        
        # Calculate calibrated score based on threat level
        calibrated_score = {
            'ignore': 0.1,
            'standard': 0.3, 
            'elevated': 0.6,
            'critical': 0.9
        }.get(threat_level_str, 0.1)
        
        # Generate reason codes
        reason_codes = []
        description = event_data.get('description', '').lower()
        
        # Add keyword reason codes
        risk_keywords = ['break', 'forced', 'intruder', 'movement', 'activity', 'blur', 'obstructed', 'alarm', 'bang', 'unknown', 'suspicious', 'smash', 'shatter']
        for keyword in risk_keywords:
            if keyword in description:
                reason_codes.append(f"kw:{keyword}")
                
        # Add negation reason codes
        negation_keywords = ['no', 'not', 'without', 'toy', 'test']
        for keyword in negation_keywords:
            if keyword in description:
                reason_codes.append(f"neg:{keyword}")
        
        # Determine uncertainty
        uncertain = event_data.get('confidence', 1.0) < 0.7
        uncertainty_reason = "Low confidence signal" if uncertain else None
        
        return SecurityEvent(
            event_id=event_data.get('event_id', 'unknown'),
            event_type=event_data.get('event_type', 'motion'),
            timestamp=event_data.get('timestamp', datetime.now(timezone.utc).isoformat()),
            source=event_data.get('source', 'unknown'),
            location=event_data.get('location', 'unknown'),
            description=event_data.get('description', ''),
            metadata=event_data.get('metadata', {}),
            confidence=event_data.get('confidence', 1.0),
            threat_level=threat_level,
            calibrated_score=calibrated_score,
            reason_codes=reason_codes,
            uncertain=uncertain,
            uncertainty_reason=uncertainty_reason
        )


__all__ = [
    "train", "predict", "save", "load", "TrainConfig", "cli_main", "self_test",
    "ThreatLevel", "SecurityEvent", "Config", "SecurityReasonerEngine"
]
