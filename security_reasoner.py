"""
Compatibility module that provides security_reasoner imports.
This module re-exports the novin_ai classes with the expected names.
"""

# Import all the required classes from novin_ai
from novin_ai import (
    ThreatLevel,
    SecurityEvent, 
    Config,
    SecurityReasonerEngine
)

# Re-export with the same names for compatibility
__all__ = [
    "ThreatLevel",
    "SecurityEvent", 
    "Config",
    "SecurityReasonerEngine"
]