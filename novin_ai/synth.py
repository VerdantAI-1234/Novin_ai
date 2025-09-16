import random
from typing import Dict, List, Any
from datetime import datetime, timedelta

def sample_event() -> Dict[str, Any]:
    """Generate a sample security event with realistic values."""
    event_types = ["motion", "contact", "glass_break", "smoke", "water_leak"]
    zones = ["front_door", "back_door", "living_room", "kitchen", "bedroom", "basement"]
    
    return {
        "type": random.choice(event_types),
        "deviceId": f"device_{random.randint(1000, 9999)}",
        "zone": random.choice(zones),
        "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(0, 60))).isoformat() + "Z",
        "value": random.choice([True, False, 0, 1, 25, 50, 75, 100])
    }

def label(events: List[Dict[str, Any]], system_mode: str = "home") -> str:
    """Generate a synthetic label based on events and system mode."""
    if not events:
        return "ignore"
    
    # Simple rule-based labeling
    event_types = [e.get("type") for e in events if isinstance(e, dict)]
    
    if any(t in event_types for t in ["smoke", "water_leak"]):
        return "critical"
    
    if system_mode == "away" and any(t in event_types for t in ["motion", "contact"]):
        return "elevated"
    
    return "ignore"
