from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any

@dataclass
class ReasonerConfig:
    tau_elevated: float = 0.55
    tau_critical: float = 0.65
    min_features: int = 2

Threats = ("ignore", "standard", "elevated", "critical")
idx = {t: i for i, t in enumerate(Threats)}

def _downgrade(l: str) -> str:
    return Threats[max(0, idx[l] - 1)]

def reason(level: str, probs: List[float], feats: int, cfg: ReasonerConfig, events: List[Dict[str, Any]]) -> Tuple[str, bool, List[str], List[str]]:
    dev_trace, user_trace = [], []
    p = max(probs)
    low = False

    dev_trace.append(f"Base={level} p={p:.2f}")
    user_trace.append(f"Initial model prediction was {level} with {p:.0%} confidence.")

    # ESCALATE: if critical event present, force elevated/critical
    CRITICAL_EVENT_TYPES = {"smoke", "glassbreak"}
    critical_events = [e for e in events if e.get("type") in CRITICAL_EVENT_TYPES]
    if critical_events and level in {"ignore", "standard"}:
        old_level = level
        level = "critical" if p > 0.5 else "elevated"
        dev_trace.append(f"Escalate: critical event(s) present: {[e.get('type') for e in critical_events]}")
        user_trace.append(f"Threat escalated due to critical event: {critical_events[0].get('type')}.")
        low = False  # override low confidence

    # DOWNGRADE
    if level == "critical" and p < cfg.tau_critical and not critical_events:
        level = "elevated"
        low = True
        dev_trace.append("Downgrade: critical<tau_critical")
        user_trace.append("Severity reduced from critical to elevated due to low confidence.")
    elif level == "elevated" and p < cfg.tau_elevated and not critical_events:
        level = "standard"
        low = True
        dev_trace.append("Downgrade: elevated<tau_elevated")
        user_trace.append("Severity reduced from elevated to standard due to low confidence.")

    if feats < cfg.min_features:
        level = _downgrade(level)
        low = True
        dev_trace.append("Downgrade: insufficient strong features")
        user_trace.append("Severity lowered because not enough strong signals were present.")

    return level, low, dev_trace, user_trace
