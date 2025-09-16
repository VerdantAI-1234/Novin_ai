from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import random

@dataclass
class ReasonerConfig:
    min_confidence: float = 0.7
    max_phrases: int = 3
    min_phrases: int = 1
    random_seed: int = 42

    def __post_init__(self):
        random.seed(self.random_seed)

def reason(level: str, probs: List[float], num_phrases: int, 
          cfg: ReasonerConfig) -> Tuple[str, List[str], List[str]]:
    """Apply reasoning to adjust threat level and generate explanations."""
    dev_trace = [f"Starting with level: {level} and {num_phrases} phrases"]
    user_trace = []
    
    # Simple confidence-based adjustment
    max_prob = max(probs) if probs else 0
    if max_prob < cfg.min_confidence and level != "ignore":
        new_level = "standard" if level in ("elevated", "critical") else "ignore"
        dev_trace.append(f"Low confidence ({max_prob:.2f} < {cfg.min_confidence}), adjusting level from {level} to {new_level}")
        level = new_level
    
    # Ensure we have a reasonable number of phrases
    num_phrases = max(cfg.min_phrases, min(cfg.max_phrases, num_phrases))
    
    return level, dev_trace, user_trace
