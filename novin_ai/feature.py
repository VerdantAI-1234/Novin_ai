from __future__ import annotations
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

@dataclass
class Ontology:
    """Optional device ontology to tag devices with semantic roles."""
    tags_by_device_id: Dict[str, List[str]]

class FeatureExtractor(BaseEstimator, TransformerMixin):
    """JSON → numeric features with optional prefilter by frequency."""
    def __init__(self, ontology: Optional[Ontology] = None, prefilter_topk: Optional[int] = None) -> None:
        self.ontology = ontology
        self.prefilter_topk = prefilter_topk
        self._keep_tokens: Optional[set] = None

    def fit(self, X: Iterable[Dict[str, Any]], y: Optional[Iterable[Any]] = None):
        if self.prefilter_topk is None:
            return self
        counts: Dict[str, int] = {}
        for sample in X:
            feats = self._one(sample, collect_all=True)
            for k in feats.keys():
                counts[k] = counts.get(k, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[: self.prefilter_topk]
        self._keep_tokens = set(k for k, _ in top)
        return self

    def transform(self, X: Iterable[Dict[str, Any]]) -> List[Dict[str, float]]:
        out: List[Dict[str, float]] = []
        for sample in X:
            feats = self._one(sample, collect_all=self._keep_tokens is None)
            if self._keep_tokens is not None:
                feats = {k: v for k, v in feats.items() if k in self._keep_tokens}
            out.append(feats)
        return out

    def _one(self, sample: Dict[str, Any], collect_all: bool) -> Dict[str, float]:
        feats: Dict[str, float] = {}
        events = sample.get("events") or []
        mode = str(sample.get("systemMode", "") or "").strip().lower()
        time_str = str(sample.get("time", "") or "")

        if mode:
            feats[f"mode={mode}"] = 1.0

        dt = _safe_parse_time(time_str)
        if dt:
            hour = dt.hour + dt.minute / 60.0
            feats["hour_sin"] = math.sin(2 * math.pi * hour / 24.0)
            feats["hour_cos"] = math.cos(2 * math.pi * hour / 24.0)
            dow = dt.weekday()
            feats["dow_sin"] = math.sin(2 * math.pi * dow / 7.0)
            feats["dow_cos"] = math.cos(2 * math.pi * dow / 7.0)

        total = 0
        uniq_type, uniq_loc = set(), set()
        num_stats: Dict[str, List[float]] = {}

        for ev in events if isinstance(events, list) else []:
            total += 1
            dev_id = None
            if isinstance(ev, dict):
                dev_id = ev.get("deviceId") or ev.get("id")
                for k, v in ev.items():
                    if v is None: continue
                    if isinstance(v, (bool, str)):
                        token = f"evt:{k}={str(v).strip().lower()}"
                        feats[token] = feats.get(token, 0.0) + 1.0
                        lk = k.lower()
                        if lk in ("type", "event", "sensor_type"):
                            uniq_type.add(str(v).lower())
                        if lk in ("location", "zone", "room"):
                            uniq_loc.add(str(v).lower())
                    elif isinstance(v, (int, float)):
                        num_stats.setdefault(k, []).append(float(v))
            if self.ontology and dev_id:
                for tag in self.ontology.tags_by_device_id.get(str(dev_id), []):
                    feats[f"tag:{tag}"] = feats.get(f"tag:{tag}", 0.0) + 1.0

        feats["events_total"] = float(total)
        feats["events_types_unique"] = float(len(uniq_type))
        feats["events_locations_unique"] = float(len(uniq_loc))

        for k, vals in num_stats.items():
            feats[f"num:{k}:mean"] = float(np.mean(vals))
            feats[f"num:{k}:max"] = float(np.max(vals))
            feats[f"num:{k}:min"] = float(np.min(vals))
            feats[f"num:{k}:std"] = float(np.std(vals) if len(vals) > 1 else 0.0)
        return feats

def _safe_parse_time(s: str) -> Optional[datetime]:
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except: return None
