from __future__ import annotations
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter

def _parse_time(s: str) -> Optional[datetime]:
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except: return None

@dataclass
class TemporalMemory:
    """Sliding window of recent events with repeat detection."""
    path: Path
    window_minutes: int = 10

    def _load(self) -> List[Dict[str, Any]]:
        if not self.path.exists(): return []
        try: return json.loads(self.path.read_text("utf-8"))
        except: return []

    def _save(self, rows: List[Dict[str, Any]]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(rows,ensure_ascii=False), "utf-8")

    def aggregate(self, ref_time: str) -> Dict[str, float]:
        feats: Dict[str,float] = {}
        rows = self._load()
        ref = _parse_time(ref_time) or datetime.utcnow()
        start = ref - timedelta(minutes=self.window_minutes)
        window = [r for r in rows if (ts:=_parse_time(r.get("time",""))) and start<=ts<=ref]

        feats["mem:events_total"] = float(sum(len(s.get("events") or []) for s in window))
        feats["mem:sessions"] = float(len(window))

        event_types = [ev.get("type") for s in window for ev in (s.get("events") or []) if isinstance(ev,dict)]
        for typ,cnt in Counter(event_types).items():
            if cnt > 1:
                feats[f"mem:repeats:type={typ}"] = float(cnt)

        device_ids = [ev.get("deviceId") for s in window for ev in (s.get("events") or []) if isinstance(ev,dict) and ev.get("deviceId")]
        for dev,cnt in Counter(device_ids).items():
            if cnt > 1:
                feats[f"mem:repeats:device={dev}"] = float(cnt)

        return feats

    def append_and_prune(self, sample: Dict[str,Any]):
        rows = self._load()
        ts = _parse_time(str(sample.get("time") or "")) or datetime.utcnow()
        rows.append({"time": ts.isoformat(), "events": sample.get("events") or []})
        start = ts - timedelta(minutes=self.window_minutes)
        rows = [r for r in rows if (_parse_time(r.get("time","")) or ts) >= start]
        self._save(rows)# Memory management and persistence
