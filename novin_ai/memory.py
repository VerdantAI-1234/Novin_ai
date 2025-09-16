from __future__ import annotations
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter
import tempfile
import os

def _parse_time(s: Any) -> Optional[datetime]:
    """Accept datetime or ISO-like string. Return datetime or None."""
    if isinstance(s, datetime):
        return s
    try:
        if not s:
            return None
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

@dataclass
class TemporalMemory:
    """Sliding window of recent events with repeat detection."""
    path: Path
    window_minutes: int = 10

    def _load(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text("utf-8"))
        except Exception:
            return []

    def _save(self, rows: List[Dict[str, Any]]):
        # Atomic write: write to temp file then replace
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(self.path.parent))
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmpf:
                json.dump(rows, tmpf, ensure_ascii=False)
            os.replace(tmp_path, str(self.path))
        finally:
            # clean up temp file if something went wrong and it's still there
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def aggregate(self, ref_time: str) -> Dict[str, float]:
        feats: Dict[str,float] = {}
        rows = self._load()
        ref = _parse_time(ref_time) or datetime.utcnow()
        start = ref - timedelta(minutes=self.window_minutes)
        window = [r for r in rows if (ts := _parse_time(r.get("time",""))) and start <= ts <= ref]

        feats["mem:events_total"] = float(sum(len(s.get("events") or []) for s in window))
        feats["mem:sessions"] = float(len(window))

        event_types = [ev.get("type") for s in window for ev in (s.get("events") or []) if isinstance(ev,dict)]
        for typ, cnt in Counter(event_types).items():
            if cnt > 1:
                feats[f"mem:repeats:type={typ}"] = float(cnt)

        device_ids = [ev.get("deviceId") for s in window for ev in (s.get("events") or []) if isinstance(ev,dict) and ev.get("deviceId")]
        for dev, cnt in Counter(device_ids).items():
            if cnt > 1:
                feats[f"mem:repeats:device={dev}"] = float(cnt)

        return feats

    def append_and_prune(self, sample: Dict[str,Any]):
        rows = self._load()
        ts = _parse_time(sample.get("time") or "") or datetime.utcnow()
        rows.append({"time": ts.isoformat(), "events": sample.get("events") or []})
        start = ts - timedelta(minutes=self.window_minutes)
        rows = [r for r in rows if (_parse_time(r.get("time","")) or ts) >= start]
        self._save(rows)
