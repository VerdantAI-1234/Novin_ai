from __future__ import annotations
import json, random, argparse
from typing import Any, Dict, List
from datetime import datetime, timedelta

random.seed(7)

LEVELS = ["ignore", "standard", "elevated", "critical"]
TYPES = ["motion", "door", "glassbreak", "noise", "face", "package", "smoke", "temp"]
LOCS = ["front_door", "back_door", "garage", "living_room", "kitchen", "hallway", "yard"]
MODES = ["home", "away", "night"]

def sample_event(device_id: str = None) -> Dict[str, Any]:
    t = random.choice(TYPES)
    loc = random.choice(LOCS)
    if not device_id:
        device_id = f"{loc}-{t}-{random.randint(1,3)}"
    ev = {
        "type": t,
        "location": loc,
        "deviceId": device_id,
        "confidence": round(random.uniform(0.5, 0.99), 2)
    }
    if t == "door":
        ev["state"] = random.choice(["open", "close"])
    if t == "noise":
        ev["db"] = round(random.uniform(30, 95), 1)
    return ev

def label(events: List[Dict], mode: str) -> str:
    score = 0.0
    type_counts = {}
    for e in events:
        typ = e.get("type")
        type_counts[typ] = type_counts.get(typ, 0) + 1
        if typ in {"glassbreak", "smoke"}:
            score += 1.0
        elif typ == "door" and e.get("state") == "open":
            score += 0.5
        if type_counts[typ] >= 3:
            score += 0.8
    if mode == "away":
        score += 0.5
    if score >= 2.0:
        return "critical"
    if score >= 1.4:
        return "elevated"
    if score >= 0.6:
        return "standard"
    return "ignore"

def synth(n: int, out: str):
    with open(out, "w", encoding="utf-8") as f:
        for i in range(n):
            mode = random.choice(MODES)
            day = random.randint(1, 28)
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            t = f"2025-01-{day:02d}T{hour:02d}:{minute:02d}:00Z"

            if random.random() < 0.3:
                loc = random.choice(LOCS)
                typ = random.choice(TYPES)
                dev_id = f"{loc}-{typ}-1"
                repeat_count = random.randint(3, 5)
                events = [sample_event(dev_id) for _ in range(repeat_count)]
            else:
                events = [sample_event() for _ in range(random.randint(1, 4))]

            lvl = label(events, mode)
            f.write(json.dumps({
                "events": events,
                "systemMode": mode,
                "time": t,
                "threatLevel": lvl
            }) + "\n")
    print(f"Wrote {n} rows to {out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=1000)
    a = ap.parse_args()
    synth(a.n, a.out)
