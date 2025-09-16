from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from .model import TrainConfig, train, save, load, predict
from .memory import TemporalMemory
from .feature import Ontology
from .reasoner import ReasonerConfig
from .synth import sample_event, label

ALLOWED = ("ignore", "standard", "elevated", "critical")

def _load_jsonl(p: str) -> List[Dict[str, Any]]:
    rows = []
    with open(p, "r", encoding="utf-8") as f:
        for i, l in enumerate(f, 1):
            if not l.strip():
                continue
            try:
                o = json.loads(l)
            except json.JSONDecodeError as e:
                raise ValueError(f"Line {i}: Invalid JSON: {e}")
            lvl = str(o.get("threatLevel", "")).lower()
            if lvl not in ALLOWED:
                raise ValueError(f"Line {i} bad threatLevel {lvl}")
            rows.append(o)
    return rows

def _maybe_onto(p: Optional[str]) -> Optional[Ontology]:
    if not p:
        return None
    try:
        data = json.loads(Path(p).read_text("utf-8"))
        return Ontology(tags_by_device_id=data)
    except Exception as e:
        raise ValueError(f"Failed to load ontology: {e}")

def train_cmd(a):
    data = _load_jsonl(a.data)
    X = [{"events": d.get("events", []), "systemMode": d.get("systemMode", ""), "time": d.get("time", "")} for d in data]
    y = [d["threatLevel"] for d in data]
    Xtr, Xva, ytr, yva = train_test_split(X, y, test_size=a.val_split, random_state=42, stratify=y if len(set(y)) > 1 else None)
    cfg = TrainConfig(
        vectorizer=a.vectorizer,
        n_features=a.n_features,
        class_weight="balanced" if a.balanced else None,
        calibrate=not a.no_calibrate,
        prefilter_topk=a.prefilter,
        reasoner=ReasonerConfig(tau_elevated=a.tau_elevated, tau_critical=a.tau_critical, min_features=a.min_feat),
        max_iter=a.max_iter,
        C=a.C,
        penalty=a.penalty
    )
    sm = train(Xtr, ytr, cfg, _maybe_onto(a.ontology))
    print(classification_report(yva, sm.pipe.predict(Xva), labels=list(ALLOWED), zero_division=0), file=sys.stderr)
    save(sm, a.out)
    print(f"Saved {a.out}")

    if a.export_onnx:
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import DictionaryType, FloatTensorType, StringTensorType
            initial_type = [('input', DictionaryType(StringTensorType([1]), FloatTensorType([1])))]
            onnx_model = convert_sklearn(sm.pipe, initial_types=initial_type)
            Path(a.export_onnx).write_bytes(onnx_model.SerializeToString())
            print(f"Exported ONNX model to {a.export_onnx}")
        except ImportError:
            print("⚠️ skl2onnx not installed, cannot export.")

def infer_cmd(a):
    sm = load(a.model)
    try:
        s = json.loads(Path(a.input).read_text("utf-8"))
    except Exception as e:
        print(f"Error loading input: {e}", file=sys.stderr)
        sys.exit(1)

    sample = {"events": s.get("events", []), "systemMode": s.get("systemMode", ""), "time": s.get("time", "")}
    mem = TemporalMemory(Path(a.memory), a.win) if a.memory else None
    out = predict(sm, sample, mem)
    if mem:
        mem.append_and_prune(sample)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")

def test_cmd(a):
    X = [{"events": [sample_event()], "systemMode": "away", "time": "2025-01-01T12:00:00Z"} for _ in range(10)]
    y = [label(d["events"], d["systemMode"]) for d in X]
    sm = train(X, y, TrainConfig(), None)
    pred = predict(sm, X[0])
    print(json.dumps(pred, indent=2))

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("novin-ai")
    sub = p.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("train")
    pt.add_argument("--data", required=True)
    pt.add_argument("--out", required=True)
    pt.add_argument("--val-split", type=float, default=0.2)
    pt.add_argument("--vectorizer", choices=["dict", "hash"], default="dict")
    pt.add_argument("--n-features", type=int, default=2**16)
    pt.add_argument("--balanced", action="store_true")
    pt.add_argument("--no-calibrate", action="store_true")
    pt.add_argument("--prefilter", type=int, default=2000)
    pt.add_argument("--ontology")
    pt.add_argument("--tau-elevated", type=float, default=0.55)
    pt.add_argument("--tau-critical", type=float, default=0.65)
    pt.add_argument("--min-feat", type=int, default=2)
    pt.add_argument("--export-onnx", help="Path to export ONNX model")
    pt.add_argument("--max-iter", type=int, default=1000, help="Max iterations for LogisticRegression")
    pt.add_argument("--C", type=float, default=1.0, help="Inverse of regularization strength")
    pt.add_argument("--penalty", choices=["l1", "l2", "none"], default="l2", help="Regularization penalty")
    pt.set_defaults(func=train_cmd)

    pi = sub.add_parser("infer")
    pi.add_argument("--model", required=True)
    pi.add_argument("--input", required=True)
    pi.add_argument("--memory")
    pi.add_argument("--win", type=int, default=10)
    pi.set_defaults(func=infer_cmd)

    ts = sub.add_parser("test")
    ts.set_defaults(func=test_cmd)

    return p

def main(argv: Optional[List[str]] = None):
    a = build_parser().parse_args(argv)
    a.func(a)

if __name__ == "__main__":
    main()
