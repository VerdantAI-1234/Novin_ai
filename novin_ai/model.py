from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer, FeatureHasher
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline

from .feature import FeatureExtractor, Ontology
from .memory import TemporalMemory
from .reasoner import reason, ReasonerConfig
from .explain import name_to_phrase, format_explanation
from .schemas import SampleInput

logger = logging.getLogger(__name__)

ALLOWED = ("ignore", "standard", "elevated", "critical")

@dataclass
class TrainConfig:
    vectorizer: str = "dict"
    n_features: int = 2**16
    class_weight: Optional[str] = "balanced"
    calibrate: bool = True
    prefilter_topk: Optional[int] = 2000
    reasoner: ReasonerConfig = ReasonerConfig()
    max_iter: int = 1000
    C: float = 1.0
    penalty: str = "l2"

@dataclass
class SavedModel:
    pipe: Pipeline
    cfg: TrainConfig
    dictvec: bool
    feature_names: Optional[List[str]] = None
    trained_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

def build_pipeline(cfg: TrainConfig, onto: Optional[Ontology]) -> Pipeline:
    feat = FeatureExtractor(ontology=onto, prefilter_topk=cfg.prefilter_topk)
    vec = DictVectorizer(sparse=True) if cfg.vectorizer == "dict" else FeatureHasher(n_features=cfg.n_features, alternate_sign=False, input_type="dict")
    
    # Solver selection based on penalty
    if cfg.penalty == "l1":
        solver = "saga"  # Only saga supports l1 + multinomial
    elif cfg.penalty == "none":
        solver = "lbfgs"  # or "saga"
    else:  # l2 or elasticnet
        solver = "lbfgs"
    
    clf = LogisticRegression(
        max_iter=cfg.max_iter,
        C=cfg.C,
        penalty=cfg.penalty,
        solver=solver,  # Explicitly set solver
        multi_class="multinomial",
        class_weight=cfg.class_weight
    )
    if cfg.calibrate:
        clf = CalibratedClassifierCV(clf, cv=3, method="sigmoid")
    return Pipeline([("feat", feat), ("vec", vec), ("clf", clf)])

def train(X: List[Dict[str, Any]], y: List[str], cfg: TrainConfig, onto: Optional[Ontology]) -> SavedModel:
    pipe = build_pipeline(cfg, onto)
    pipe.fit(X, y)
    names = None
    if cfg.vectorizer == "dict":
        names = pipe.named_steps["vec"].get_feature_names_out().tolist()
    return SavedModel(pipe, cfg, cfg.vectorizer == "dict", names)

def save(sm: SavedModel, path: str): joblib.dump(sm, path)
def load(path: str) -> SavedModel: return joblib.load(path)

def predict(sm: SavedModel, sample: Dict[str, Any], memory: Optional[TemporalMemory] = None) -> Dict[str, Any]:
    start_time = datetime.utcnow()

    # Validate and normalize input
    try:
        validated = SampleInput(**sample)
        sample = validated.dict()
    except Exception as e:
        error_msg = f"Input validation failed: {str(e)}"
        # REDACT sensitive fields before logging
        redacted_sample = {
            "events": [{"type": ev.get("type"), "location": "REDACTED"} for ev in sample.get("events", [])],
            "systemMode": sample.get("systemMode", "REDACTED"),
            "time": sample.get("time", "REDACTED")
        }
        logger.warning("prediction_failed", extra={"error": error_msg, "input_redacted": redacted_sample})
        return {
            "error": "Input validation failed",
            "details": str(e),
            "threatLevel": "ignore"
        }

    pipe = sm.pipe
    feat = pipe.named_steps["feat"]
    vec = pipe.named_steps["vec"]
    clf = pipe.named_steps["clf"]

    feats = feat.transform([sample])[0]
    if memory:
        feats.update(memory.aggregate(str(sample.get("time", ""))))

    X = vec.transform([feats])
    
    # Fixed: Use len(classes) for fallback probabilities
    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(X)[0]
    else:
        classes = getattr(clf, "classes_", np.array(ALLOWED))
        probs = np.ones(len(classes)) / len(classes)

    classes = getattr(clf, "classes_", np.array(ALLOWED))
    idx = int(np.argmax(probs))
    level = str(classes[idx])

    phrases = [name_to_phrase(k) for k in list(feats.keys())[:3]]
    level, low, dev, user = reason(level, probs.tolist(), len(phrases), sm.cfg.reasoner, sample.get("events", []))

    expl = format_explanation(level, phrases, float(np.max(probs)), low)

    latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
    logger.info("prediction_complete", extra={
        "threat_level": level,
        "confidence": float(np.max(probs)),
        "latency_ms": latency_ms,
        "downgraded": low,
        "system_mode": sample.get("systemMode", ""),
        "event_count": len(sample.get("events", [])),
        "trained_at": sm.trained_at
    })

    return {
        "threatLevel": level,
        "explanation": expl,
        "dev_trace": dev,
        "user_trace": user,
        "trained_at": sm.trained_at,
        "latency_ms": latency_ms
    }

def self_test():
    """Run a quick smoke test to verify installation."""
    from .synth import sample_event, label
    from .cli import _load_jsonl

    X = [{"events": [sample_event()], "systemMode": "away", "time": "2025-01-01T12:00:00Z"} for _ in range(10)]
    y = [label(d["events"], d["systemMode"]) for d in X]

    sm = train(X, y, TrainConfig(vectorizer="hash", n_features=256), None)
    pred = predict(sm, X[0])
    assert pred["threatLevel"] in ("ignore", "standard", "elevated", "critical"), "Prediction failed"
    print("✅ Self-test passed. Model is functional.")
    return True# Core AI model definitions and training
