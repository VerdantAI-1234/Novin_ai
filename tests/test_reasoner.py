# tests/test_reasoner.py
import pytest
from datetime import timezone

from security_reasoner import ThreatLevel


# ----------------------------------------------------------------------
# 1️⃣  Core dimensions you care about
# ----------------------------------------------------------------------
EVENT_TYPES = ["motion", "door", "window", "camera", "sound", "person"]
HOURS = list(range(0, 24))                     # every hour of the day
LOCATIONS = [
    "main entrance", "back door", "server room", "parking lot",
    "lobby", "warehouse", "roof", "basement"
]
CONFIDENCES = [0.3, 0.6, 0.9, 1.0]             # low-mid-high confidence
NEGATIONS = [
    "no gun detected",                     # explicit negation
    "the door was not forced",             # verb-negation
    "toy weapon on the floor",             # semantic negation
    "test event – ignore",                 # disclaimer token
    "g u n spotted",                       # leet-style
    "枪 detected",                         # non-Latin (Chinese "gun")
]

# ----------------------------------------------------------------------
# 2️⃣  Helper that builds a description from a token list
# ----------------------------------------------------------------------
def build_description(tokens):
    """Join tokens with random punctuation to stress the parser."""
    import random
    punct = ["", " ", " - ", ", ", ". "]
    return "".join(t + random.choice(punct) for t in tokens)


# ----------------------------------------------------------------------
# 3️⃣  Parametrised test – each combination becomes a separate test case
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "event_type",
    EVENT_TYPES,
    ids=lambda v: f"type={v}",
)
@pytest.mark.parametrize(
    "hour",
    HOURS,
    ids=lambda v: f"hour={v:02d}",
)
@pytest.mark.parametrize(
    "location",
    LOCATIONS,
    ids=lambda v: f"loc={v.replace(' ', '_')}",
)
@pytest.mark.parametrize(
    "confidence",
    CONFIDENCES,
    ids=lambda v: f"conf={v:.1f}",
)
@pytest.mark.parametrize(
    "negation",
    NEGATIONS,
    ids=lambda v: f"neg={v.split()[0]}",
)
def test_reasoner_day_to_day_scenarios(
    engine,
    make_event,
    event_type,
    hour,
    location,
    confidence,
    negation,
    event_loop,
):
    """
    One test case per cross-product of the dimensions above.
    The description mixes a risk keyword with a negation/disclaimer token.
    """
    # --------------------------------------------------------------
    # 4️⃣  Build a realistic description
    # --------------------------------------------------------------
    risk_map = {
        "door": ["break", "forced", "intruder"],
        "window": ["smash", "shatter", "intruder"],
        "motion": ["movement", "activity"],
        "camera": ["blur", "obstructed"],
        "sound": ["alarm", "bang"],
        "person": ["unknown", "suspicious"],
    }
    risk_word = risk_map.get(event_type, ["alert"])[0]

    description = build_description([risk_word, negation])

    # --------------------------------------------------------------
    # 5️⃣  Create the raw dict and feed it to the engine
    # --------------------------------------------------------------
    raw = make_event(
        event_type=event_type,
        hour=hour,
        location=location,
        description=description,
        confidence=confidence,
    )

    assessment = event_loop.run_until_complete(
        engine.process_event(raw, wait_for_result=True, result_timeout=5.0)
    )

    # --------------------------------------------------------------
    # 6️⃣  Assertions – you can tighten them later
    # --------------------------------------------------------------
    assert assessment.event_id == raw["event_id"]
    assert isinstance(assessment.threat_level, ThreatLevel)

    if confidence < 0.6 or any(tok in negation.lower() for tok in ["no", "not", "without", "toy", "test"]):
        assert assessment.calibrated_score <= 0.5, "Negated / low-confidence events should stay low"

    assert any(f"kw:" in rc for rc in assessment.reason_codes)
    if any(tok in negation.lower() for tok in ["no", "not", "without", "toy", "test"]):
        assert any(rc.startswith("neg:") for rc in assessment.reason_codes)

    if assessment.uncertain:
        assert assessment.uncertainty_reason is not None