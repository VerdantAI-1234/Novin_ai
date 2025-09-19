# Novin AI - Threat Classification System

Novin AI is an ultra-lightweight threat classifier with temporal memory and explainability features, designed for mobile B2B applications. It's built using Python with scikit-learn and can export to ONNX format.

**ALWAYS follow these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### Bootstrap, build, and test the repository:
- Install Python dependencies: `pip install joblib numpy scikit-learn pydantic`
- OPTIONAL for ONNX export: `pip install skl2onnx` (NOTE: ONNX export currently fails due to custom FeatureExtractor transformer not being supported by skl2onnx)
- Verify installation: `python3 -c "from novin_ai import self_test; self_test()"` -- takes ~1 second. NEVER CANCEL.
- All Python files can be syntax-checked with: `python3 -m py_compile novin_ai/*.py`

### Training models:
- Generate test data: Use the built-in synthetic data generator in `novin_ai.synth`
- Training command: `python3 -c "from novin_ai import cli_main; cli_main(['train', '--data', 'data.jsonl', '--out', 'model.pkl', '--no-calibrate'])"`
- **IMPORTANT**: Use `--no-calibrate` flag for small datasets (<100 samples) to avoid calibration errors
- Training with 200 samples takes ~2 seconds. NEVER CANCEL. Set timeout to 30+ seconds for safety.
- Large training datasets (1000+ samples) may take 10-30 seconds. NEVER CANCEL.

### Running inference:
- Inference command: `python3 -c "from novin_ai import cli_main; cli_main(['infer', '--model', 'model.pkl', '--input', 'sample.json'])"`
- Inference typically takes <1 second for single samples

### CLI Usage:
- Help: `python3 -c "from novin_ai import cli_main; cli_main(['--help'])"`
- Train: `python3 -c "from novin_ai import cli_main; cli_main(['train', '--data', 'file.jsonl', '--out', 'model.pkl', '--no-calibrate'])"`
- Infer: `python3 -c "from novin_ai import cli_main; cli_main(['infer', '--model', 'model.pkl', '--input', 'sample.json'])"`
- Test: `python3 -c "from novin_ai import cli_main; cli_main(['test'])"`

## Validation

### MANUAL VALIDATION REQUIREMENT:
- ALWAYS run the self-test after making changes: `python3 -c "from novin_ai import self_test; self_test()"`
- ALWAYS test the complete workflow:
  1. Generate synthetic data using the synth module
  2. Train a model with the generated data
  3. Run inference on a test sample
  4. Verify the output contains threatLevel, explanation, and dev_trace fields
- For any changes to the core model or feature extraction, generate at least 50 samples and verify training completes successfully

### Critical timing expectations:
- **NEVER CANCEL** training or testing operations - they complete quickly but may show warnings
- Self-test: ~1 second, timeout 30 seconds
- Training (50-200 samples): 1-2 seconds, timeout 30 seconds  
- Training (1000+ samples): 10-30 seconds, timeout 60 seconds
- Inference: <1 second per sample, timeout 10 seconds

## Common Tasks

### Repository Structure:
```
.
├── README.md                    # Basic project description
├── LICENSE                      # Apache 2.0 license
├── novin_ai/                    # Main Python package
│   ├── __init__.py             # Package initialization, imports main functions
│   ├── cli.py                  # Command-line interface (train/infer/test)
│   ├── model.py                # Core ML model, training, and prediction logic
│   ├── feature.py              # Feature extraction and ontology handling
│   ├── reasoner.py             # Threat level reasoning and escalation logic
│   ├── memory.py               # Temporal memory for event sequences
│   ├── explain.py              # Explanation generation for predictions
│   ├── schemas.py              # Pydantic models for data validation
│   ├── synth.py                # Synthetic data generation for testing
│   └── py.typed                # Type hints marker file
└── .github/
    └── copilot-instructions.md  # This file
```

### Key Dependencies:
- **Required**: joblib, numpy, scikit-learn, pydantic
- **Optional**: skl2onnx (for ONNX export - currently broken due to custom transformer)
- **Python Version**: Works with Python 3.12+

### Important Code Paths:
- Model training: `novin_ai.model.train()` 
- Prediction: `novin_ai.model.predict()`
- CLI entry point: `novin_ai.cli.main()`
- Self-test: `novin_ai.model.self_test()`
- Data generation: `novin_ai.synth.sample_event()`, `novin_ai.synth.label()`

### Data Format:
Input data should be JSONL format with each line containing:
```json
{
  "events": [{"type": "motion", "location": "front_door", "deviceId": "sensor1", "confidence": 0.95}],
  "systemMode": "away",
  "time": "2025-01-01T12:00:00Z",
  "threatLevel": "elevated"
}
```

### Known Issues:
- ONNX export fails with custom FeatureExtractor - document this limitation
- Calibration requires minimum 3 samples per class - use `calibrate=False` for small datasets
- FutureWarning from scikit-learn about 'multi_class' parameter - cosmetic, ignore

### Quick Test Commands:
```python
# Test import
python3 -c "import novin_ai; print('✅ Import successful')"

# Run self-test
python3 -c "from novin_ai import self_test; self_test()"

# Generate and train on synthetic data
python3 -c "
from novin_ai.synth import sample_event, label
import json
data = []
for i in range(50):
    events = [sample_event() for _ in range(2)]
    mode = ['home', 'away', 'night'][i % 3]
    sample = {'events': events, 'systemMode': mode, 'time': '2025-01-01T12:00:00Z'}
    sample['threatLevel'] = label(events, mode)
    data.append(sample)
with open('test_data.jsonl', 'w') as f:
    for d in data: f.write(json.dumps(d) + '\n')
print('Generated test_data.jsonl')
"

# Train model
python3 -c "from novin_ai import cli_main; cli_main(['train', '--data', 'test_data.jsonl', '--out', 'test_model.pkl', '--no-calibrate'])"

# Test inference
python3 -c "
from novin_ai.synth import sample_event
import json
sample = {'events': [sample_event()], 'systemMode': 'away', 'time': '2025-01-01T12:00:00Z'}
with open('test_input.json', 'w') as f: json.dump(sample, f)
print('Generated test_input.json')
"

python3 -c "from novin_ai import cli_main; cli_main(['infer', '--model', 'test_model.pkl', '--input', 'test_input.json'])"
```

### When Making Changes:
1. **ALWAYS** run the self-test after code changes to verify basic functionality
2. **ALWAYS** test with synthetic data generation and training for feature/model changes
3. Check that both DictVectorizer and FeatureHasher work by testing different `--vectorizer` options
4. If modifying the reasoner logic, test with different threat levels and system modes
5. For memory-related changes, test with the `--memory` option in inference
6. Syntax check: `python3 -m py_compile novin_ai/*.py`

### Troubleshooting:
- **Import errors**: Install missing dependencies with pip
- **Calibration errors**: Use `calibrate=False` in TrainConfig for small datasets
- **ONNX export fails**: This is expected due to custom transformer - document the limitation
- **Training hangs**: Training should complete in seconds to minutes, never hangs - check data format
- **Self-test fails**: Usually indicates a dependency issue or code syntax error