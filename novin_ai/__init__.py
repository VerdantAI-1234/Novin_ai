"""
Novin AI — Ultra-lightweight threat classifier with temporal memory & explainability.
Mobile-ready. ONNX exportable. Production-grade.
"""

import logging

# Set up basic logging if not configured
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from .model import train, predict, save, load, TrainConfig
from .cli import main as cli_main
from .model import self_test

__all__ = ["train", "predict", "save", "load", "TrainConfig", "cli_main", "self_test"]# Initialize the novin_ai package
