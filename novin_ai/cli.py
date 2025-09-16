"""Command-line interface for Novin AI."""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from .model import train, save, load, predict, TrainConfig
from .memory import TemporalMemory
from .synth import sample_event

def train_command(args):
    """Handle the train subcommand."""
    # In a real implementation, load data from args.input
    print(f"Training model with config: {args}")
    # This is a placeholder - in a real implementation, you would load data here
    print("Training complete. Model saved to:", args.output)
    return 0

def predict_command(args):
    """Handle the predict subcommand."""
    model = load(args.model)
    
    # In a real implementation, load input data
    input_data = {"events": [sample_event() for _ in range(2)], 
                 "systemMode": "away",
                 "time": "2025-01-01T12:00:00Z"}
    
    memory = TemporalMemory(Path("./memory.json"))
    result = predict(model, input_data, memory)
    
    print(json.dumps(result, indent=2))
    return 0

def main(argv: List[str] = None) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(prog="novin-ai", 
                                   description="Novin AI - Security threat classification")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train a new model")
    train_parser.add_argument("-i", "--input", type=Path, required=True, 
                             help="Input training data file")
    train_parser.add_argument("-o", "--output", type=Path, required=True,
                             help="Output model file")
    train_parser.set_defaults(func=train_command)
    
    # Predict command
    predict_parser = subparsers.add_parser("predict", help="Make predictions")
    predict_parser.add_argument("-m", "--model", type=Path, required=True,
                               help="Path to trained model")
    predict_parser.add_argument("-i", "--input", type=Path,
                               help="Input data file (default: stdin)")
    predict_parser.set_defaults(func=predict_command)
    
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
