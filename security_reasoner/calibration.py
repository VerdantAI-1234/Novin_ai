"""
Calibration Module

Provides model calibration and confidence adjustment capabilities
for the security reasoner system. Ensures accurate confidence scores
and proper probability calibration for threat detection models.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Callable
import numpy as np
import json
from datetime import datetime
from collections import defaultdict
import statistics


@dataclass
class CalibrationPoint:
    """Individual calibration data point"""
    predicted_probability: float
    actual_outcome: bool
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "predicted_probability": self.predicted_probability,
            "actual_outcome": self.actual_outcome,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class CalibrationBin:
    """Calibration bin for reliability analysis"""
    bin_min: float
    bin_max: float
    predictions: List[float]
    outcomes: List[bool]
    
    @property
    def bin_center(self) -> float:
        """Center point of the bin"""
        return (self.bin_min + self.bin_max) / 2
    
    @property
    def count(self) -> int:
        """Number of samples in bin"""
        return len(self.predictions)
    
    @property
    def mean_prediction(self) -> float:
        """Mean predicted probability in bin"""
        return statistics.mean(self.predictions) if self.predictions else 0.0
    
    @property
    def accuracy(self) -> float:
        """Actual accuracy in bin"""
        return statistics.mean(self.outcomes) if self.outcomes else 0.0
    
    @property
    def confidence_interval(self) -> Tuple[float, float]:
        """95% confidence interval for accuracy"""
        if self.count < 2:
            return (0.0, 1.0)
        
        p = self.accuracy
        n = self.count
        margin = 1.96 * np.sqrt(p * (1 - p) / n)
        
        return (max(0.0, p - margin), min(1.0, p + margin))


@dataclass
class CalibrationResults:
    """Results from calibration analysis"""
    bins: List[CalibrationBin]
    expected_calibration_error: float
    maximum_calibration_error: float
    brier_score: float
    reliability: float
    resolution: float
    uncertainty: float
    sample_count: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "bins": [
                {
                    "bin_center": bin.bin_center,
                    "count": bin.count,
                    "mean_prediction": bin.mean_prediction,
                    "accuracy": bin.accuracy,
                    "confidence_interval": bin.confidence_interval
                }
                for bin in self.bins
            ],
            "expected_calibration_error": self.expected_calibration_error,
            "maximum_calibration_error": self.maximum_calibration_error,
            "brier_score": self.brier_score,
            "reliability": self.reliability,
            "resolution": self.resolution,
            "uncertainty": self.uncertainty,
            "sample_count": self.sample_count
        }


class SecurityCalibrator:
    """
    Security-focused model calibration system.
    
    Provides confidence calibration, reliability analysis, and probability
    adjustment capabilities specifically designed for security threat detection.
    """
    
    def __init__(self, num_bins: int = 10, min_samples_per_bin: int = 5):
        """
        Initialize security calibrator.
        
        Args:
            num_bins: Number of calibration bins
            min_samples_per_bin: Minimum samples required per bin for reliability
        """
        self.num_bins = num_bins
        self.min_samples_per_bin = min_samples_per_bin
        self.calibration_data: List[CalibrationPoint] = []
        self.calibration_curve: Optional[Dict[str, Any]] = None
        self.adjustment_function: Optional[Callable[[float], float]] = None
        
        # Threat-specific calibration tracking
        self.threat_type_calibration: Dict[str, List[CalibrationPoint]] = defaultdict(list)
        self.severity_calibration: Dict[str, List[CalibrationPoint]] = defaultdict(list)
        
        # Historical performance tracking
        self.performance_history: List[Dict[str, Any]] = []
    
    def add_calibration_point(self, 
                            predicted_prob: float, 
                            actual_outcome: bool,
                            threat_type: Optional[str] = None,
                            severity: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a calibration data point.
        
        Args:
            predicted_prob: Model's predicted probability
            actual_outcome: True outcome (True for positive, False for negative)
            threat_type: Type of threat (optional)
            severity: Severity level (optional)
            metadata: Additional metadata (optional)
        """
        point = CalibrationPoint(
            predicted_probability=predicted_prob,
            actual_outcome=actual_outcome,
            timestamp=datetime.now(),
            metadata=metadata or {}
        )
        
        self.calibration_data.append(point)
        
        # Track by threat type
        if threat_type:
            self.threat_type_calibration[threat_type].append(point)
        
        # Track by severity
        if severity:
            self.severity_calibration[severity].append(point)
    
    def compute_calibration_metrics(self, data_points: Optional[List[CalibrationPoint]] = None) -> CalibrationResults:
        """
        Compute comprehensive calibration metrics.
        
        Args:
            data_points: Optional specific data points to analyze
            
        Returns:
            CalibrationResults with detailed metrics
        """
        if data_points is None:
            data_points = self.calibration_data
        
        if not data_points:
            return CalibrationResults(
                bins=[],
                expected_calibration_error=0.0,
                maximum_calibration_error=0.0,
                brier_score=0.0,
                reliability=0.0,
                resolution=0.0,
                uncertainty=0.0,
                sample_count=0
            )
        
        # Extract predictions and outcomes
        predictions = [point.predicted_probability for point in data_points]
        outcomes = [point.actual_outcome for point in data_points]
        
        # Create bins
        bins = self._create_calibration_bins(predictions, outcomes)
        
        # Calculate metrics
        ece = self._calculate_expected_calibration_error(bins)
        mce = self._calculate_maximum_calibration_error(bins)
        brier_score = self._calculate_brier_score(predictions, outcomes)
        reliability, resolution, uncertainty = self._calculate_reliability_metrics(bins, outcomes)
        
        return CalibrationResults(
            bins=bins,
            expected_calibration_error=ece,
            maximum_calibration_error=mce,
            brier_score=brier_score,
            reliability=reliability,
            resolution=resolution,
            uncertainty=uncertainty,
            sample_count=len(data_points)
        )
    
    def _create_calibration_bins(self, predictions: List[float], outcomes: List[bool]) -> List[CalibrationBin]:
        """Create calibration bins for analysis"""
        bins = []
        bin_width = 1.0 / self.num_bins
        
        for i in range(self.num_bins):
            bin_min = i * bin_width
            bin_max = (i + 1) * bin_width
            
            # Find predictions in this bin
            bin_predictions = []
            bin_outcomes = []
            
            for pred, outcome in zip(predictions, outcomes):
                if bin_min <= pred < bin_max or (i == self.num_bins - 1 and pred == 1.0):
                    bin_predictions.append(pred)
                    bin_outcomes.append(outcome)
            
            bins.append(CalibrationBin(
                bin_min=bin_min,
                bin_max=bin_max,
                predictions=bin_predictions,
                outcomes=bin_outcomes
            ))
        
        return bins
    
    def _calculate_expected_calibration_error(self, bins: List[CalibrationBin]) -> float:
        """Calculate Expected Calibration Error (ECE)"""
        total_samples = sum(bin.count for bin in bins)
        if total_samples == 0:
            return 0.0
        
        ece = 0.0
        for bin in bins:
            if bin.count > 0:
                weight = bin.count / total_samples
                calibration_error = abs(bin.mean_prediction - bin.accuracy)
                ece += weight * calibration_error
        
        return ece
    
    def _calculate_maximum_calibration_error(self, bins: List[CalibrationBin]) -> float:
        """Calculate Maximum Calibration Error (MCE)"""
        max_error = 0.0
        for bin in bins:
            if bin.count > 0:
                calibration_error = abs(bin.mean_prediction - bin.accuracy)
                max_error = max(max_error, calibration_error)
        
        return max_error
    
    def _calculate_brier_score(self, predictions: List[float], outcomes: List[bool]) -> float:
        """Calculate Brier Score"""
        if not predictions:
            return 0.0
        
        score = 0.0
        for pred, outcome in zip(predictions, outcomes):
            score += (pred - float(outcome)) ** 2
        
        return score / len(predictions)
    
    def _calculate_reliability_metrics(self, bins: List[CalibrationBin], outcomes: List[bool]) -> Tuple[float, float, float]:
        """Calculate reliability, resolution, and uncertainty"""
        total_samples = len(outcomes)
        if total_samples == 0:
            return 0.0, 0.0, 0.0
        
        base_rate = statistics.mean(outcomes)
        
        # Reliability (average squared deviation of bin accuracy from bin confidence)
        reliability = 0.0
        for bin in bins:
            if bin.count > 0:
                weight = bin.count / total_samples
                reliability += weight * (bin.mean_prediction - bin.accuracy) ** 2
        
        # Resolution (variance of bin accuracies weighted by bin sizes)
        resolution = 0.0
        for bin in bins:
            if bin.count > 0:
                weight = bin.count / total_samples
                resolution += weight * (bin.accuracy - base_rate) ** 2
        
        # Uncertainty (variance of the base rate)
        uncertainty = base_rate * (1 - base_rate)
        
        return reliability, resolution, uncertainty
    
    def build_calibration_curve(self) -> Dict[str, Any]:
        """
        Build calibration curve for probability adjustment.
        
        Returns:
            Dictionary containing calibration curve data
        """
        if not self.calibration_data:
            return {"curve_points": [], "adjustment_function": None}
        
        results = self.compute_calibration_metrics()
        
        # Extract curve points
        curve_points = []
        for bin in results.bins:
            if bin.count >= self.min_samples_per_bin:
                curve_points.append({
                    "predicted": bin.mean_prediction,
                    "actual": bin.accuracy,
                    "count": bin.count,
                    "confidence_interval": bin.confidence_interval
                })
        
        # Build adjustment function
        if len(curve_points) >= 3:
            self.adjustment_function = self._build_adjustment_function(curve_points)
        
        self.calibration_curve = {
            "curve_points": curve_points,
            "adjustment_function": self.adjustment_function is not None,
            "last_updated": datetime.now().isoformat(),
            "sample_count": len(self.calibration_data)
        }
        
        return self.calibration_curve
    
    def _build_adjustment_function(self, curve_points: List[Dict[str, Any]]) -> Callable[[float], float]:
        """Build probability adjustment function from calibration curve"""
        predicted_values = [point["predicted"] for point in curve_points]
        actual_values = [point["actual"] for point in curve_points]
        
        # Simple linear interpolation function
        def adjust_probability(prob: float) -> float:
            if not predicted_values:
                return prob
            
            # Handle edge cases
            if prob <= predicted_values[0]:
                return actual_values[0]
            if prob >= predicted_values[-1]:
                return actual_values[-1]
            
            # Linear interpolation
            for i in range(len(predicted_values) - 1):
                if predicted_values[i] <= prob <= predicted_values[i + 1]:
                    # Interpolate between points
                    x1, y1 = predicted_values[i], actual_values[i]
                    x2, y2 = predicted_values[i + 1], actual_values[i + 1]
                    
                    if x2 == x1:
                        return y1
                    
                    interpolated = y1 + (y2 - y1) * (prob - x1) / (x2 - x1)
                    return max(0.0, min(1.0, interpolated))
            
            return prob
        
        return adjust_probability
    
    def adjust_probability(self, probability: float) -> float:
        """
        Adjust probability using calibration curve.
        
        Args:
            probability: Raw probability from model
            
        Returns:
            Calibrated probability
        """
        if self.adjustment_function is None:
            self.build_calibration_curve()
        
        if self.adjustment_function is not None:
            return self.adjustment_function(probability)
        
        return probability
    
    def get_threat_type_calibration(self, threat_type: str) -> Optional[CalibrationResults]:
        """
        Get calibration metrics for specific threat type.
        
        Args:
            threat_type: Type of threat
            
        Returns:
            CalibrationResults for the threat type or None
        """
        if threat_type not in self.threat_type_calibration:
            return None
        
        return self.compute_calibration_metrics(self.threat_type_calibration[threat_type])
    
    def get_severity_calibration(self, severity: str) -> Optional[CalibrationResults]:
        """
        Get calibration metrics for specific severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            CalibrationResults for the severity level or None
        """
        if severity not in self.severity_calibration:
            return None
        
        return self.compute_calibration_metrics(self.severity_calibration[severity])
    
    def evaluate_calibration_quality(self) -> Dict[str, Any]:
        """
        Evaluate overall calibration quality with recommendations.
        
        Returns:
            Dictionary with quality assessment and recommendations
        """
        results = self.compute_calibration_metrics()
        
        # Quality thresholds
        excellent_ece = 0.05
        good_ece = 0.10
        poor_ece = 0.20
        
        excellent_brier = 0.10
        good_brier = 0.20
        poor_brier = 0.30
        
        # Assess calibration quality
        if results.expected_calibration_error <= excellent_ece:
            ece_quality = "excellent"
        elif results.expected_calibration_error <= good_ece:
            ece_quality = "good"
        elif results.expected_calibration_error <= poor_ece:
            ece_quality = "fair"
        else:
            ece_quality = "poor"
        
        if results.brier_score <= excellent_brier:
            brier_quality = "excellent"
        elif results.brier_score <= good_brier:
            brier_quality = "good"
        elif results.brier_score <= poor_brier:
            brier_quality = "fair"
        else:
            brier_quality = "poor"
        
        # Generate recommendations
        recommendations = []
        
        if results.expected_calibration_error > good_ece:
            recommendations.append("Consider recalibrating the model - ECE is above acceptable threshold")
        
        if results.brier_score > good_brier:
            recommendations.append("Model accuracy could be improved - Brier score is suboptimal")
        
        if results.sample_count < 100:
            recommendations.append("Collect more calibration data for more reliable metrics")
        
        # Check bin distribution
        populated_bins = sum(1 for bin in results.bins if bin.count >= self.min_samples_per_bin)
        if populated_bins < 5:
            recommendations.append("Need more diverse probability predictions across confidence ranges")
        
        return {
            "overall_quality": min(ece_quality, brier_quality, key=lambda x: ["excellent", "good", "fair", "poor"].index(x)),
            "ece_quality": ece_quality,
            "brier_quality": brier_quality,
            "metrics": results.to_dict(),
            "recommendations": recommendations,
            "calibration_curve_available": self.adjustment_function is not None,
            "evaluation_timestamp": datetime.now().isoformat()
        }
    
    def export_calibration_data(self, format_type: str = "json") -> str:
        """
        Export calibration data in specified format.
        
        Args:
            format_type: Export format (json, csv)
            
        Returns:
            Formatted calibration data
        """
        if format_type.lower() == "json":
            data = {
                "calibration_points": [point.to_dict() for point in self.calibration_data],
                "calibration_curve": self.calibration_curve,
                "metrics": self.compute_calibration_metrics().to_dict(),
                "export_timestamp": datetime.now().isoformat()
            }
            return json.dumps(data, indent=2, default=str)
        
        elif format_type.lower() == "csv":
            lines = ["predicted_probability,actual_outcome,timestamp,threat_type,severity"]
            
            for point in self.calibration_data:
                threat_type = point.metadata.get("threat_type", "")
                severity = point.metadata.get("severity", "")
                lines.append(f"{point.predicted_probability},{point.actual_outcome},{point.timestamp.isoformat()},{threat_type},{severity}")
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def reset_calibration_data(self) -> None:
        """Reset all calibration data"""
        self.calibration_data.clear()
        self.threat_type_calibration.clear()
        self.severity_calibration.clear()
        self.calibration_curve = None
        self.adjustment_function = None
        self.performance_history.clear()
    
    def get_calibration_summary(self) -> Dict[str, Any]:
        """
        Get summary of calibration status.
        
        Returns:
            Dictionary with calibration summary
        """
        return {
            "total_samples": len(self.calibration_data),
            "threat_types_tracked": len(self.threat_type_calibration),
            "severity_levels_tracked": len(self.severity_calibration),
            "calibration_curve_built": self.calibration_curve is not None,
            "adjustment_function_available": self.adjustment_function is not None,
            "last_point_timestamp": self.calibration_data[-1].timestamp.isoformat() if self.calibration_data else None,
            "metrics": self.compute_calibration_metrics().to_dict() if self.calibration_data else None
        }