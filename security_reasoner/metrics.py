"""
Metrics Module

Comprehensive metrics collection and tracking for the security reasoner system.
Tracks performance, accuracy, latency, and security-specific metrics.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from threading import Lock
import time
import statistics
import json


@dataclass
class MetricValue:
    """Individual metric value with timestamp"""
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags
        }


@dataclass
class MetricSummary:
    """Statistical summary of metric values"""
    count: int
    mean: float
    median: float
    min_value: float
    max_value: float
    std_dev: float
    percentile_95: float
    percentile_99: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "count": self.count,
            "mean": self.mean,
            "median": self.median,
            "min": self.min_value,
            "max": self.max_value,
            "std_dev": self.std_dev,
            "p95": self.percentile_95,
            "p99": self.percentile_99
        }


class SecurityMetrics:
    """
    Comprehensive metrics tracking system for security operations.
    
    Collects, aggregates, and provides access to various performance
    and security metrics with thread-safe operations.
    """
    
    def __init__(self, retention_period: int = 7 * 24 * 3600):
        """
        Initialize metrics system.
        
        Args:
            retention_period: How long to keep metrics in seconds (default: 7 days)
        """
        self.retention_period = retention_period
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque())
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._custom_metrics: Dict[str, Any] = {}
        self._lock = Lock()
        
        # Performance metrics
        self.start_time = datetime.now()
        self._events_processed = 0
        self._errors_count = 0
        self._warnings_count = 0
        
        # Security-specific metrics
        self._threats_detected = 0
        self._false_positives = 0
        self._false_negatives = 0
        self._true_positives = 0
        self._true_negatives = 0
        
        # Latency tracking
        self._processing_latencies = deque(maxlen=1000)
        self._detection_latencies = deque(maxlen=1000)
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a metric value with optional tags.
        
        Args:
            name: Metric name
            value: Metric value
            tags: Optional tags for categorization
        """
        with self._lock:
            metric_value = MetricValue(
                value=value,
                timestamp=datetime.now(),
                tags=tags or {}
            )
            self._metrics[name].append(metric_value)
            self._cleanup_old_metrics()
    
    def increment_counter(self, name: str, amount: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Increment a counter metric.
        
        Args:
            name: Counter name
            amount: Amount to increment by
            tags: Optional tags for categorization
        """
        with self._lock:
            self._counters[name] += amount
            self.record_metric(f"{name}_total", self._counters[name], tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Set a gauge metric value.
        
        Args:
            name: Gauge name
            value: Current value
            tags: Optional tags for categorization
        """
        with self._lock:
            self._gauges[name] = value
            self.record_metric(name, value, tags)
    
    def record_timer(self, name: str, duration: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a timing measurement.
        
        Args:
            name: Timer name
            duration: Duration in seconds
            tags: Optional tags for categorization
        """
        with self._lock:
            self._timers[name].append(duration)
            self.record_metric(f"{name}_duration", duration, tags)
    
    def time_function(self, name: str, tags: Optional[Dict[str, str]] = None) -> Callable:
        """
        Decorator to time function execution.
        
        Args:
            name: Timer name
            tags: Optional tags for categorization
            
        Returns:
            Decorator function
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time
                    self.record_timer(name, duration, tags)
            return wrapper
        return decorator
    
    def record_event_processed(self, processing_time: float, success: bool = True) -> None:
        """
        Record a processed event with timing.
        
        Args:
            processing_time: Time taken to process event
            success: Whether processing was successful
        """
        with self._lock:
            self._events_processed += 1
            self._processing_latencies.append(processing_time)
            
            if success:
                self.increment_counter("events_processed_success")
            else:
                self.increment_counter("events_processed_error")
                self._errors_count += 1
            
            self.record_timer("event_processing", processing_time)
    
    def record_threat_detection(self, detected: bool, actual: bool, confidence: float, detection_time: float) -> None:
        """
        Record threat detection results for accuracy tracking.
        
        Args:
            detected: Whether threat was detected
            actual: Whether threat was actually present
            confidence: Detection confidence score
            detection_time: Time taken for detection
        """
        with self._lock:
            self._detection_latencies.append(detection_time)
            
            if detected and actual:
                self._true_positives += 1
                self.increment_counter("true_positives")
            elif detected and not actual:
                self._false_positives += 1
                self.increment_counter("false_positives")
            elif not detected and actual:
                self._false_negatives += 1
                self.increment_counter("false_negatives")
            else:
                self._true_negatives += 1
                self.increment_counter("true_negatives")
            
            if detected:
                self._threats_detected += 1
                self.increment_counter("threats_detected")
            
            self.record_metric("detection_confidence", confidence)
            self.record_timer("threat_detection", detection_time)
    
    def record_error(self, error_type: str, severity: str = "error") -> None:
        """
        Record an error occurrence.
        
        Args:
            error_type: Type of error
            severity: Error severity (error, warning, critical)
        """
        with self._lock:
            if severity == "warning":
                self._warnings_count += 1
            else:
                self._errors_count += 1
            
            self.increment_counter(f"errors_{error_type}")
            self.increment_counter(f"errors_by_severity_{severity}")
    
    def get_metric_summary(self, name: str, time_range: Optional[timedelta] = None) -> Optional[MetricSummary]:
        """
        Get statistical summary for a metric.
        
        Args:
            name: Metric name
            time_range: Optional time range to filter metrics
            
        Returns:
            MetricSummary or None if no data
        """
        with self._lock:
            if name not in self._metrics or not self._metrics[name]:
                return None
            
            cutoff_time = None
            if time_range:
                cutoff_time = datetime.now() - time_range
            
            values = []
            for metric_value in self._metrics[name]:
                if cutoff_time is None or metric_value.timestamp >= cutoff_time:
                    values.append(metric_value.value)
            
            if not values:
                return None
            
            values.sort()
            count = len(values)
            
            return MetricSummary(
                count=count,
                mean=statistics.mean(values),
                median=statistics.median(values),
                min_value=min(values),
                max_value=max(values),
                std_dev=statistics.stdev(values) if count > 1 else 0.0,
                percentile_95=values[int(0.95 * count)] if count > 0 else 0.0,
                percentile_99=values[int(0.99 * count)] if count > 0 else 0.0
            )
    
    def get_accuracy_metrics(self) -> Dict[str, float]:
        """
        Calculate accuracy metrics for threat detection.
        
        Returns:
            Dictionary with accuracy, precision, recall, F1 score
        """
        with self._lock:
            tp = self._true_positives
            fp = self._false_positives
            fn = self._false_negatives
            tn = self._true_negatives
            
            total = tp + fp + fn + tn
            if total == 0:
                return {
                    "accuracy": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                    "specificity": 0.0
                }
            
            accuracy = (tp + tn) / total
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            
            return {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1_score,
                "specificity": specificity
            }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get overall performance metrics.
        
        Returns:
            Dictionary with performance statistics
        """
        with self._lock:
            uptime = datetime.now() - self.start_time
            
            avg_processing_latency = 0.0
            avg_detection_latency = 0.0
            
            if self._processing_latencies:
                avg_processing_latency = statistics.mean(self._processing_latencies)
            
            if self._detection_latencies:
                avg_detection_latency = statistics.mean(self._detection_latencies)
            
            events_per_second = self._events_processed / uptime.total_seconds() if uptime.total_seconds() > 0 else 0.0
            error_rate = self._errors_count / self._events_processed if self._events_processed > 0 else 0.0
            
            return {
                "uptime_seconds": uptime.total_seconds(),
                "events_processed": self._events_processed,
                "events_per_second": events_per_second,
                "error_count": self._errors_count,
                "warning_count": self._warnings_count,
                "error_rate": error_rate,
                "avg_processing_latency": avg_processing_latency,
                "avg_detection_latency": avg_detection_latency,
                "threats_detected": self._threats_detected
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all metrics in a comprehensive report.
        
        Returns:
            Dictionary with all metric categories
        """
        return {
            "performance": self.get_performance_metrics(),
            "accuracy": self.get_accuracy_metrics(),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "custom": self._custom_metrics.copy(),
            "timestamp": datetime.now().isoformat()
        }
    
    def export_metrics(self, format_type: str = "json") -> str:
        """
        Export metrics in specified format.
        
        Args:
            format_type: Export format (json, csv)
            
        Returns:
            Formatted metrics string
        """
        metrics_data = self.get_all_metrics()
        
        if format_type.lower() == "json":
            return json.dumps(metrics_data, indent=2, default=str)
        elif format_type.lower() == "csv":
            # Simple CSV export for counters and gauges
            lines = ["metric_name,metric_type,value,timestamp"]
            timestamp = datetime.now().isoformat()
            
            for name, value in metrics_data["counters"].items():
                lines.append(f"{name},counter,{value},{timestamp}")
            
            for name, value in metrics_data["gauges"].items():
                lines.append(f"{name},gauge,{value},{timestamp}")
            
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def reset_metrics(self) -> None:
        """Reset all metrics to initial state"""
        with self._lock:
            self._metrics.clear()
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()
            self._custom_metrics.clear()
            
            self.start_time = datetime.now()
            self._events_processed = 0
            self._errors_count = 0
            self._warnings_count = 0
            self._threats_detected = 0
            self._false_positives = 0
            self._false_negatives = 0
            self._true_positives = 0
            self._true_negatives = 0
            
            self._processing_latencies.clear()
            self._detection_latencies.clear()
    
    def _cleanup_old_metrics(self) -> None:
        """Remove metrics older than retention period"""
        cutoff_time = datetime.now() - timedelta(seconds=self.retention_period)
        
        for name, metric_queue in self._metrics.items():
            while metric_queue and metric_queue[0].timestamp < cutoff_time:
                metric_queue.popleft()
    
    def set_custom_metric(self, name: str, value: Any) -> None:
        """
        Set a custom metric value.
        
        Args:
            name: Metric name
            value: Metric value (any type)
        """
        with self._lock:
            self._custom_metrics[name] = value
    
    def get_custom_metric(self, name: str) -> Any:
        """
        Get a custom metric value.
        
        Args:
            name: Metric name
            
        Returns:
            Metric value or None if not found
        """
        with self._lock:
            return self._custom_metrics.get(name)
    
    def get_counter(self, name: str) -> int:
        """Get current counter value"""
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_gauge(self, name: str) -> float:
        """Get current gauge value"""
        with self._lock:
            return self._gauges.get(name, 0.0)