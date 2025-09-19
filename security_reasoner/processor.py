"""
Processor Module

Main security event processor that orchestrates all components of the security reasoner.
Provides high-level processing capabilities with integration of sanitization, validation,
calibration, queueing, and metrics collection.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Union
import asyncio
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from collections import defaultdict

from .event_schema import SecurityEvent, EventSchema, EventType, SeverityLevel
from .config import SecurityConfig
from .metrics import SecurityMetrics
from .logging_config import get_security_logger, SecurityLoggerAdapter
from .calibration import SecurityCalibrator
from .queueing import SecurityQueue, QueuePriority
from .sanitizer import SecuritySanitizer


@dataclass
class ProcessingResult:
    """Result of security event processing"""
    event_id: str
    threat_level: str
    confidence: float
    processing_time: float
    timestamp: datetime
    sanitized_data: Dict[str, Any]
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "event_id": self.event_id,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "processing_time": self.processing_time,
            "timestamp": self.timestamp.isoformat(),
            "sanitized_data": self.sanitized_data,
            "validation_errors": self.validation_errors,
            "warnings": self.warnings,
            "metadata": self.metadata
        }


@dataclass
class BatchProcessingResult:
    """Result of batch processing operation"""
    batch_id: str
    processed_count: int
    failed_count: int
    total_processing_time: float
    individual_results: List[ProcessingResult]
    batch_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "batch_id": self.batch_id,
            "processed_count": self.processed_count,
            "failed_count": self.failed_count,
            "total_processing_time": self.total_processing_time,
            "individual_results": [result.to_dict() for result in self.individual_results],
            "batch_metadata": self.batch_metadata
        }


class SecurityProcessor:
    """
    Main security event processor integrating all security reasoner components.
    
    Provides comprehensive security event processing with sanitization, validation,
    threat detection, calibration, and metrics collection.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Initialize security processor.
        
        Args:
            config: Security configuration, uses defaults if None
        """
        self.config = config or SecurityConfig()
        
        # Initialize components
        self.sanitizer = SecuritySanitizer()
        self.calibrator = SecurityCalibrator()
        self.metrics = SecurityMetrics(retention_period=self.config.metrics.retention_period)
        self.queue = SecurityQueue(
            max_size=self.config.processing.max_queue_size,
            num_workers=self.config.processing.max_workers,
            batch_size=self.config.processing.batch_size
        )
        
        # Setup logging
        self.logger = get_security_logger()
        
        # Processing state
        self.is_running = False
        self.processor_id = str(uuid.uuid4())
        self.start_time: Optional[datetime] = None
        
        # Custom processors
        self.custom_processors: Dict[str, Callable] = {}
        self.threat_detectors: Dict[str, Callable] = {}
        self.result_handlers: Dict[str, Callable] = {}
        
        # Processing statistics
        self.events_processed = 0
        self.events_failed = 0
        self.last_processing_time = 0.0
        
        # Thread pool for async operations
        self.thread_pool = ThreadPoolExecutor(max_workers=self.config.processing.max_workers)
        
        # Setup queue processor
        self.queue.set_processor(self._process_single_event)
        self.queue.set_batch_processor(self._process_event_batch)
        self.queue.set_error_handler(self._handle_processing_error)
        
        # Initialize default threat detectors
        self._setup_default_threat_detectors()
    
    def start(self) -> None:
        """Start the security processor"""
        if self.is_running:
            self.logger.warning("Processor already running")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        
        # Start queue processing
        self.queue.start()
        
        self.logger.info(
            "Security processor started",
            extra={
                "processor_id": self.processor_id,
                "config": self.config.to_dict()
            }
        )
    
    def stop(self, timeout: float = 30.0) -> None:
        """
        Stop the security processor.
        
        Args:
            timeout: Maximum time to wait for shutdown
        """
        if not self.is_running:
            return
        
        self.logger.info("Stopping security processor", extra={"processor_id": self.processor_id})
        
        # Stop queue processing
        self.queue.stop(timeout=timeout)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True, timeout=timeout)
        
        self.is_running = False
        
        self.logger.info(
            "Security processor stopped",
            extra={
                "processor_id": self.processor_id,
                "events_processed": self.events_processed,
                "uptime_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            }
        )
    
    def process_event(self, 
                     event_data: Dict[str, Any], 
                     priority: QueuePriority = QueuePriority.NORMAL,
                     callback: Optional[Callable] = None) -> str:
        """
        Queue a security event for processing.
        
        Args:
            event_data: Raw event data
            priority: Processing priority
            callback: Optional completion callback
            
        Returns:
            Event ID for tracking
        """
        if not self.is_running:
            raise RuntimeError("Processor is not running")
        
        # Generate event ID if not provided
        event_id = event_data.get('event_id', str(uuid.uuid4()))
        event_data['event_id'] = event_id
        
        # Queue for processing
        item_id = self.queue.enqueue(
            data=event_data,
            priority=priority,
            callback=callback,
            metadata={'event_id': event_id}
        )
        
        self.logger.debug(
            "Event queued for processing",
            extra={
                "event_id": event_id,
                "item_id": item_id,
                "priority": priority.name
            }
        )
        
        return event_id
    
    def process_event_sync(self, event_data: Dict[str, Any]) -> ProcessingResult:
        """
        Process a security event synchronously.
        
        Args:
            event_data: Raw event data
            
        Returns:
            ProcessingResult with processing outcome
        """
        start_time = time.time()
        
        try:
            result = self._process_single_event(event_data)
            processing_time = time.time() - start_time
            
            # Update metrics
            self.metrics.record_event_processed(processing_time, success=True)
            
            return result
            
        except Exception as e:
            processing_time = time.time() - start_time
            self.metrics.record_event_processed(processing_time, success=False)
            self.metrics.record_error("processing_error", "error")
            
            self.logger.log_error(
                f"Synchronous event processing failed: {str(e)}",
                error=e,
                extra={"event_data": event_data}
            )
            
            raise
    
    def process_batch(self, 
                     events: List[Dict[str, Any]],
                     priority: QueuePriority = QueuePriority.NORMAL) -> str:
        """
        Process a batch of events.
        
        Args:
            events: List of event data dictionaries
            priority: Processing priority for the batch
            
        Returns:
            Batch ID for tracking
        """
        if not self.is_running:
            raise RuntimeError("Processor is not running")
        
        batch_id = str(uuid.uuid4())
        
        # Queue all events with batch metadata
        item_ids = []
        for event_data in events:
            event_id = event_data.get('event_id', str(uuid.uuid4()))
            event_data['event_id'] = event_id
            
            item_id = self.queue.enqueue(
                data=event_data,
                priority=priority,
                metadata={'event_id': event_id, 'batch_id': batch_id}
            )
            item_ids.append(item_id)
        
        self.logger.info(
            "Batch queued for processing",
            extra={
                "batch_id": batch_id,
                "event_count": len(events),
                "priority": priority.name
            }
        )
        
        return batch_id
    
    def _process_single_event(self, event_data: Dict[str, Any]) -> ProcessingResult:
        """Process a single security event"""
        start_time = time.time()
        event_id = event_data.get('event_id', str(uuid.uuid4()))
        
        try:
            # Step 1: Sanitize input data
            sanitization_result = self.sanitizer.sanitize_data(event_data)
            sanitized_data = sanitization_result.sanitized_value
            
            # Step 2: Validate event schema
            if not EventSchema.validate_event(sanitized_data):
                sanitized_data = EventSchema.normalize_event(sanitized_data)
            
            # Step 3: Create security event object
            try:
                security_event = SecurityEvent.from_dict(sanitized_data)
            except Exception:
                # Fallback to normalized data
                sanitized_data = EventSchema.transform_legacy_event(sanitized_data)
                security_event = SecurityEvent.from_dict(sanitized_data)
            
            # Step 4: Threat detection
            threat_level, confidence = self._detect_threats(security_event)
            
            # Step 5: Calibrate confidence
            calibrated_confidence = self.calibrator.adjust_probability(confidence)
            
            # Step 6: Apply reasoning thresholds
            final_threat_level = self._apply_threat_thresholds(threat_level, calibrated_confidence)
            
            processing_time = time.time() - start_time
            
            # Create result
            result = ProcessingResult(
                event_id=event_id,
                threat_level=final_threat_level,
                confidence=calibrated_confidence,
                processing_time=processing_time,
                timestamp=datetime.now(),
                sanitized_data=sanitized_data,
                validation_errors=sanitization_result.errors,
                warnings=sanitization_result.warnings,
                metadata={
                    "original_threat_level": threat_level,
                    "original_confidence": confidence,
                    "rules_applied": sanitization_result.rules_applied
                }
            )
            
            # Update calibration data
            actual_threat = self._determine_actual_threat(security_event)
            if actual_threat is not None:
                self.calibrator.add_calibration_point(
                    predicted_prob=confidence,
                    actual_outcome=actual_threat,
                    threat_type=security_event.event_type.value,
                    severity=security_event.severity.value
                )
            
            # Record metrics
            self.metrics.record_threat_detection(
                detected=final_threat_level != "ignore",
                actual=actual_threat or False,
                confidence=calibrated_confidence,
                detection_time=processing_time
            )
            
            self.events_processed += 1
            self.last_processing_time = processing_time
            
            self.logger.log_security_event(
                level=40 if final_threat_level in ["high", "critical"] else 20,  # WARNING or INFO
                msg=f"Security event processed: {final_threat_level}",
                event_id=event_id,
                threat_level=final_threat_level,
                extra={
                    "confidence": calibrated_confidence,
                    "processing_time": processing_time,
                    "event_type": security_event.event_type.value
                }
            )
            
            return result
            
        except Exception as e:
            processing_time = time.time() - start_time
            self.events_failed += 1
            
            self.logger.log_error(
                f"Event processing failed: {str(e)}",
                error=e,
                extra={"event_id": event_id, "event_data": event_data}
            )
            
            # Return error result
            return ProcessingResult(
                event_id=event_id,
                threat_level="ignore",
                confidence=0.0,
                processing_time=processing_time,
                timestamp=datetime.now(),
                sanitized_data={},
                validation_errors=[str(e)],
                warnings=[],
                metadata={"processing_failed": True}
            )
    
    def _process_event_batch(self, batch_data: List[Dict[str, Any]]) -> List[ProcessingResult]:
        """Process a batch of events"""
        batch_id = str(uuid.uuid4())
        start_time = time.time()
        
        results = []
        for event_data in batch_data:
            try:
                result = self._process_single_event(event_data)
                results.append(result)
            except Exception as e:
                # Create error result for failed event
                event_id = event_data.get('event_id', str(uuid.uuid4()))
                error_result = ProcessingResult(
                    event_id=event_id,
                    threat_level="ignore",
                    confidence=0.0,
                    processing_time=0.0,
                    timestamp=datetime.now(),
                    sanitized_data={},
                    validation_errors=[str(e)],
                    warnings=[],
                    metadata={"batch_processing_failed": True}
                )
                results.append(error_result)
        
        batch_processing_time = time.time() - start_time
        
        self.logger.info(
            "Batch processing completed",
            extra={
                "batch_id": batch_id,
                "event_count": len(batch_data),
                "processing_time": batch_processing_time
            }
        )
        
        return results
    
    def _detect_threats(self, event: SecurityEvent) -> tuple[str, float]:
        """
        Detect threats in security event.
        
        Args:
            event: Security event to analyze
            
        Returns:
            Tuple of (threat_level, confidence)
        """
        threat_scores = {}
        
        # Run all threat detectors
        for detector_name, detector in self.threat_detectors.items():
            try:
                score = detector(event)
                threat_scores[detector_name] = score
            except Exception as e:
                self.logger.warning(
                    f"Threat detector {detector_name} failed: {str(e)}",
                    extra={"event_id": event.event_id, "detector": detector_name}
                )
        
        # Aggregate scores
        if not threat_scores:
            return "ignore", 0.0
        
        # Use maximum score for threat level determination
        max_score = max(threat_scores.values())
        
        # Map score to threat level
        if max_score >= self.config.thresholds.critical_threshold:
            threat_level = "critical"
        elif max_score >= self.config.thresholds.high_threshold:
            threat_level = "high"
        elif max_score >= self.config.thresholds.medium_threshold:
            threat_level = "medium"
        elif max_score >= self.config.thresholds.low_threshold:
            threat_level = "low"
        else:
            threat_level = "ignore"
        
        return threat_level, max_score
    
    def _apply_threat_thresholds(self, threat_level: str, confidence: float) -> str:
        """Apply configuration thresholds to threat level"""
        
        # Check minimum confidence requirements
        if confidence < self.config.thresholds.confidence_threshold:
            if threat_level in ["high", "critical"]:
                return "medium"  # Downgrade high-severity with low confidence
            elif threat_level == "medium":
                return "low"
        
        return threat_level
    
    def _determine_actual_threat(self, event: SecurityEvent) -> Optional[bool]:
        """
        Determine if event represents actual threat (for calibration).
        This is a placeholder - in real implementation, this would use
        ground truth data or feedback mechanisms.
        """
        # Placeholder implementation - would be replaced with actual logic
        if event.event_type in [EventType.MALWARE, EventType.BREACH]:
            return True
        elif event.event_type in [EventType.ANOMALY, EventType.SUSPICIOUS_ACTIVITY]:
            return event.confidence_score > 0.8
        return None
    
    def _setup_default_threat_detectors(self) -> None:
        """Setup default threat detection algorithms"""
        
        def detect_malware_indicators(event: SecurityEvent) -> float:
            """Detect malware indicators"""
            score = 0.0
            
            if event.event_type == EventType.MALWARE:
                score += 0.8
            
            if event.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                score += 0.3
            
            # Check for suspicious metadata
            suspicious_patterns = ['trojan', 'virus', 'malware', 'backdoor', 'rootkit']
            description_lower = event.description.lower()
            
            for pattern in suspicious_patterns:
                if pattern in description_lower:
                    score += 0.4
                    break
            
            return min(1.0, score)
        
        def detect_network_anomalies(event: SecurityEvent) -> float:
            """Detect network-based anomalies"""
            score = 0.0
            
            if event.event_type in [EventType.INTRUSION, EventType.UNAUTHORIZED_ACCESS]:
                score += 0.7
            
            # Check for suspicious IP patterns
            if event.source_ip and event.destination_ip:
                if event.source_ip == event.destination_ip:
                    score += 0.2  # Self-communication can be suspicious
            
            return min(1.0, score)
        
        def detect_behavioral_anomalies(event: SecurityEvent) -> float:
            """Detect behavioral anomalies"""
            score = 0.0
            
            if event.event_type == EventType.ANOMALY:
                score += event.confidence_score * 0.8
            
            if event.event_type == EventType.SUSPICIOUS_ACTIVITY:
                score += 0.6
            
            return min(1.0, score)
        
        # Register default detectors
        self.threat_detectors.update({
            "malware_detector": detect_malware_indicators,
            "network_anomaly_detector": detect_network_anomalies,
            "behavioral_anomaly_detector": detect_behavioral_anomalies
        })
    
    def _handle_processing_error(self, error: Exception, item) -> None:
        """Handle processing errors"""
        self.metrics.record_error("processing_error", "error")
        
        self.logger.log_error(
            f"Processing error: {str(error)}",
            error=error,
            extra={"item": str(item) if item else None}
        )
    
    def add_threat_detector(self, name: str, detector: Callable[[SecurityEvent], float]) -> None:
        """
        Add custom threat detector.
        
        Args:
            name: Detector name
            detector: Function that takes SecurityEvent and returns threat score (0-1)
        """
        self.threat_detectors[name] = detector
        self.logger.info(f"Added threat detector: {name}")
    
    def remove_threat_detector(self, name: str) -> bool:
        """
        Remove threat detector.
        
        Args:
            name: Detector name
            
        Returns:
            True if detector was removed, False if not found
        """
        if name in self.threat_detectors:
            del self.threat_detectors[name]
            self.logger.info(f"Removed threat detector: {name}")
            return True
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive processor status"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            "processor_id": self.processor_id,
            "is_running": self.is_running,
            "uptime_seconds": uptime,
            "events_processed": self.events_processed,
            "events_failed": self.events_failed,
            "last_processing_time": self.last_processing_time,
            "queue_status": self.queue.get_status(),
            "metrics": self.metrics.get_all_metrics(),
            "calibration": self.calibrator.get_calibration_summary(),
            "threat_detectors": list(self.threat_detectors.keys()),
            "config": self.config.to_dict()
        }
    
    def get_processing_metrics(self) -> Dict[str, Any]:
        """Get processing performance metrics"""
        return {
            "performance": self.metrics.get_performance_metrics(),
            "accuracy": self.metrics.get_accuracy_metrics(),
            "queue_metrics": self.queue.get_status(),
            "calibration_quality": self.calibrator.evaluate_calibration_quality()
        }
    
    def export_data(self, format_type: str = "json") -> str:
        """
        Export processor data and metrics.
        
        Args:
            format_type: Export format (json, csv)
            
        Returns:
            Formatted data string
        """
        data = {
            "processor_status": self.get_status(),
            "metrics": self.metrics.export_metrics(format_type),
            "calibration_data": self.calibrator.export_calibration_data(format_type),
            "export_timestamp": datetime.now().isoformat()
        }
        
        if format_type.lower() == "json":
            import json
            return json.dumps(data, indent=2, default=str)
        else:
            # For CSV, return status summary
            return f"processor_id,is_running,events_processed,events_failed,uptime_seconds\n{self.processor_id},{self.is_running},{self.events_processed},{self.events_failed},{(datetime.now() - self.start_time).total_seconds() if self.start_time else 0}"
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of all components"""
        health_status = {
            "overall_status": "healthy",
            "components": {},
            "issues": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Check processor status
        if not self.is_running:
            health_status["components"]["processor"] = "stopped"
            health_status["issues"].append("Processor is not running")
            health_status["overall_status"] = "unhealthy"
        else:
            health_status["components"]["processor"] = "running"
        
        # Check queue status
        queue_status = self.queue.get_status()
        if queue_status["status"] in ["active", "paused"]:
            health_status["components"]["queue"] = "healthy"
        else:
            health_status["components"]["queue"] = "unhealthy"
            health_status["issues"].append(f"Queue status: {queue_status['status']}")
            health_status["overall_status"] = "degraded"
        
        # Check calibration quality
        calibration_quality = self.calibrator.evaluate_calibration_quality()
        if calibration_quality["overall_quality"] in ["excellent", "good"]:
            health_status["components"]["calibration"] = "healthy"
        else:
            health_status["components"]["calibration"] = "degraded"
            health_status["issues"].extend(calibration_quality["recommendations"])
            if health_status["overall_status"] == "healthy":
                health_status["overall_status"] = "degraded"
        
        # Check metrics collection
        if self.metrics.get_counter("events_processed") >= 0:
            health_status["components"]["metrics"] = "healthy"
        else:
            health_status["components"]["metrics"] = "unhealthy"
            health_status["issues"].append("Metrics collection issue")
            health_status["overall_status"] = "degraded"
        
        return health_status
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()