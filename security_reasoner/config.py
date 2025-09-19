"""
Configuration Module

Manages configuration settings for the security reasoner system,
including threat thresholds, processing parameters, and system settings.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json
import os
from pathlib import Path


@dataclass
class ThreatThresholds:
    """Threat detection thresholds configuration"""
    low_threshold: float = 0.3
    medium_threshold: float = 0.6
    high_threshold: float = 0.8
    critical_threshold: float = 0.9
    confidence_threshold: float = 0.5
    
    def validate(self) -> bool:
        """Validate threshold values are in correct order"""
        thresholds = [
            self.low_threshold,
            self.medium_threshold, 
            self.high_threshold,
            self.critical_threshold
        ]
        return all(0 <= t <= 1 for t in thresholds) and thresholds == sorted(thresholds)


@dataclass
class ProcessingConfig:
    """Event processing configuration"""
    batch_size: int = 100
    max_queue_size: int = 10000
    processing_timeout: float = 30.0
    retry_attempts: int = 3
    retry_delay: float = 1.0
    enable_parallel_processing: bool = True
    max_workers: int = 4
    memory_limit_mb: int = 1024
    
    def validate(self) -> bool:
        """Validate processing configuration values"""
        return (
            self.batch_size > 0 and
            self.max_queue_size > 0 and
            self.processing_timeout > 0 and
            self.retry_attempts >= 0 and
            self.retry_delay >= 0 and
            self.max_workers > 0 and
            self.memory_limit_mb > 0
        )


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = False
    enable_structured: bool = True
    
    def validate(self) -> bool:
        """Validate logging configuration"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        return (
            self.level.upper() in valid_levels and
            self.max_file_size > 0 and
            self.backup_count >= 0
        )


@dataclass
class MetricsConfig:
    """Metrics collection configuration"""
    enabled: bool = True
    collection_interval: float = 60.0  # seconds
    retention_period: int = 7 * 24 * 3600  # 7 days in seconds
    export_format: str = "json"
    export_path: Optional[str] = None
    track_performance: bool = True
    track_accuracy: bool = True
    track_latency: bool = True
    
    def validate(self) -> bool:
        """Validate metrics configuration"""
        valid_formats = ["json", "csv", "prometheus"]
        return (
            self.collection_interval > 0 and
            self.retention_period > 0 and
            self.export_format.lower() in valid_formats
        )


@dataclass
class SecurityConfig:
    """
    Main configuration class for the security reasoner system.
    
    Combines all configuration aspects including thresholds, processing,
    logging, and metrics settings.
    """
    thresholds: ThreatThresholds = field(default_factory=ThreatThresholds)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    
    # Additional system settings
    debug_mode: bool = False
    strict_validation: bool = True
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour
    api_timeout: float = 10.0
    max_concurrent_requests: int = 100
    
    # Feature flags
    features: Dict[str, bool] = field(default_factory=lambda: {
        "advanced_analytics": True,
        "real_time_processing": True,
        "machine_learning": True,
        "behavioral_analysis": True,
        "threat_intelligence": True
    })
    
    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    
    def validate(self) -> bool:
        """
        Validate all configuration settings.
        
        Returns:
            bool: True if all settings are valid, False otherwise
        """
        return (
            self.thresholds.validate() and
            self.processing.validate() and
            self.logging.validate() and
            self.metrics.validate() and
            self.api_timeout > 0 and
            self.max_concurrent_requests > 0 and
            self.cache_ttl > 0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "thresholds": {
                "low_threshold": self.thresholds.low_threshold,
                "medium_threshold": self.thresholds.medium_threshold,
                "high_threshold": self.thresholds.high_threshold,
                "critical_threshold": self.thresholds.critical_threshold,
                "confidence_threshold": self.thresholds.confidence_threshold
            },
            "processing": {
                "batch_size": self.processing.batch_size,
                "max_queue_size": self.processing.max_queue_size,
                "processing_timeout": self.processing.processing_timeout,
                "retry_attempts": self.processing.retry_attempts,
                "retry_delay": self.processing.retry_delay,
                "enable_parallel_processing": self.processing.enable_parallel_processing,
                "max_workers": self.processing.max_workers,
                "memory_limit_mb": self.processing.memory_limit_mb
            },
            "logging": {
                "level": self.logging.level,
                "format": self.logging.format,
                "file_path": self.logging.file_path,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count,
                "enable_console": self.logging.enable_console,
                "enable_file": self.logging.enable_file,
                "enable_structured": self.logging.enable_structured
            },
            "metrics": {
                "enabled": self.metrics.enabled,
                "collection_interval": self.metrics.collection_interval,
                "retention_period": self.metrics.retention_period,
                "export_format": self.metrics.export_format,
                "export_path": self.metrics.export_path,
                "track_performance": self.metrics.track_performance,
                "track_accuracy": self.metrics.track_accuracy,
                "track_latency": self.metrics.track_latency
            },
            "debug_mode": self.debug_mode,
            "strict_validation": self.strict_validation,
            "enable_caching": self.enable_caching,
            "cache_ttl": self.cache_ttl,
            "api_timeout": self.api_timeout,
            "max_concurrent_requests": self.max_concurrent_requests,
            "features": self.features,
            "custom_settings": self.custom_settings
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityConfig:
        """Create SecurityConfig from dictionary"""
        config = cls()
        
        # Update thresholds
        if "thresholds" in data:
            threshold_data = data["thresholds"]
            config.thresholds = ThreatThresholds(**threshold_data)
        
        # Update processing config
        if "processing" in data:
            processing_data = data["processing"]
            config.processing = ProcessingConfig(**processing_data)
        
        # Update logging config
        if "logging" in data:
            logging_data = data["logging"]
            config.logging = LoggingConfig(**logging_data)
        
        # Update metrics config
        if "metrics" in data:
            metrics_data = data["metrics"]
            config.metrics = MetricsConfig(**metrics_data)
        
        # Update other settings
        for key in ["debug_mode", "strict_validation", "enable_caching", 
                   "cache_ttl", "api_timeout", "max_concurrent_requests"]:
            if key in data:
                setattr(config, key, data[key])
        
        # Update features and custom settings
        if "features" in data:
            config.features.update(data["features"])
        if "custom_settings" in data:
            config.custom_settings.update(data["custom_settings"])
        
        return config
    
    def save_to_file(self, file_path: str) -> None:
        """Save configuration to JSON file"""
        config_dict = self.to_dict()
        with open(file_path, 'w') as f:
            json.dump(config_dict, f, indent=2)
    
    @classmethod
    def load_from_file(cls, file_path: str) -> SecurityConfig:
        """Load configuration from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    @classmethod
    def load_from_env(cls) -> SecurityConfig:
        """Load configuration from environment variables"""
        config = cls()
        
        # Load from environment variables with prefixes
        env_mappings = {
            "SECURITY_DEBUG_MODE": ("debug_mode", bool),
            "SECURITY_STRICT_VALIDATION": ("strict_validation", bool),
            "SECURITY_ENABLE_CACHING": ("enable_caching", bool),
            "SECURITY_CACHE_TTL": ("cache_ttl", int),
            "SECURITY_API_TIMEOUT": ("api_timeout", float),
            "SECURITY_MAX_CONCURRENT": ("max_concurrent_requests", int),
            "SECURITY_LOG_LEVEL": ("logging.level", str),
            "SECURITY_BATCH_SIZE": ("processing.batch_size", int),
            "SECURITY_MAX_QUEUE_SIZE": ("processing.max_queue_size", int),
        }
        
        for env_var, (attr_path, type_func) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    if type_func == bool:
                        parsed_value = value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        parsed_value = type_func(value)
                    
                    # Set nested attributes
                    if '.' in attr_path:
                        obj_attr, attr_name = attr_path.split('.', 1)
                        obj = getattr(config, obj_attr)
                        setattr(obj, attr_name, parsed_value)
                    else:
                        setattr(config, attr_path, parsed_value)
                        
                except (ValueError, TypeError):
                    # Skip invalid environment variable values
                    pass
        
        return config
    
    def update_from_dict(self, updates: Dict[str, Any]) -> None:
        """Update configuration from dictionary"""
        updated_config = self.from_dict({**self.to_dict(), **updates})
        
        # Update self with new values
        self.thresholds = updated_config.thresholds
        self.processing = updated_config.processing
        self.logging = updated_config.logging
        self.metrics = updated_config.metrics
        self.debug_mode = updated_config.debug_mode
        self.strict_validation = updated_config.strict_validation
        self.enable_caching = updated_config.enable_caching
        self.cache_ttl = updated_config.cache_ttl
        self.api_timeout = updated_config.api_timeout
        self.max_concurrent_requests = updated_config.max_concurrent_requests
        self.features = updated_config.features
        self.custom_settings = updated_config.custom_settings