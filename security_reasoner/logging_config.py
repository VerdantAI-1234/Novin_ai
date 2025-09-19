"""
Logging Configuration Module

Provides comprehensive logging setup and configuration for the security reasoner system.
Supports structured logging, multiple outputs, and security-specific log formatting.
"""

from __future__ import annotations
import logging
import logging.handlers
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional, TextIO
from pathlib import Path


class SecurityFormatter(logging.Formatter):
    """
    Custom formatter for security-related log entries.
    
    Provides structured logging with security context and
    consistent formatting across all security operations.
    """
    
    def __init__(self, include_security_context: bool = True):
        """
        Initialize security formatter.
        
        Args:
            include_security_context: Whether to include security-specific fields
        """
        self.include_security_context = include_security_context
        super().__init__()
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with security context.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log string
        """
        # Build base log entry
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "process": record.process
        }
        
        # Add security context if enabled
        if self.include_security_context:
            security_context = {
                "component": "security_reasoner",
                "subsystem": getattr(record, 'subsystem', 'unknown'),
                "operation": getattr(record, 'operation', 'unknown'),
                "user_id": getattr(record, 'user_id', None),
                "session_id": getattr(record, 'session_id', None),
                "correlation_id": getattr(record, 'correlation_id', None),
                "threat_level": getattr(record, 'threat_level', None),
                "event_id": getattr(record, 'event_id', None)
            }
            log_entry["security"] = {k: v for k, v in security_context.items() if v is not None}
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add extra fields from log record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 'exc_text', 
                          'stack_info', 'subsystem', 'operation', 'user_id', 'session_id',
                          'correlation_id', 'threat_level', 'event_id']:
                extra_fields[key] = value
        
        if extra_fields:
            log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, default=str, separators=(',', ':'))


class PlainTextFormatter(logging.Formatter):
    """Simple plain text formatter for console output"""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )


class SecurityLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that adds security context to log records.
    
    Automatically includes security-specific information in log entries
    such as user context, session information, and threat levels.
    """
    
    def __init__(self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None):
        """
        Initialize security logger adapter.
        
        Args:
            logger: Base logger instance
            extra: Additional context to include in all log entries
        """
        super().__init__(logger, extra or {})
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process log message and add security context.
        
        Args:
            msg: Log message
            kwargs: Log keyword arguments
            
        Returns:
            Tuple of (message, kwargs) with security context added
        """
        # Merge extra context
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        
        kwargs['extra'].update(self.extra)
        
        return msg, kwargs
    
    def log_security_event(self, level: int, msg: str, event_id: str = None, 
                          threat_level: str = None, user_id: str = None,
                          **kwargs) -> None:
        """
        Log a security-specific event with appropriate context.
        
        Args:
            level: Log level
            msg: Log message
            event_id: Security event ID
            threat_level: Detected threat level
            user_id: Associated user ID
            **kwargs: Additional log context
        """
        extra = kwargs.get('extra', {})
        extra.update({
            'subsystem': 'security',
            'operation': 'security_event',
            'event_id': event_id,
            'threat_level': threat_level,
            'user_id': user_id
        })
        kwargs['extra'] = extra
        
        self.log(level, msg, **kwargs)
    
    def log_performance(self, msg: str, duration: float, operation: str = None, **kwargs) -> None:
        """
        Log performance-related information.
        
        Args:
            msg: Log message
            duration: Operation duration in seconds
            operation: Operation name
            **kwargs: Additional log context
        """
        extra = kwargs.get('extra', {})
        extra.update({
            'subsystem': 'performance',
            'operation': operation or 'unknown',
            'duration_seconds': duration,
            'performance_metric': True
        })
        kwargs['extra'] = extra
        
        self.info(msg, **kwargs)
    
    def log_error(self, msg: str, error: Exception = None, correlation_id: str = None, **kwargs) -> None:
        """
        Log error with enhanced context.
        
        Args:
            msg: Error message
            error: Exception instance
            correlation_id: Request correlation ID
            **kwargs: Additional log context
        """
        extra = kwargs.get('extra', {})
        extra.update({
            'subsystem': 'error_handling',
            'correlation_id': correlation_id,
            'error_type': type(error).__name__ if error else None
        })
        kwargs['extra'] = extra
        
        if error:
            kwargs['exc_info'] = (type(error), error, error.__traceback__)
        
        self.error(msg, **kwargs)


class LoggingConfig:
    """
    Comprehensive logging configuration for the security reasoner system.
    
    Manages multiple loggers, handlers, and formatters with support for
    structured logging, file rotation, and security-specific features.
    """
    
    def __init__(self):
        """Initialize logging configuration"""
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}
        self.configured = False
    
    def setup_logging(self, 
                     level: str = "INFO",
                     console_output: bool = True,
                     file_output: bool = False,
                     file_path: Optional[str] = None,
                     structured_logging: bool = True,
                     max_file_size: int = 10 * 1024 * 1024,  # 10MB
                     backup_count: int = 5,
                     log_format: Optional[str] = None) -> None:
        """
        Set up comprehensive logging configuration.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            console_output: Enable console logging
            file_output: Enable file logging
            file_path: Path for log files
            structured_logging: Use JSON structured logging
            max_file_size: Maximum size for log files before rotation
            backup_count: Number of backup files to keep
            log_format: Custom log format string
        """
        # Convert level string to logging constant
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(numeric_level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Setup console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(numeric_level)
            
            if structured_logging:
                console_formatter = SecurityFormatter(include_security_context=True)
            else:
                console_formatter = PlainTextFormatter()
                if log_format:
                    console_formatter = logging.Formatter(log_format)
            
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)
            self.handlers['console'] = console_handler
        
        # Setup file handler with rotation
        if file_output and file_path:
            # Ensure log directory exists
            log_path = Path(file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                filename=file_path,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(numeric_level)
            
            if structured_logging:
                file_formatter = SecurityFormatter(include_security_context=True)
            else:
                file_formatter = PlainTextFormatter()
                if log_format:
                    file_formatter = logging.Formatter(log_format)
            
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            self.handlers['file'] = file_handler
        
        self.configured = True
    
    def get_logger(self, name: str, context: Optional[Dict[str, Any]] = None) -> SecurityLoggerAdapter:
        """
        Get a security-aware logger instance.
        
        Args:
            name: Logger name
            context: Additional context to include in all log entries
            
        Returns:
            SecurityLoggerAdapter instance
        """
        if not self.configured:
            self.setup_logging()
        
        logger = logging.getLogger(name)
        
        # Create security adapter with context
        security_logger = SecurityLoggerAdapter(logger, context or {})
        self.loggers[name] = logger
        
        return security_logger
    
    def get_performance_logger(self) -> SecurityLoggerAdapter:
        """Get logger specifically for performance metrics"""
        return self.get_logger('security_reasoner.performance', {
            'subsystem': 'performance',
            'logger_type': 'performance'
        })
    
    def get_security_logger(self) -> SecurityLoggerAdapter:
        """Get logger specifically for security events"""
        return self.get_logger('security_reasoner.security', {
            'subsystem': 'security',
            'logger_type': 'security'
        })
    
    def get_audit_logger(self) -> SecurityLoggerAdapter:
        """Get logger specifically for audit trails"""
        return self.get_logger('security_reasoner.audit', {
            'subsystem': 'audit',
            'logger_type': 'audit'
        })
    
    def setup_component_logging(self, component_name: str, level: str = None) -> SecurityLoggerAdapter:
        """
        Set up logging for a specific component.
        
        Args:
            component_name: Name of the component
            level: Optional specific log level for this component
            
        Returns:
            SecurityLoggerAdapter for the component
        """
        logger = self.get_logger(f'security_reasoner.{component_name}', {
            'component': component_name
        })
        
        if level:
            numeric_level = getattr(logging, level.upper(), logging.INFO)
            logger.logger.setLevel(numeric_level)
        
        return logger
    
    def add_custom_handler(self, name: str, handler: logging.Handler, 
                          formatter: logging.Formatter = None) -> None:
        """
        Add a custom log handler.
        
        Args:
            name: Handler name
            handler: Logging handler instance
            formatter: Optional custom formatter
        """
        if formatter is None:
            formatter = SecurityFormatter(include_security_context=True)
        
        handler.setFormatter(formatter)
        
        # Add to all existing loggers
        for logger in self.loggers.values():
            logger.addHandler(handler)
        
        # Add to root logger
        logging.getLogger().addHandler(handler)
        
        self.handlers[name] = handler
    
    def setup_syslog_handler(self, address: str = '/dev/log', facility: str = 'local0') -> None:
        """
        Set up syslog handler for system-wide logging.
        
        Args:
            address: Syslog address
            facility: Syslog facility
        """
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=address,
                facility=getattr(logging.handlers.SysLogHandler, f'LOG_{facility.upper()}')
            )
            
            syslog_formatter = logging.Formatter(
                'security_reasoner[%(process)d]: %(levelname)s - %(message)s'
            )
            
            self.add_custom_handler('syslog', syslog_handler, syslog_formatter)
            
        except Exception as e:
            logging.getLogger().warning(f"Failed to setup syslog handler: {e}")
    
    def setup_json_file_handler(self, file_path: str, max_size: int = 50 * 1024 * 1024) -> None:
        """
        Set up dedicated JSON file handler for structured logs.
        
        Args:
            file_path: Path for JSON log file
            max_size: Maximum file size before rotation
        """
        log_path = Path(file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        json_handler = logging.handlers.RotatingFileHandler(
            filename=file_path,
            maxBytes=max_size,
            backupCount=10,
            encoding='utf-8'
        )
        
        json_formatter = SecurityFormatter(include_security_context=True)
        self.add_custom_handler('json_file', json_handler, json_formatter)
    
    def update_log_level(self, level: str, logger_name: str = None) -> None:
        """
        Update log level for specific logger or all loggers.
        
        Args:
            level: New log level
            logger_name: Specific logger name, or None for all loggers
        """
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        
        if logger_name:
            if logger_name in self.loggers:
                self.loggers[logger_name].setLevel(numeric_level)
        else:
            logging.getLogger().setLevel(numeric_level)
            for logger in self.loggers.values():
                logger.setLevel(numeric_level)
    
    def flush_logs(self) -> None:
        """Flush all log handlers"""
        for handler in self.handlers.values():
            if hasattr(handler, 'flush'):
                handler.flush()
    
    def close_handlers(self) -> None:
        """Close all log handlers"""
        for handler in self.handlers.values():
            if hasattr(handler, 'close'):
                handler.close()
        
        self.handlers.clear()
        self.loggers.clear()
        self.configured = False


# Global logging configuration instance
_logging_config = LoggingConfig()

def setup_logging(**kwargs) -> None:
    """Global function to setup logging"""
    _logging_config.setup_logging(**kwargs)

def get_logger(name: str, context: Optional[Dict[str, Any]] = None) -> SecurityLoggerAdapter:
    """Global function to get a logger"""
    return _logging_config.get_logger(name, context)

def get_security_logger() -> SecurityLoggerAdapter:
    """Global function to get security logger"""
    return _logging_config.get_security_logger()

def get_performance_logger() -> SecurityLoggerAdapter:
    """Global function to get performance logger"""
    return _logging_config.get_performance_logger()

def get_audit_logger() -> SecurityLoggerAdapter:
    """Global function to get audit logger"""
    return _logging_config.get_audit_logger()