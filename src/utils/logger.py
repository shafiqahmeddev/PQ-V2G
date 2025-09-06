"""
PQ-V2G Logging Utility
======================

Structured logging setup for the PQ-V2G system with performance metrics,
security event logging, and multi-destination support.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import sys
import logging
import logging.handlers
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import structlog
import colorlog

class PQV2GFormatter(logging.Formatter):
    """Custom formatter for PQ-V2G log messages"""
    
    def __init__(self, format_string: Optional[str] = None, structured: bool = True):
        self.structured = structured
        
        if not format_string:
            if structured:
                format_string = '%(asctime)s | %(levelname)8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s'
            else:
                format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        super().__init__(format_string, datefmt='%Y-%m-%d %H:%M:%S')
    
    def format(self, record):
        """Format log record with additional PQ-V2G context"""
        
        # Add PQ-V2G specific fields
        if not hasattr(record, 'component'):
            record.component = getattr(record, 'name', 'unknown').split('.')[-1]
        
        if not hasattr(record, 'session_id'):
            record.session_id = getattr(record, 'session_id', None)
        
        if not hasattr(record, 'ev_id'):
            record.ev_id = getattr(record, 'ev_id', None)
        
        if not hasattr(record, 'evse_id'):
            record.evse_id = getattr(record, 'evse_id', None)
        
        # Format the base message
        formatted = super().format(record)
        
        # Add structured data if available
        if self.structured and hasattr(record, 'extra_data'):
            extra = record.extra_data
            if extra:
                structured_data = json.dumps(extra, separators=(',', ':'))
                formatted += f" | data={structured_data}"
        
        return formatted

class PerformanceLogger:
    """Performance metrics logging utility"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.start_times = {}
    
    def start_timer(self, operation: str, context: Dict[str, Any] = None):
        """Start timing an operation"""
        timer_key = f"{operation}_{id(context) if context else 'global'}"
        self.start_times[timer_key] = time.time()
        
        self.logger.debug(
            f"Started timing: {operation}",
            extra={'extra_data': {'operation': operation, 'action': 'start_timer', **context or {}}}
        )
    
    def end_timer(self, operation: str, context: Dict[str, Any] = None):
        """End timing an operation and log duration"""
        timer_key = f"{operation}_{id(context) if context else 'global'}"
        
        if timer_key not in self.start_times:
            self.logger.warning(f"Timer not found for operation: {operation}")
            return None
        
        start_time = self.start_times.pop(timer_key)
        duration = time.time() - start_time
        
        self.logger.info(
            f"Operation completed: {operation} ({duration:.3f}s)",
            extra={'extra_data': {
                'operation': operation,
                'action': 'end_timer',
                'duration_ms': round(duration * 1000, 3),
                **context or {}
            }}
        )
        
        return duration
    
    def log_metric(self, metric_name: str, value: float, unit: str = "", context: Dict[str, Any] = None):
        """Log a performance metric"""
        self.logger.info(
            f"Metric: {metric_name}={value}{unit}",
            extra={'extra_data': {
                'metric_name': metric_name,
                'metric_value': value,
                'metric_unit': unit,
                'action': 'metric',
                **context or {}
            }}
        )

class SecurityLogger:
    """Security event logging utility"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_auth_attempt(self, ev_id: str, evse_id: str, success: bool, method: str, 
                        certificate_serial: str = None):
        """Log authentication attempt"""
        level = logging.INFO if success else logging.WARNING
        status = "SUCCESS" if success else "FAILURE"
        
        self.logger.log(
            level,
            f"Authentication {status}: {ev_id} -> {evse_id} via {method}",
            extra={'extra_data': {
                'event_type': 'authentication',
                'ev_id': ev_id,
                'evse_id': evse_id,
                'success': success,
                'method': method,
                'certificate_serial': certificate_serial,
                'timestamp': datetime.utcnow().isoformat()
            }}
        )
    
    def log_certificate_event(self, event_type: str, certificate_serial: str, 
                             details: Dict[str, Any] = None):
        """Log certificate-related security event"""
        self.logger.info(
            f"Certificate {event_type}: {certificate_serial}",
            extra={'extra_data': {
                'event_type': 'certificate',
                'certificate_event': event_type,
                'certificate_serial': certificate_serial,
                'timestamp': datetime.utcnow().isoformat(),
                **details or {}
            }}
        )
    
    def log_crypto_operation(self, operation: str, algorithm: str, success: bool, 
                            duration_ms: float = None):
        """Log cryptographic operation"""
        level = logging.DEBUG if success else logging.ERROR
        status = "SUCCESS" if success else "FAILURE"
        
        extra_data = {
            'event_type': 'crypto_operation',
            'operation': operation,
            'algorithm': algorithm,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if duration_ms is not None:
            extra_data['duration_ms'] = duration_ms
        
        self.logger.log(
            level,
            f"Crypto {operation} ({algorithm}): {status}",
            extra={'extra_data': extra_data}
        )
    
    def log_security_violation(self, violation_type: str, description: str, 
                              context: Dict[str, Any] = None):
        """Log security violation"""
        self.logger.error(
            f"SECURITY VIOLATION - {violation_type}: {description}",
            extra={'extra_data': {
                'event_type': 'security_violation',
                'violation_type': violation_type,
                'description': description,
                'timestamp': datetime.utcnow().isoformat(),
                **context or {}
            }}
        )

def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup logging configuration for PQ-V2G system
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Configured root logger
    """
    
    # Get configuration values
    log_level = config.get('level', 'INFO').upper()
    structured = config.get('structured', True)
    categories = config.get('categories', {})
    handlers_config = config.get('handlers', {})
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Setup console handler
    if handlers_config.get('console', {}).get('enabled', True):
        console_handler = _setup_console_handler(handlers_config.get('console', {}), structured)
        root_logger.addHandler(console_handler)
    
    # Setup file handler
    if handlers_config.get('file', {}).get('enabled', True):
        file_handler = _setup_file_handler(handlers_config.get('file', {}), structured)
        if file_handler:
            root_logger.addHandler(file_handler)
    
    # Setup category-specific loggers
    for category, level in categories.items():
        category_logger = logging.getLogger(category)
        category_logger.setLevel(getattr(logging, level.upper()))
    
    # Setup structured logging if enabled
    if structured:
        _setup_structlog()
    
    # Log startup message
    logger = logging.getLogger('pq_v2g.logging')
    logger.info("PQ-V2G logging system initialized", extra={
        'extra_data': {
            'log_level': log_level,
            'structured': structured,
            'handlers': list(handlers_config.keys())
        }
    })
    
    return root_logger

def _setup_console_handler(config: Dict[str, Any], structured: bool) -> logging.Handler:
    """Setup console logging handler"""
    
    console_handler = logging.StreamHandler(sys.stdout)
    
    # Use colored output for human-readable format
    format_type = config.get('format', 'human')
    
    if format_type == 'human' and not structured:
        # Colored formatter for development
        formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s | %(levelname)8s | %(name)20s | %(message)s%(reset)s',
            datefmt='%H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
    else:
        # Structured formatter
        formatter = PQV2GFormatter(structured=structured)
    
    console_handler.setFormatter(formatter)
    
    return console_handler

def _setup_file_handler(config: Dict[str, Any], structured: bool) -> Optional[logging.Handler]:
    """Setup file logging handler"""
    
    log_path = config.get('path', 'logs/pq_v2g.log')
    
    try:
        # Create log directory
        log_file = Path(log_path)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup rotating file handler
        rotation = config.get('rotation', 'daily')
        retention_days = config.get('retention_days', 30)
        
        if rotation == 'daily':
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_path,
                when='midnight',
                interval=1,
                backupCount=retention_days,
                encoding='utf-8'
            )
        else:
            # Size-based rotation (default 10MB)
            max_bytes = config.get('max_bytes', 10 * 1024 * 1024)
            backup_count = config.get('backup_count', 10)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
        
        # Use structured formatter for file output
        formatter = PQV2GFormatter(structured=True)
        file_handler.setFormatter(formatter)
        
        return file_handler
        
    except Exception as e:
        print(f"Warning: Could not setup file handler: {e}", file=sys.stderr)
        return None

def _setup_structlog():
    """Setup structlog for structured logging"""
    
    # Configure processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ]
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

class PQV2GLogger:
    """Main PQ-V2G logger wrapper with specialized loggers"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.performance = PerformanceLogger(self.logger)
        self.security = SecurityLogger(self.logger)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self._log(logging.CRITICAL, message, **kwargs)
    
    def _log(self, level: int, message: str, **kwargs):
        """Internal logging method with context"""
        extra_data = {}
        
        # Extract special context fields
        for key in ['session_id', 'ev_id', 'evse_id', 'component', 'operation']:
            if key in kwargs:
                extra_data[key] = kwargs.pop(key)
        
        # Add remaining kwargs as extra data
        if kwargs:
            extra_data.update(kwargs)
        
        # Log with extra data
        extra = {'extra_data': extra_data} if extra_data else {}
        self.logger.log(level, message, extra=extra)

def get_logger(name: str) -> PQV2GLogger:
    """Get a PQ-V2G logger instance"""
    return PQV2GLogger(name)

# Context managers for logging
class LoggingContext:
    """Context manager for adding logging context"""
    
    def __init__(self, logger: PQV2GLogger, **context):
        self.logger = logger
        self.context = context
        self.original_logger = None
    
    def __enter__(self):
        # In production, this would modify the logger to include context
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original logger state
        pass

def with_logging_context(**context):
    """Decorator for adding logging context to functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # In production, this would set up logging context
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Export main functions and classes
__all__ = [
    'setup_logging',
    'get_logger', 
    'PQV2GLogger',
    'PerformanceLogger',
    'SecurityLogger',
    'LoggingContext',
    'with_logging_context'
]
