"""JSON structured logging module.

This module provides structured logging functionality:
- Configure Python logging to output JSON
- Add correlation ID to all log entries
- Add audit hooks for security events

Requirements: 4.7
"""

import json
import logging
import sys
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from contextvars import ContextVar


# Context variable for correlation ID
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs logs as JSON."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON-formatted log string
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add correlation ID if present
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_data["correlation_id"] = correlation_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class JSONLogger:
    """Structured JSON logger with correlation ID support."""
    
    def __init__(self, name: str):
        """Initialize JSON logger.
        
        Args:
            name: Logger name (typically module name)
        """
        self.logger = logging.getLogger(name)
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for current context.
        
        Args:
            correlation_id: Correlation ID to use for subsequent log entries
        """
        correlation_id_var.set(correlation_id)
    
    def generate_correlation_id(self) -> str:
        """Generate and set a new correlation ID.
        
        Returns:
            Generated correlation ID
        """
        correlation_id = str(uuid.uuid4())
        self.set_correlation_id(correlation_id)
        return correlation_id
    
    def clear_correlation_id(self):
        """Clear correlation ID from current context."""
        correlation_id_var.set(None)
    
    def _log(self, level: int, message: str, extra_fields: Optional[Dict[str, Any]] = None):
        """Internal log method with extra fields support.
        
        Args:
            level: Log level
            message: Log message
            extra_fields: Additional fields to include in log entry
        """
        extra = {'extra_fields': extra_fields} if extra_fields else {}
        self.logger.log(level, message, extra=extra)
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log(logging.DEBUG, message, kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log(logging.INFO, message, kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log(logging.WARNING, message, kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log(logging.ERROR, message, kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self._log(logging.CRITICAL, message, kwargs)
    
    def audit(self, event_type: str, **kwargs):
        """Log audit event.
        
        Args:
            event_type: Type of audit event
            **kwargs: Additional audit fields
        """
        audit_data = {
            "audit_event": True,
            "event_type": event_type,
            **kwargs
        }
        self._log(logging.INFO, f"Audit: {event_type}", audit_data)


def setup_logging(level: str = "INFO") -> None:
    """Configure structured JSON logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Get root logger
    root_logger = logging.getLogger()
    
    # Set log level
    log_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler with JSON formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(JSONFormatter())
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
