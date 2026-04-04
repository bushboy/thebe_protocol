"""Prometheus metrics for Identity Abstraction Layer adapters.

This module provides Prometheus metrics for monitoring adapter operations,
including operation duration histograms and success/failure counters.

Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.7
"""

from prometheus_client import Histogram, Counter
from typing import Optional
import time
from functools import wraps
from shared.logging.json_logger import JSONLogger


logger = JSONLogger(__name__)


# Duration histograms for adapter operations
# Buckets are in seconds: 0.1s, 0.5s, 1s, 2s, 5s, 10s, 30s, 60s
adapter_get_token_duration = Histogram(
    'ial_adapter_get_token_duration_seconds',
    'Duration of get_token operations in seconds',
    ['provider_type'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
)

adapter_exchange_token_duration = Histogram(
    'ial_adapter_exchange_token_duration_seconds',
    'Duration of exchange_token operations in seconds',
    ['provider_type'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
)

adapter_revoke_session_duration = Histogram(
    'ial_adapter_revoke_session_duration_seconds',
    'Duration of revoke_session operations in seconds',
    ['provider_type'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
)

# Success/failure counters for adapter operations
adapter_operation_total = Counter(
    'ial_adapter_operation_total',
    'Total count of adapter operations',
    ['provider_type', 'operation', 'status']
)


def record_metrics(operation: str):
    """Decorator to record metrics for adapter operations.
    
    This decorator wraps adapter methods to automatically record:
    - Operation duration (histogram)
    - Operation success/failure count (counter)
    
    The decorator extracts the provider_type from the adapter instance
    using the get_provider_name() method.
    
    Args:
        operation: Operation name ('get_token', 'exchange_token', 'revoke_session')
        
    Returns:
        Decorated function that records metrics
        
    Example:
        @record_metrics('get_token')
        async def get_token(self, rar, provider):
            # Implementation
            pass
            
    Requirements: 22.1, 22.2, 22.3, 22.4, 22.7
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Get provider type from adapter instance
            provider_type = self.get_provider_name()
            
            # Select appropriate histogram based on operation
            if operation == 'get_token':
                histogram = adapter_get_token_duration
            elif operation == 'exchange_token':
                histogram = adapter_exchange_token_duration
            elif operation == 'revoke_session':
                histogram = adapter_revoke_session_duration
            else:
                logger.warning(f"Unknown operation for metrics: {operation}")
                histogram = None
            
            # Record start time
            start_time = time.time()
            status = 'failure'
            
            try:
                # Execute the operation
                result = await func(self, *args, **kwargs)
                status = 'success'
                return result
            
            except Exception as e:
                # Operation failed, status remains 'failure'
                logger.debug(
                    f"Operation {operation} failed for provider {provider_type}",
                    extra={"error": str(e)}
                )
                raise
            
            finally:
                # Record duration
                duration = time.time() - start_time
                
                if histogram:
                    histogram.labels(provider_type=provider_type).observe(duration)
                
                # Record operation count
                adapter_operation_total.labels(
                    provider_type=provider_type,
                    operation=operation,
                    status=status
                ).inc()
                
                logger.debug(
                    f"Recorded metrics for {operation}",
                    extra={
                        "provider_type": provider_type,
                        "operation": operation,
                        "status": status,
                        "duration_seconds": duration
                    }
                )
        
        return wrapper
    return decorator


def record_revoke_session_metrics(func):
    """Decorator specifically for revoke_session operations.
    
    This is a specialized decorator for revoke_session since it returns
    a boolean instead of raising exceptions on failure.
    
    Args:
        func: The revoke_session method to wrap
        
    Returns:
        Decorated function that records metrics
        
    Requirements: 22.3, 22.4, 22.7
    """
    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        # Get provider type from adapter instance
        provider_type = self.get_provider_name()
        
        # Record start time
        start_time = time.time()
        
        try:
            # Execute the operation
            result = await func(self, *args, **kwargs)
            
            # Determine status based on return value
            status = 'success' if result else 'failure'
            
            return result
        
        except Exception as e:
            # Unexpected exception
            status = 'failure'
            logger.error(
                f"Unexpected exception in revoke_session for provider {provider_type}",
                extra={"error": str(e)}
            )
            raise
        
        finally:
            # Record duration
            duration = time.time() - start_time
            
            adapter_revoke_session_duration.labels(
                provider_type=provider_type
            ).observe(duration)
            
            # Record operation count
            adapter_operation_total.labels(
                provider_type=provider_type,
                operation='revoke_session',
                status=status
            ).inc()
            
            logger.debug(
                f"Recorded metrics for revoke_session",
                extra={
                    "provider_type": provider_type,
                    "operation": "revoke_session",
                    "status": status,
                    "duration_seconds": duration
                }
            )
    
    return wrapper
