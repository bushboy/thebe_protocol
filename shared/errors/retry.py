"""Retry logic with exponential backoff for network errors.

This module provides decorators and utilities for retrying failed operations
with exponential backoff, specifically for network and service availability errors.

Requirements: 24.1
"""

import asyncio
import time
from functools import wraps
from typing import Callable, TypeVar, Any, Tuple, Type
import logging

from .exceptions import ServiceUnavailableError


logger = logging.getLogger(__name__)

T = TypeVar('T')


def exponential_backoff_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
) -> Callable:
    """Decorator for retrying functions with exponential backoff.
    
    This decorator retries a function up to max_retries times with exponential
    backoff between attempts. The delay doubles after each retry:
    - Attempt 1: base_delay (1s)
    - Attempt 2: base_delay * 2 (2s)
    - Attempt 3: base_delay * 4 (4s)
    
    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        base_delay: Initial delay in seconds (default: 1.0)
        max_delay: Maximum delay in seconds (default: 60.0)
        exceptions: Tuple of exception types to catch and retry
        
    Returns:
        Decorated function with retry logic
        
    Requirements: 24.1
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        # Calculate delay with exponential backoff
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: {str(e)}. "
                            f"Retrying in {delay}s..."
                        )
                        
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}: {str(e)}"
                        )
            
            # All retries exhausted, raise the last exception
            raise last_exception
        
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        # Calculate delay with exponential backoff
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: {str(e)}. "
                            f"Retrying in {delay}s..."
                        )
                        
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}: {str(e)}"
                        )
            
            # All retries exhausted, raise the last exception
            raise last_exception
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def retry_on_network_error(func: Callable[..., T]) -> Callable[..., T]:
    """Convenience decorator for retrying on common network errors.
    
    This decorator retries on:
    - ConnectionError
    - TimeoutError
    - ServiceUnavailableError
    
    Uses default retry settings: 3 retries with 1s, 2s, 4s delays.
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function with retry logic
        
    Requirements: 24.1
    """
    return exponential_backoff_retry(
        max_retries=3,
        base_delay=1.0,
        exceptions=(ConnectionError, TimeoutError, ServiceUnavailableError)
    )(func)


class RetryContext:
    """Context manager for retry logic with exponential backoff.
    
    This provides a more flexible retry mechanism that can be used
    with context managers instead of decorators.
    
    Example:
        retry_ctx = RetryContext(max_retries=3, base_delay=1.0)
        for attempt in retry_ctx:
            try:
                result = make_network_call()
                break
            except ConnectionError as e:
                retry_ctx.handle_exception(e)
    
    Requirements: 24.1
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exceptions = exceptions
        self.attempt = 0
        self.last_exception = None
    
    def __iter__(self):
        """Iterate through retry attempts."""
        self.attempt = 0
        return self
    
    def __next__(self):
        """Get next retry attempt."""
        if self.attempt > self.max_retries:
            raise StopIteration
        
        current_attempt = self.attempt
        self.attempt += 1
        return current_attempt
    
    def handle_exception(self, exception: Exception) -> None:
        """Handle an exception during a retry attempt.
        
        Args:
            exception: The exception that occurred
            
        Raises:
            Exception: If all retries are exhausted
        """
        self.last_exception = exception
        
        if not isinstance(exception, self.exceptions):
            # Not a retryable exception, raise immediately
            raise exception
        
        if self.attempt > self.max_retries:
            # All retries exhausted
            logger.error(f"All {self.max_retries + 1} attempts failed: {str(exception)}")
            raise exception
        
        # Calculate delay and wait
        delay = min(self.base_delay * (2 ** (self.attempt - 1)), self.max_delay)
        logger.warning(
            f"Attempt {self.attempt}/{self.max_retries + 1} failed: {str(exception)}. "
            f"Retrying in {delay}s..."
        )
        time.sleep(delay)
    
    async def handle_exception_async(self, exception: Exception) -> None:
        """Async version of handle_exception.
        
        Args:
            exception: The exception that occurred
            
        Raises:
            Exception: If all retries are exhausted
        """
        self.last_exception = exception
        
        if not isinstance(exception, self.exceptions):
            # Not a retryable exception, raise immediately
            raise exception
        
        if self.attempt > self.max_retries:
            # All retries exhausted
            logger.error(f"All {self.max_retries + 1} attempts failed: {str(exception)}")
            raise exception
        
        # Calculate delay and wait
        delay = min(self.base_delay * (2 ** (self.attempt - 1)), self.max_delay)
        logger.warning(
            f"Attempt {self.attempt}/{self.max_retries + 1} failed: {str(exception)}. "
            f"Retrying in {delay}s..."
        )
        await asyncio.sleep(delay)
