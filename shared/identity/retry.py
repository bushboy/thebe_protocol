"""Retry logic with exponential backoff for Identity Abstraction Layer.

This module provides a decorator for retrying adapter methods with exponential
backoff and jitter, handling transient failures gracefully while avoiding
unnecessary retries for client errors.

Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7
"""

import asyncio
import random
from functools import wraps
from typing import Callable, Any
import httpx
from .exceptions import VaultProviderError
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    jitter: bool = True
):
    """Decorator for retrying adapter methods with exponential backoff.
    
    Retries network errors and 5xx responses up to max_attempts times with
    exponential backoff. Does not retry 4xx responses (client errors).
    Logs each retry attempt with attempt number and delay.
    
    Args:
        max_attempts: Maximum number of attempts (default: 3)
        base_delay: Base delay in seconds for exponential backoff (default: 1.0)
        max_delay: Maximum delay in seconds (default: 10.0)
        jitter: Whether to add jitter to retry delays (default: True)
        
    Returns:
        Decorated function with retry logic
        
    Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7
    
    Example:
        @with_retry(max_attempts=3, base_delay=1.0)
        async def get_token(self, rar, provider):
            # Method implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            attempts = []
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    # Attempt the operation
                    result = await func(*args, **kwargs)
                    
                    # Success - log if this was a retry
                    if attempt > 1:
                        logger.info(
                            f"Operation succeeded on attempt {attempt}",
                            extra={
                                "function": func.__name__,
                                "attempt": attempt,
                                "total_attempts": max_attempts
                            }
                        )
                    
                    return result
                
                except httpx.RequestError as e:
                    # Network error - retryable
                    last_exception = e
                    attempts.append({
                        "attempt": attempt,
                        "error_type": "network_error",
                        "error": str(e)
                    })
                    
                    if attempt < max_attempts:
                        delay = _calculate_delay(attempt, base_delay, max_delay, jitter)
                        logger.warning(
                            f"Network error on attempt {attempt}, retrying in {delay:.2f}s",
                            extra={
                                "function": func.__name__,
                                "attempt": attempt,
                                "max_attempts": max_attempts,
                                "delay": delay,
                                "error": str(e)
                            }
                        )
                        await asyncio.sleep(delay)
                    else:
                        # Exhausted all attempts
                        logger.error(
                            f"Network error persisted after {max_attempts} attempts",
                            extra={
                                "function": func.__name__,
                                "attempts": attempts
                            }
                        )
                
                except VaultProviderError as e:
                    # Check if this is a 5xx error (retryable) or 4xx error (not retryable)
                    error_msg = str(e).lower()
                    
                    # Check for 5xx status codes in error message
                    is_5xx = any(f"returned {code}" in error_msg for code in range(500, 600))
                    
                    # Check for 4xx status codes in error message
                    is_4xx = any(f"returned {code}" in error_msg for code in range(400, 500))
                    
                    if is_4xx:
                        # Client error - do not retry
                        logger.error(
                            f"Client error (4xx) on attempt {attempt}, not retrying",
                            extra={
                                "function": func.__name__,
                                "attempt": attempt,
                                "error": str(e)
                            }
                        )
                        raise
                    
                    if is_5xx:
                        # Server error - retryable
                        last_exception = e
                        attempts.append({
                            "attempt": attempt,
                            "error_type": "server_error_5xx",
                            "error": str(e)
                        })
                        
                        if attempt < max_attempts:
                            delay = _calculate_delay(attempt, base_delay, max_delay, jitter)
                            logger.warning(
                                f"Server error (5xx) on attempt {attempt}, retrying in {delay:.2f}s",
                                extra={
                                    "function": func.__name__,
                                    "attempt": attempt,
                                    "max_attempts": max_attempts,
                                    "delay": delay,
                                    "error": str(e)
                                }
                            )
                            await asyncio.sleep(delay)
                        else:
                            # Exhausted all attempts
                            logger.error(
                                f"Server error (5xx) persisted after {max_attempts} attempts",
                                extra={
                                    "function": func.__name__,
                                    "attempts": attempts
                                }
                            )
                    else:
                        # Other VaultProviderError - treat as retryable
                        last_exception = e
                        attempts.append({
                            "attempt": attempt,
                            "error_type": "provider_error",
                            "error": str(e)
                        })
                        
                        if attempt < max_attempts:
                            delay = _calculate_delay(attempt, base_delay, max_delay, jitter)
                            logger.warning(
                                f"Provider error on attempt {attempt}, retrying in {delay:.2f}s",
                                extra={
                                    "function": func.__name__,
                                    "attempt": attempt,
                                    "max_attempts": max_attempts,
                                    "delay": delay,
                                    "error": str(e)
                                }
                            )
                            await asyncio.sleep(delay)
                        else:
                            # Exhausted all attempts
                            logger.error(
                                f"Provider error persisted after {max_attempts} attempts",
                                extra={
                                    "function": func.__name__,
                                    "attempts": attempts
                                }
                            )
                
                except Exception as e:
                    # Unexpected error - do not retry, re-raise immediately
                    logger.error(
                        f"Unexpected error on attempt {attempt}, not retrying",
                        extra={
                            "function": func.__name__,
                            "attempt": attempt,
                            "error": str(e),
                            "error_type": type(e).__name__
                        },
                        exc_info=True
                    )
                    raise
            
            # If we get here, all attempts failed
            # Raise VaultProviderError with details of all attempts
            error_summary = _format_retry_error(func.__name__, attempts, last_exception)
            raise VaultProviderError(error_summary)
        
        return wrapper
    return decorator


def _calculate_delay(attempt: int, base_delay: float, max_delay: float, jitter: bool) -> float:
    """Calculate retry delay with exponential backoff and optional jitter.
    
    Implements exponential backoff: delay = base_delay * (2 ** (attempt - 1))
    Adds jitter if enabled: delay += random(0, delay * 0.1)
    Caps delay at max_delay.
    
    Args:
        attempt: Current attempt number (1-indexed)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        jitter: Whether to add jitter
        
    Returns:
        Calculated delay in seconds
        
    Requirements: 20.5, 20.6
    """
    # Exponential backoff: base_delay * 2^(attempt-1)
    # Attempt 1: base_delay * 2^0 = base_delay * 1 = base_delay
    # Attempt 2: base_delay * 2^1 = base_delay * 2
    # Attempt 3: base_delay * 2^2 = base_delay * 4
    delay = base_delay * (2 ** (attempt - 1))
    
    # Add jitter to prevent thundering herd
    if jitter:
        # Add random jitter up to 10% of the delay
        jitter_amount = random.uniform(0, delay * 0.1)
        delay += jitter_amount
    
    # Cap at max_delay
    delay = min(delay, max_delay)
    
    return delay


def _format_retry_error(function_name: str, attempts: list, last_exception: Exception) -> str:
    """Format error message with details of all retry attempts.
    
    Creates a comprehensive error message containing:
    - Function name
    - Total number of attempts
    - Details of each attempt (attempt number, error type, error message)
    - Final exception message
    
    Args:
        function_name: Name of the function that failed
        attempts: List of attempt dictionaries with error details
        last_exception: The last exception that was raised
        
    Returns:
        Formatted error message string
        
    Requirements: 20.7
    """
    error_lines = [
        f"Operation '{function_name}' failed after {len(attempts)} attempts:"
    ]
    
    for attempt_info in attempts:
        error_lines.append(
            f"  Attempt {attempt_info['attempt']}: "
            f"{attempt_info['error_type']} - {attempt_info['error']}"
        )
    
    if last_exception:
        error_lines.append(f"Final error: {str(last_exception)}")
    
    return "\n".join(error_lines)
