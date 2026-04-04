"""Error handling middleware for FastAPI services.

This module provides middleware for consistent error handling across all services,
including logging, response formatting, and correlation ID tracking.

Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback
import uuid
from typing import Callable, Any
import logging

from .exceptions import BaseServiceError
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


async def error_handling_middleware(request: Request, call_next: Callable) -> Any:
    """Middleware to handle errors consistently across all services.
    
    This middleware:
    - Adds correlation IDs to all requests
    - Catches and formats all exceptions
    - Logs errors with full context
    - Returns standardized error responses
    
    Args:
        request: The incoming request
        call_next: The next middleware or route handler
        
    Returns:
        Response with error handling applied
        
    Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
    """
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    
    try:
        response = await call_next(request)
        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id
        return response
        
    except BaseServiceError as e:
        # Handle our custom exceptions
        logger.error(
            f"Service error: {e.error_code}",
            extra={
                "correlation_id": correlation_id,
                "error_code": e.error_code,
                "message": e.message,
                "details": e.details,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.error_code,
                "message": e.message,
                **e.details
            },
            headers={"X-Correlation-ID": correlation_id}
        )
        
    except Exception as e:
        # Handle unexpected exceptions
        logger.error(
            f"Unexpected error: {str(e)}",
            extra={
                "correlation_id": correlation_id,
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "path": request.url.path,
                "method": request.method
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": "An unexpected error occurred",
                "correlation_id": correlation_id
            },
            headers={"X-Correlation-ID": correlation_id}
        )


def setup_error_handlers(app: FastAPI) -> None:
    """Set up error handlers for a FastAPI application.
    
    This function registers exception handlers for:
    - Custom service exceptions
    - Validation errors
    - HTTP exceptions
    - Unexpected exceptions
    
    Args:
        app: The FastAPI application instance
        
    Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
    """
    
    @app.exception_handler(BaseServiceError)
    async def service_error_handler(request: Request, exc: BaseServiceError) -> JSONResponse:
        """Handle custom service exceptions."""
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        
        logger.error(
            f"Service error: {exc.error_code}",
            extra={
                "correlation_id": correlation_id,
                "error_code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                **exc.details
            },
            headers={"X-Correlation-ID": correlation_id}
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Handle request validation errors."""
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        
        logger.warning(
            "Validation error",
            extra={
                "correlation_id": correlation_id,
                "errors": exc.errors(),
                "path": request.url.path,
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "validation_error",
                "message": "Request validation failed",
                "details": exc.errors()
            },
            headers={"X-Correlation-ID": correlation_id}
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Handle HTTP exceptions."""
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        
        logger.warning(
            f"HTTP exception: {exc.status_code}",
            extra={
                "correlation_id": correlation_id,
                "status_code": exc.status_code,
                "detail": exc.detail,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail
            },
            headers={"X-Correlation-ID": correlation_id}
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle all other exceptions."""
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        
        logger.error(
            f"Unexpected error: {str(exc)}",
            extra={
                "correlation_id": correlation_id,
                "error_type": type(exc).__name__,
                "traceback": traceback.format_exc(),
                "path": request.url.path,
                "method": request.method
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": "An unexpected error occurred",
                "correlation_id": correlation_id
            },
            headers={"X-Correlation-ID": correlation_id}
        )
    
    # Add middleware
    app.middleware("http")(error_handling_middleware)
    
    logger.info("Error handlers configured successfully")
