"""Replay prevention module using Redis.

This module tracks used ZT-ATs to prevent replay attacks.

Requirements: 9.1, 9.4
"""

import hashlib
from typing import Optional
from datetime import datetime, timedelta
import redis
from redis.exceptions import RedisError

from shared.schemas import ZeroTrustAuthorizationToken
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


class ReplayPreventionError(Exception):
    """Exception raised when replay attack is detected."""
    pass


class ReplayPrevention:
    """Redis-based replay prevention for ZT-ATs."""
    
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379,
                 redis_db: int = 0, redis_password: Optional[str] = None):
        """Initialize replay prevention with Redis connection.
        
        Args:
            redis_host: Redis server hostname
            redis_port: Redis server port
            redis_db: Redis database number
            redis_password: Redis password (optional)
        """
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password if redis_password else None,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5
        )
        logger.info(f"Initialized replay prevention with Redis at {redis_host}:{redis_port}")
    
    def check_and_mark_used(self, zt_at: ZeroTrustAuthorizationToken) -> None:
        """Check if ZT-AT has been used and mark it as used.
        
        This method atomically checks if the ZT-AT has been used before
        and marks it as used if not. This prevents replay attacks.
        
        Args:
            zt_at: Zero-Trust Authorization Token
            
        Raises:
            ReplayPreventionError: If ZT-AT has already been used
            RedisError: If Redis connection fails
            
        Requirements: 9.1, 9.4
        """
        # Compute unique hash for this ZT-AT
        ztat_hash = self._compute_ztat_hash(zt_at)
        redis_key = f"ztat:used:{ztat_hash}"
        
        logger.debug(f"Checking ZT-AT usage for hash: {ztat_hash}")
        
        try:
            # Use Redis SETNX (SET if Not eXists) for atomic check-and-set
            # Returns 1 if key was set (first use), 0 if key already exists (replay)
            was_set = self.redis_client.setnx(redis_key, datetime.utcnow().isoformat())
            
            if not was_set:
                # ZT-AT has already been used - replay attack detected
                original_use_time = self.redis_client.get(redis_key)
                error_msg = (
                    f"ZT-AT replay detected! Token was already used at {original_use_time}. "
                    f"Plan: {zt_at.plan_id}, Task: {zt_at.task_id}"
                )
                logger.error(error_msg)
                raise ReplayPreventionError(error_msg)
            
            # Set expiration based on ZT-AT expiration time
            # Add buffer to ensure we track it past its validity period
            ttl_seconds = self._calculate_ttl(zt_at)
            self.redis_client.expire(redis_key, ttl_seconds)
            
            logger.info(
                f"ZT-AT marked as used: {ztat_hash} "
                f"(plan: {zt_at.plan_id}, task: {zt_at.task_id}, TTL: {ttl_seconds}s)"
            )
            
        except RedisError as e:
            logger.error(f"Redis error during replay prevention check: {str(e)}")
            raise
    
    def is_used(self, zt_at: ZeroTrustAuthorizationToken) -> bool:
        """Check if ZT-AT has been used (without marking it).
        
        Args:
            zt_at: Zero-Trust Authorization Token
            
        Returns:
            True if ZT-AT has been used, False otherwise
            
        Raises:
            RedisError: If Redis connection fails
        """
        ztat_hash = self._compute_ztat_hash(zt_at)
        redis_key = f"ztat:used:{ztat_hash}"
        
        try:
            exists = self.redis_client.exists(redis_key)
            return bool(exists)
        except RedisError as e:
            logger.error(f"Redis error checking ZT-AT usage: {str(e)}")
            raise
    
    def health_check(self) -> bool:
        """Check if Redis connection is healthy.
        
        Returns:
            True if Redis is accessible, False otherwise
        """
        try:
            self.redis_client.ping()
            return True
        except RedisError as e:
            logger.error(f"Redis health check failed: {str(e)}")
            return False
    
    def _compute_ztat_hash(self, zt_at: ZeroTrustAuthorizationToken) -> str:
        """Compute unique hash for ZT-AT.
        
        The hash is computed from fields that uniquely identify the token:
        - nonce (already unique per token)
        - plan_id and task_id (for additional context)
        - issued_at timestamp (for uniqueness)
        
        Args:
            zt_at: Zero-Trust Authorization Token
            
        Returns:
            SHA256 hash as hexadecimal string
        """
        # Construct unique identifier from ZT-AT fields
        unique_data = (
            f"{zt_at.nonce}|"
            f"{zt_at.plan_id}|"
            f"{zt_at.task_id}|"
            f"{zt_at.issued_at.isoformat()}"
        )
        
        # Compute SHA256 hash
        hash_obj = hashlib.sha256(unique_data.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def _calculate_ttl(self, zt_at: ZeroTrustAuthorizationToken) -> int:
        """Calculate TTL (time-to-live) for Redis key.
        
        The TTL is set to the token's remaining lifetime plus a buffer
        to ensure we track it past its validity period.
        
        Args:
            zt_at: Zero-Trust Authorization Token
            
        Returns:
            TTL in seconds
        """
        current_time = datetime.utcnow()
        
        # Ensure expires_at is timezone-naive for comparison
        expires_at = zt_at.expires_at
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)
        
        # Calculate remaining lifetime
        if expires_at > current_time:
            remaining = (expires_at - current_time).total_seconds()
        else:
            remaining = 0
        
        # Add 1 hour buffer to track past expiration
        buffer_seconds = 3600
        ttl = int(remaining + buffer_seconds)
        
        # Minimum TTL of 1 hour
        return max(ttl, 3600)
