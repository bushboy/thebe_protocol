"""Pydantic data models for the Zero-Trust Agentic Guardian Architecture.

This module defines all shared data structures used across services:
- IntentSignature: Semantic embeddings and cryptographic signatures
- PolicyDecision: OPA policy evaluation results
- RichAuthorizationRequest: Detailed authorization requests
- ZeroTrustAuthorizationToken: Complete authorization chain tokens
- AuditLogEntry: Cryptographically chained audit log entries
- DPoPProof: Proof-of-possession token structure

Requirements: 4.6
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class DPoPProof(BaseModel):
    """DPoP (Demonstrating Proof-of-Possession) proof structure."""

    jti: str = Field(..., description="Unique token identifier")
    htm: str = Field(..., description="HTTP method")
    htu: str = Field(..., description="HTTP URI")
    iat: int = Field(..., description="Issued at timestamp")
    ath: str = Field(..., description="Access token hash (SHA256)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "htm": "POST",
                "htu": "https://api.example.com/resource",
                "iat": 1705320600,
                "ath": "a1b2c3d4e5f6..."
            }
        }
    }


class IntentSignature(BaseModel):
    """Cryptographic intent signature with semantic embeddings."""

    embedding: List[float] = Field(..., description="Semantic embedding vector")
    hash: str = Field(..., description="SHA256 hash of user goal")
    allowed_actions: List[str] = Field(..., description="List of permitted action types")
    semantic_similarity_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Cosine similarity score between user goal and representative allowed action"
    )
    semantic_match_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Configured semantic match threshold used by intent verification"
    )
    timestamp: datetime = Field(..., description="Signature creation time")
    signature: str = Field(..., description="Cryptographic signature")

    @field_validator('embedding')
    @classmethod
    def validate_embedding_dimensionality(cls, v):
        """Validate embedding has correct dimensionality (384 for all-MiniLM-L6-v2)."""
        if len(v) != 384:
            raise ValueError(f"Embedding must have 384 dimensions, got {len(v)}")
        return v

    @field_validator('hash')
    @classmethod
    def validate_hash_format(cls, v):
        """Validate hash is 64 hex characters (SHA256)."""
        if len(v) != 64 or not all(c in '0123456789abcdef' for c in v.lower()):
            raise ValueError("Hash must be 64 hexadecimal characters (SHA256)")
        return v

    @field_validator('allowed_actions')
    @classmethod
    def validate_allowed_actions_non_empty(cls, v):
        """Validate allowed actions list is non-empty."""
        if not v:
            raise ValueError("Allowed actions list cannot be empty")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "embedding": [0.123, -0.456] + [0.0] * 382,  # 384 dimensions
                "hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                "allowed_actions": ["github:create_branch", "github:create_pr"],
                "semantic_similarity_score": 0.91,
                "semantic_match_threshold": 0.70,
                "timestamp": "2024-01-15T10:30:00Z",
                "signature": "e5f6g7h8..."
            }
        }
    }


class PolicyDecision(BaseModel):
    """OPA policy evaluation decision."""

    decision: str = Field(..., pattern="^(ALLOW|DENY)$", description="Policy decision")
    reason: str = Field(..., description="Human-readable explanation")
    evaluated_policies: List[str] = Field(..., description="List of policy names evaluated")
    semantic_similarity_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Cosine similarity score from intent verification"
    )
    semantic_match_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Configured semantic match threshold used for decision context"
    )
    signature: str = Field(..., description="Safety Agent signature")
    timestamp: datetime = Field(..., description="Decision time")
    signer_identity: str = Field(..., description="Certificate subject of signer")

    model_config = {
        "json_schema_extra": {
            "example": {
                "decision": "ALLOW",
                "reason": "All policies passed",
                "evaluated_policies": ["destructive_actions", "spending_limits"],
                "semantic_similarity_score": 0.91,
                "semantic_match_threshold": 0.70,
                "signature": "sig123...",
                "timestamp": "2024-01-15T10:31:00Z",
                "signer_identity": "CN=safety-agent"
            }
        }
    }


class RichAuthorizationRequest(BaseModel):
    """Rich Authorization Request (RAR) for provider token requests."""

    type: str = Field(..., description="Action type identifier")
    actions: List[str] = Field(..., description="Required OAuth scopes")
    locations: List[str] = Field(..., description="Resource URLs")
    purpose: str = Field(..., description="Purpose of access")
    context: Dict[str, Any] = Field(..., description="Additional context")

    model_config = {
        "json_schema_extra": {
            "example": {
                "type": "github_action",
                "actions": ["repo:write"],
                "locations": ["https://github.com/org/repo"],
                "purpose": "task_execution",
                "context": {
                    "plan_id": "plan_123",
                    "task_id": "task_456",
                    "intent_hash": "a1b2c3..."
                }
            }
        }
    }


class ZeroTrustAuthorizationToken(BaseModel):
    """Zero-Trust Authorization Token containing complete authorization chain."""

    plan_id: str = Field(..., description="Unique plan identifier")
    task_id: str = Field(..., description="Unique task identifier")
    action: str = Field(..., description="Action to be performed")
    provider: str = Field(..., description="Target provider")
    action_params_hash: str = Field(
        default="",
        description="SHA256 hash of canonical action_params approved at authorization time"
    )
    policy_approval: PolicyDecision = Field(..., description="Safety Agent approval")
    intent_signature: IntentSignature = Field(..., description="Intent verification")
    broker_signature: str = Field(..., description="Permission Broker signature")
    issued_at: datetime = Field(..., description="Token issuance time")
    expires_at: datetime = Field(..., description="Token expiration time")
    nonce: str = Field(..., description="Unique nonce for replay prevention")

    model_config = {
        "json_schema_extra": {
            "example": {
                "plan_id": "plan_123",
                "task_id": "task_456",
                "action": "create_branch",
                "provider": "github",
                "action_params_hash": "8dfc3f54a6f79f06b1f9f95f8f76d5956f48811d6f095e2f4f8a7db8f7b7cb3b",
                "policy_approval": {
                    "decision": "ALLOW",
                    "reason": "All policies passed",
                    "evaluated_policies": ["destructive_actions"],
                    "signature": "sig123...",
                    "timestamp": "2024-01-15T10:31:00Z",
                    "signer_identity": "CN=safety-agent"
                },
                "intent_signature": {
                    "embedding": [0.123] * 384,
                    "hash": "a1b2c3...",
                    "allowed_actions": ["github:create_branch"],
                    "timestamp": "2024-01-15T10:30:00Z",
                    "signature": "sig456..."
                },
                "broker_signature": "broker_sig789...",
                "issued_at": "2024-01-15T10:32:00Z",
                "expires_at": "2024-01-15T10:37:00Z",
                "nonce": "nonce_abc123"
            }
        }
    }


class AuditLogEntry(BaseModel):
    """Cryptographically chained audit log entry."""

    log_id: str = Field(..., description="Unique log entry ID")
    component: str = Field(..., description="Service that generated the log")
    event_type: str = Field(..., description="Type of event")
    action_metadata: Dict[str, Any] = Field(..., description="Action-specific data")
    zt_at: Optional[ZeroTrustAuthorizationToken] = Field(None, description="Associated ZT-AT")
    dpop_fingerprint: str = Field(..., description="DPoP key fingerprint")
    timestamp: datetime = Field(..., description="Event timestamp")
    hash: str = Field(..., description="Current entry hash")
    previous_hash: str = Field(..., description="Previous entry hash")

    model_config = {
        "json_schema_extra": {
            "example": {
                "log_id": "log_001",
                "component": "executor",
                "event_type": "action_executed",
                "action_metadata": {
                    "action": "create_branch",
                    "provider": "github",
                    "result": "success"
                },
                "zt_at": None,
                "dpop_fingerprint": "fp_abc123",
                "timestamp": "2024-01-15T10:33:00Z",
                "hash": "hash_current",
                "previous_hash": "hash_previous"
            }
        }
    }
