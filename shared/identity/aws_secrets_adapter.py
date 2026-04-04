"""AWS Secrets Manager adapter implementation.

This module implements the IVaultProvider interface for AWS Secrets Manager,
enabling the Identity Abstraction Layer to support AWS-native credential storage
and session management using Secrets Manager and DynamoDB.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
"""

import json
import uuid
import hashlib
import time
from typing import Dict, Any
from datetime import datetime, timedelta
from .ivault_provider import IVaultProvider
from .exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
)
from .retry import with_retry
from .metrics import record_metrics, record_revoke_session_metrics
from shared.schemas.models import RichAuthorizationRequest
from shared.logging.json_logger import JSONLogger

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    # Allow module to be imported even if boto3 is not installed
    # This enables testing without AWS dependencies
    boto3 = None
    ClientError = Exception
    BotoCoreError = Exception


logger = JSONLogger(__name__)


class AWSSecretsAdapter(IVaultProvider):
    """AWS Secrets Manager adapter implementation.

    This adapter implements the IVaultProvider interface for AWS Secrets Manager,
    retrieving provider credentials from Secrets Manager, generating provider tokens,
    and tracking session revocation in DynamoDB.

    Attributes:
        region: AWS region for Secrets Manager and DynamoDB
        secret_name_prefix: Prefix for secret names in Secrets Manager
        session_table_name: DynamoDB table name for session tracking
        timeout: Request timeout in seconds
        secrets_client: Boto3 Secrets Manager client
        dynamodb: Boto3 DynamoDB resource
        session_table: DynamoDB table for session tracking
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize AWS Secrets Manager adapter with configuration.

        Args:
            config: Configuration dictionary with keys:
                - region: AWS region (required)
                - secret_name_prefix: Prefix for secret names (required)
                - session_table_name: DynamoDB table for sessions (required)
                - timeout: Request timeout in seconds (optional, default: 10.0)

        Raises:
            VaultValidationError: If required configuration is missing or invalid
            VaultProviderError: If boto3 is not installed or AWS client initialization fails

        Requirements: 4.1, 4.6, 15.3
        """
        # Check if boto3 is available
        if boto3 is None:
            raise VaultProviderError(
                "boto3 is not installed. Install it with: pip install boto3"
            )

        # Validate required configuration fields
        if not config.get("region"):
            raise VaultValidationError("AWS region is required")
        if not config.get("secret_name_prefix"):
            raise VaultValidationError("AWS secret_name_prefix is required")
        if not config.get("session_table_name"):
            raise VaultValidationError("AWS session_table_name is required")

        self.region = config["region"].strip()
        self.secret_name_prefix = config["secret_name_prefix"].strip()
        self.session_table_name = config["session_table_name"].strip()
        self.timeout = config.get("timeout", 10.0)

        # Validate timeout is positive
        if self.timeout <= 0:
            raise VaultValidationError("Timeout must be a positive number")

        try:
            # Initialize AWS clients
            # Uses IAM role authentication if running on EC2/ECS/Lambda
            # or AWS credentials from environment/config file
            self.secrets_client = boto3.client(
                'secretsmanager',
                region_name=self.region
            )
            self.dynamodb = boto3.resource(
                'dynamodb',
                region_name=self.region
            )
            self.session_table = self.dynamodb.Table(self.session_table_name)

            logger.info(
                f"Initialized AWSSecretsAdapter",
                extra={
                    "region": self.region,
                    "secret_name_prefix": self.secret_name_prefix,
                    "session_table_name": self.session_table_name,
                    "timeout": self.timeout
                }
            )

        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            raise VaultProviderError(f"Failed to initialize AWS clients: {str(e)}")

    @staticmethod
    def _extract_aws_error(e: Exception) -> tuple[str, str]:
        """Extract AWS-style error code/message, with safe fallbacks."""
        response = getattr(e, "response", None)
        if isinstance(response, dict):
            error = response.get("Error", {})
            return error.get("Code", "Unknown"), error.get("Message", str(e))
        return "Unknown", str(e)

    @record_metrics('get_token')
    @with_retry(max_attempts=3, base_delay=1.0)
    async def get_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request provider token using credentials from AWS Secrets Manager.

        Retrieves provider credentials from AWS Secrets Manager, generates a
        provider token, and tracks the session in DynamoDB for revocation support.

        The secret name format is: {secret_name_prefix}/{provider}/credentials

        Expected secret structure:
        {
            "client_id": "...",
            "client_secret": "...",
            "api_key": "...",
            "access_token": "..."  # Optional: pre-generated token
        }

        Args:
            rar: Rich Authorization Request containing action details
            provider: Target provider (github, slack, google_workspace)

        Returns:
            Dictionary with token information:
                - access_token: Provider access token
                - token_type: Token type (normalized to "Bearer")
                - expires_in: Token expiration in seconds
                - scope: Granted scopes

        Raises:
            VaultProviderError: AWS API errors, secret not found, or network errors
            VaultAuthenticationError: Invalid AWS credentials
            VaultValidationError: Invalid RAR or malformed secret data
            VaultTimeoutError: Request timeout

        Requirements: 4.2, 4.6, 4.7
        """
        logger.info(f"Requesting token for provider: {provider}")

        # Construct secret name from prefix and provider
        secret_name = f"{self.secret_name_prefix}/{provider}/credentials"

        try:
            # Retrieve provider credentials from Secrets Manager
            logger.debug(f"Retrieving secret: {secret_name}")

            response = self.secrets_client.get_secret_value(SecretId=secret_name)

            # Parse secret JSON
            if 'SecretString' not in response:
                logger.error(f"Secret {secret_name} does not contain SecretString")
                raise VaultValidationError(f"Secret {secret_name} is not a string secret")

            try:
                credentials = json.loads(response['SecretString'])
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse secret JSON: {str(e)}")
                raise VaultValidationError(f"Secret {secret_name} contains invalid JSON: {str(e)}")

            # Validate credentials structure
            if not isinstance(credentials, dict):
                logger.error(f"Secret {secret_name} is not a JSON object")
                raise VaultValidationError(f"Secret {secret_name} must be a JSON object")

            # Generate provider token using retrieved credentials
            # If the secret contains a pre-generated access_token, use it
            # Otherwise, generate a token from the credentials
            if credentials.get("access_token"):
                access_token = credentials["access_token"]
                logger.debug("Using pre-generated access_token from secret")
            else:
                access_token = self._generate_token(credentials, provider)
                logger.debug("Generated token from credentials")

            # Construct token response
            token = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,  # Default 1 hour expiration
                "scope": " ".join(rar.actions)
            }

            # Track session in DynamoDB for revocation support
            session_id = self._generate_session_id()
            self._store_session(session_id, provider, token)

            logger.info(f"Provider token obtained successfully for {provider}")

            return token

        except ClientError as e:
            error_code, error_message = self._extract_aws_error(e)

            if error_code == 'ResourceNotFoundException':
                logger.error(f"Secret not found: {secret_name}")
                raise VaultProviderError(f"Secret not found: {secret_name}")

            elif error_code == 'InvalidRequestException':
                logger.error(f"Invalid AWS request: {error_message}")
                raise VaultAuthenticationError(f"Invalid AWS credentials or request: {error_message}")

            elif error_code == 'AccessDeniedException':
                logger.error(f"Access denied to secret: {secret_name}")
                raise VaultAuthenticationError(f"Access denied to secret {secret_name}: {error_message}")

            else:
                logger.error(f"AWS Secrets Manager error ({error_code}): {error_message}")
                raise VaultProviderError(f"AWS Secrets Manager error: {error_message}")

        except BotoCoreError as e:
            logger.error(f"AWS SDK error: {str(e)}")
            raise VaultProviderError(f"AWS SDK error: {str(e)}")

        except (VaultAuthenticationError, VaultValidationError, VaultProviderError):
            # Re-raise IAL exceptions as-is
            raise

        except Exception as e:
            logger.error(f"Unexpected error requesting AWS token: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_metrics('exchange_token')
    @with_retry(max_attempts=3, base_delay=1.0)
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange token by retrieving updated credentials from Secrets Manager.

        For AWS Secrets Manager, token exchange retrieves fresh credentials from
        Secrets Manager and generates a new token. This is different from OAuth
        token exchange since AWS Secrets Manager stores static credentials rather
        than managing OAuth flows.

        Args:
            existing_token: Current access token (not used for AWS adapter)
            new_scopes: Requested scopes for new token
            provider: Target provider

        Returns:
            Dictionary with new token information

        Raises:
            VaultProviderError: AWS API errors or network errors
            VaultAuthenticationError: Invalid AWS credentials
            VaultValidationError: Malformed secret data

        Requirements: 4.3
        """
        logger.info(f"Exchanging token for provider: {provider}")

        # Retrieve fresh credentials from Secrets Manager
        secret_name = f"{self.secret_name_prefix}/{provider}/credentials"

        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)

            if 'SecretString' not in response:
                raise VaultValidationError(f"Secret {secret_name} is not a string secret")

            try:
                credentials = json.loads(response['SecretString'])
            except json.JSONDecodeError as e:
                raise VaultValidationError(f"Secret {secret_name} contains invalid JSON: {str(e)}")

            # Generate new token from credentials
            if credentials.get("access_token"):
                access_token = credentials["access_token"]
            else:
                access_token = self._generate_token(credentials, provider)

            logger.info(f"Token exchanged successfully for {provider}")

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": " ".join(new_scopes)
            }

        except ClientError as e:
            error_code, error_message = self._extract_aws_error(e)

            logger.error(f"Token exchange failed ({error_code}): {error_message}")

            if error_code == 'InvalidRequestException':
                raise VaultAuthenticationError(f"Invalid AWS credentials: {error_message}")
            else:
                raise VaultProviderError(f"Token exchange failed: {error_message}")

        except (VaultAuthenticationError, VaultValidationError, VaultProviderError):
            raise

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_revoke_session_metrics
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke session by marking it as revoked in DynamoDB.

        Updates the session record in DynamoDB to mark it as revoked. The
        Executor Agent should check the revocation status before using tokens.

        Args:
            session_id: Session identifier to revoke

        Returns:
            True if revocation succeeded, False otherwise

        Requirements: 4.4
        """
        logger.info(f"Revoking session: {session_id[:8]}...")

        try:
            # Update session record in DynamoDB to mark as revoked
            self.session_table.update_item(
                Key={'session_id': session_id},
                UpdateExpression='SET revoked = :val, revoked_at = :time',
                ExpressionAttributeValues={
                    ':val': True,
                    ':time': datetime.utcnow().isoformat()
                }
            )

            logger.info("Session revoked successfully")
            return True

        except ClientError as e:
            error_code, error_message = self._extract_aws_error(e)
            logger.error(f"Session revocation failed ({error_code}): {error_message}")
            return False

        except Exception as e:
            logger.error(f"Session revocation failed: {str(e)}")
            return False

    async def health_check(self) -> bool:
        """Check AWS Secrets Manager availability.

        Verifies connectivity to AWS Secrets Manager by attempting to list
        secrets. This is a lightweight check that doesn't retrieve actual
        secret values.

        Returns:
            True if AWS Secrets Manager is accessible, False otherwise

        Requirements: 4.5
        """
        try:
            # Try to list secrets to verify connectivity
            # MaxResults=1 keeps the request lightweight
            self.secrets_client.list_secrets(MaxResults=1)

            logger.debug("AWS Secrets Manager health check passed")
            return True

        except Exception as e:
            logger.error(f"AWS Secrets Manager health check failed: {str(e)}")
            return False

    def get_provider_name(self) -> str:
        """Return provider name.

        Returns:
            "aws_secrets"

        Requirements: 4.1
        """
        return "aws_secrets"

    def _generate_token(self, credentials: Dict[str, Any], provider: str) -> str:
        """Generate provider token from credentials.

        This is a simplified implementation that generates a deterministic token
        from the credentials. In a production implementation, this would use
        provider-specific OAuth flows with the credentials to obtain real tokens.

        For example:
        - GitHub: Use client_id and client_secret to get OAuth token
        - Slack: Use api_key or OAuth credentials
        - Google Workspace: Use service account credentials

        Args:
            credentials: Dictionary containing provider credentials
            provider: Target provider name

        Returns:
            Generated token string

        Requirements: 4.2
        """
        # Generate a deterministic token from credentials and current time
        # This ensures each call produces a unique token
        token_input = f"{credentials.get('client_id', '')}:{provider}:{time.time()}"
        token_hash = hashlib.sha256(token_input.encode()).hexdigest()

        logger.debug(f"Generated token for provider: {provider}")

        return token_hash

    def _generate_session_id(self) -> str:
        """Generate unique session ID.

        Creates a UUID v4 session identifier for tracking sessions in DynamoDB.

        Returns:
            UUID string for session identification

        Requirements: 4.2
        """
        session_id = str(uuid.uuid4())
        logger.debug(f"Generated session ID: {session_id}")
        return session_id

    def _store_session(
        self,
        session_id: str,
        provider: str,
        token: Dict[str, Any]
    ) -> None:
        """Store session metadata in DynamoDB.

        Creates a session record in DynamoDB for tracking and revocation support.
        The record includes session ID, provider, creation time, expiration time,
        and revocation status.

        Args:
            session_id: Unique session identifier
            provider: Target provider name
            token: Token dictionary containing expires_in

        Raises:
            VaultProviderError: If DynamoDB write fails

        Requirements: 4.2, 4.6
        """
        try:
            # Calculate expiration time
            created_at = datetime.utcnow()
            expires_at = created_at + timedelta(seconds=token['expires_in'])

            # Store session metadata in DynamoDB
            self.session_table.put_item(
                Item={
                    'session_id': session_id,
                    'provider': provider,
                    'created_at': created_at.isoformat(),
                    'expires_at': expires_at.isoformat(),
                    'revoked': False
                }
            )

            logger.debug(
                f"Stored session in DynamoDB",
                extra={
                    "session_id": session_id,
                    "provider": provider,
                    "expires_at": expires_at.isoformat()
                }
            )

        except ClientError as e:
            error_code, error_message = self._extract_aws_error(e)
            logger.error(f"Failed to store session in DynamoDB ({error_code}): {error_message}")
            raise VaultProviderError(f"Failed to store session: {error_message}")

        except Exception as e:
            logger.error(f"Failed to store session in DynamoDB: {str(e)}")
            raise VaultProviderError(f"Failed to store session: {str(e)}")
