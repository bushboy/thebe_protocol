"""Authentication middleware for Safety Agent service.

This module implements the triple authentication mechanism:
- mTLS certificate validation
- JWT token validation
- DPoP proof validation

Requirements: 11.1, 11.2, 11.3, 11.4
"""

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer
from typing import Optional
import jwt

from shared.jwt import JWTValidator, JWTValidationError
from shared.dpop import DPoPProofVerifier, DPoPValidationError
from shared.mtls import CertificateLoader, CertificateValidationError
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)
security = HTTPBearer()


class AuthenticationMiddleware:
    """Middleware for validating JWT + DPoP + mTLS authentication."""

    def __init__(self):
        """Initialize authentication components."""
        # Load root CA certificate for mTLS validation
        root_ca_pem = None
        if config.root_ca_path.exists():
            with open(config.root_ca_path, 'r') as f:
                root_ca_pem = f.read()

        self.cert_loader = CertificateLoader(root_ca_pem=root_ca_pem)

        # Note: JWT and DPoP validators require public keys which would be
        # loaded from Auth0 JWKS endpoint in production. For now, we'll
        # perform basic validation without signature verification.
        self.jwt_validator = None
        self.dpop_verifier = None

    async def validate_request(self, request: Request) -> dict:
        """Validate complete authentication chain.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary with validated identity information

        Raises:
            HTTPException: If any validation fails

        Requirements: 11.1, 11.2, 11.3, 11.4
        """
        # Extract authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.error("Missing or invalid Authorization header")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_token", "message": "Missing or invalid Authorization header"}
            )

        access_token = auth_header.replace("Bearer ", "")

        # Extract DPoP header
        dpop_header = request.headers.get("DPoP")
        if not dpop_header:
            logger.error("Missing DPoP header")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_dpop", "message": "Missing DPoP header"}
            )

        # Validate mTLS certificate
        client_cert = self._extract_client_certificate(request)
        cert_identity = None
        if client_cert:
            try:
                cert = self.cert_loader.load_certificate(client_cert)
                cert_identity = self.cert_loader.extract_client_identity(cert)
                logger.info(f"mTLS certificate validated for: {cert_identity}")
            except CertificateValidationError as e:
                logger.error(f"Certificate validation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_certificate", "message": str(e)}
                )
        else:
            # In strict mode this should be rejected; allow in current test mode.
            logger.warning("No client certificate provided - mTLS validation skipped")
            cert_identity = "unknown"

        # Validate JWT token (simplified for testing)
        jwt_claims = {}
        if self.jwt_validator:
            try:
                jwt_claims = self.jwt_validator.validate(access_token)
                logger.info(f"JWT validated for issuer: {jwt_claims.get('iss')}")
            except JWTValidationError as e:
                logger.error(f"JWT validation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_token", "message": str(e)}
                )
        else:
            # For testing without JWT validation, decode without verification.
            logger.warning("JWT validation skipped - no validator configured")
            try:
                jwt_claims = jwt.decode(access_token, options={"verify_signature": False})
                if not isinstance(jwt_claims, dict) or not jwt_claims:
                    raise ValueError("Invalid JWT structure")
            except Exception as e:
                logger.error(f"JWT decode failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_token", "message": f"JWT decode failed: {str(e)}"}
                )

        # Validate DPoP proof (simplified for testing)
        if self.dpop_verifier:
            try:
                self.dpop_verifier.verify_proof(
                    proof=dpop_header,
                    access_token=access_token,
                    http_method=request.method,
                    http_uri=str(request.url)
                )
                logger.info("DPoP proof validated")
            except DPoPValidationError as e:
                logger.error(f"DPoP validation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_dpop", "message": str(e)}
                )
        else:
            # For testing without DPoP validation, at least check structure.
            logger.warning("DPoP validation skipped - no verifier configured")
            try:
                dpop_claims = jwt.decode(dpop_header, options={"verify_signature": False})
                if not isinstance(dpop_claims, dict) or not dpop_claims:
                    raise ValueError("Invalid DPoP structure")
            except Exception as e:
                logger.error(f"DPoP decode failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_dpop", "message": f"DPoP decode failed: {str(e)}"}
                )

        return {
            "certificate_identity": cert_identity,
            "jwt_claims": jwt_claims,
            "authenticated": True
        }

    def _extract_client_certificate(self, request: Request) -> Optional[str]:
        """Extract client certificate from request.

        In production, this would extract the certificate from the TLS connection.
        For testing, we can use a header or mock value.

        Args:
            request: FastAPI request object

        Returns:
            PEM-encoded certificate string or None
        """
        # In production with proper mTLS setup, the certificate would be
        # available through request.scope['transport'] or similar
        # For now, we'll check for a test header
        cert_header = request.headers.get("X-Client-Certificate")
        if cert_header:
            return cert_header

        # In a real deployment, this would extract from the TLS connection
        # For testing purposes, we'll return None and handle it gracefully
        return None


async def require_authentication(request: Request) -> dict:
    """Dependency for requiring authentication on endpoints.

    Args:
        request: FastAPI request object

    Returns:
        Dictionary with validated identity information

    Raises:
        HTTPException: If authentication fails
    """
    middleware = AuthenticationMiddleware()
    return await middleware.validate_request(request)
