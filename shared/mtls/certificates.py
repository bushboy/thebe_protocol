"""mTLS certificate loading and validation module.

This module provides certificate handling functionality:
- Load PEM certificates using cryptography library
- Extract client identity from certificate subject
- Validate certificate chain against root CA

Requirements: 4.5
"""

from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID


class CertificateValidationError(Exception):
    """Raised when certificate validation fails."""
    pass


class CertificateLoader:
    """Loads and validates X.509 certificates for mTLS."""
    
    def __init__(self, root_ca_pem: Optional[str] = None):
        """Initialize certificate loader.
        
        Args:
            root_ca_pem: Optional PEM-encoded root CA certificate for chain validation
        """
        self.root_ca_cert = None
        if root_ca_pem:
            self.root_ca_cert = self._load_certificate_from_pem(root_ca_pem)
    
    def _load_certificate_from_pem(self, pem_data: str) -> x509.Certificate:
        """Load certificate from PEM string.
        
        Args:
            pem_data: PEM-encoded certificate string
            
        Returns:
            Loaded certificate object
            
        Raises:
            CertificateValidationError: If PEM data is invalid
        """
        try:
            cert = x509.load_pem_x509_certificate(
                pem_data.encode(),
                backend=default_backend()
            )
            return cert
        except Exception as e:
            raise CertificateValidationError(f"Failed to load certificate from PEM: {str(e)}")
    
    def load_certificate(self, pem_data: str) -> x509.Certificate:
        """Load certificate from PEM format.
        
        Args:
            pem_data: PEM-encoded certificate string
            
        Returns:
            Loaded certificate object
            
        Raises:
            CertificateValidationError: If certificate cannot be loaded
        """
        return self._load_certificate_from_pem(pem_data)
    
    def extract_client_identity(self, cert: x509.Certificate) -> str:
        """Extract client identity from certificate subject.
        
        Extracts the Common Name (CN) from the certificate subject field.
        
        Args:
            cert: X.509 certificate object
            
        Returns:
            Client identity string (Common Name from subject)
            
        Raises:
            CertificateValidationError: If CN cannot be extracted
        """
        try:
            # Get the subject from the certificate
            subject = cert.subject
            
            # Extract Common Name (CN) attribute
            cn_attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            
            if not cn_attributes:
                raise CertificateValidationError("Certificate subject missing Common Name (CN)")
            
            # Return the first CN value
            return cn_attributes[0].value
            
        except CertificateValidationError:
            raise
        except Exception as e:
            raise CertificateValidationError(f"Failed to extract client identity: {str(e)}")
    
    def validate_certificate_chain(self, cert: x509.Certificate) -> bool:
        """Validate certificate chain against root CA.
        
        Verifies that the certificate is signed by the trusted root CA.
        
        Args:
            cert: X.509 certificate to validate
            
        Returns:
            True if certificate is valid and signed by root CA
            
        Raises:
            CertificateValidationError: If validation fails or root CA not configured
        """
        if not self.root_ca_cert:
            raise CertificateValidationError("Root CA certificate not configured")
        
        try:
            # Get the issuer from the certificate
            cert_issuer = cert.issuer
            
            # Get the subject from the root CA
            ca_subject = self.root_ca_cert.subject
            
            # Verify issuer matches CA subject
            if cert_issuer != ca_subject:
                raise CertificateValidationError(
                    f"Certificate issuer does not match root CA subject. "
                    f"Issuer: {cert_issuer}, CA Subject: {ca_subject}"
                )
            
            # Verify signature using root CA public key
            ca_public_key = self.root_ca_cert.public_key()
            
            # Verify the certificate signature
            # Note: We use the signature hash algorithm from the certificate
            try:
                from cryptography.hazmat.primitives.asymmetric import padding
                
                if isinstance(ca_public_key, rsa.RSAPublicKey):
                    # For RSA signatures, use PKCS1v15 padding with the hash algorithm from cert
                    ca_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                    # For EC signatures, use ECDSA with the hash algorithm from cert
                    from cryptography.hazmat.primitives.asymmetric import ec as ec_module
                    ca_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec_module.ECDSA(cert.signature_hash_algorithm)
                    )
                else:
                    raise CertificateValidationError(
                        f"Unsupported public key type: {type(ca_public_key)}"
                    )
            except Exception as e:
                raise CertificateValidationError(f"Certificate signature verification failed: {str(e)}")
            
            return True
            
        except CertificateValidationError:
            raise
        except Exception as e:
            raise CertificateValidationError(f"Certificate chain validation failed: {str(e)}")
    
    def load_and_validate(self, cert_pem: str) -> tuple[x509.Certificate, str]:
        """Load certificate and extract identity with optional chain validation.
        
        Convenience method that loads a certificate, validates it against the root CA
        (if configured), and extracts the client identity.
        
        Args:
            cert_pem: PEM-encoded certificate string
            
        Returns:
            Tuple of (certificate object, client identity string)
            
        Raises:
            CertificateValidationError: If loading, validation, or identity extraction fails
        """
        # Load certificate
        cert = self.load_certificate(cert_pem)
        
        # Validate against root CA if configured
        if self.root_ca_cert:
            self.validate_certificate_chain(cert)
        
        # Extract client identity
        identity = self.extract_client_identity(cert)
        
        return cert, identity
