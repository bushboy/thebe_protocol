"""Configuration for Audit Service."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuditConfig(BaseSettings):
    """Configuration settings for Audit Service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service settings
    host: str = "0.0.0.0"
    port: int = 8006

    # Database settings
    database_url: str = "postgresql://audit_user:audit_pass@localhost:5432/audit_db"

    # Auth0 settings
    auth0_domain: str = "dev-example.auth0.com"
    auth0_client_id: str = ""
    auth0_client_secret: str = ""

    # Certificate paths
    root_ca_path: Path = Path("infra/certificates/root_ca/ca.crt")
    client_cert_path: Path = Path("infra/certificates/audit/client.crt")
    client_key_path: Path = Path("infra/certificates/audit/client.key")
    server_cert_path: Path = Path("infra/certificates/audit/server.crt")
    server_key_path: Path = Path("infra/certificates/audit/server.key")

    # DPoP key path
    dpop_private_key_path: Path = Path("infra/auth0/audit_dpop_key.pem")

    # Genesis hash for hash chain
    genesis_hash: str = "genesis"

config = AuditConfig()
