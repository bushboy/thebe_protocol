#!/usr/bin/env python3
"""Configuration migration script for Identity Abstraction Layer.

This script migrates existing TokenVaultClient configuration to the new
IAL configuration format. It:
1. Reads existing Permission Broker configuration
2. Detects TokenVaultClient configuration parameters
3. Generates new IALConfig with identity_provider set to "auth0"
4. Validates generated configuration
5. Creates backup of original configuration
6. Writes new configuration file
7. Outputs summary of migration changes

Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import shutil

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.identity.config_models import IALConfig
from pydantic import ValidationError


class ConfigMigrator:
    """Handles migration of TokenVaultClient configuration to IAL format."""
    
    def __init__(self, config_file: Path, backup: bool = True, dry_run: bool = False):
        """Initialize the migrator.
        
        Args:
            config_file: Path to configuration file to migrate
            backup: Whether to create backup of original file
            dry_run: If True, don't write changes, just show what would be done
        """
        self.config_file = config_file
        self.backup = backup
        self.dry_run = dry_run
        self.changes: list[str] = []
    
    def detect_legacy_config(self, config: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Detect TokenVaultClient configuration parameters.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Tuple of (is_legacy, legacy_params)
            
        Requirements: 24.1
        """
        legacy_keys = {
            "auth0_domain",
            "auth0_client_id",
            "auth0_client_secret",
            "auth0_audience",
            "auth0_token_vault_url"
        }
        
        found_keys = legacy_keys.intersection(config.keys())
        
        # Check if we have the minimum required legacy config
        required_legacy = {"auth0_domain", "auth0_client_id", "auth0_client_secret"}
        has_legacy = required_legacy.issubset(found_keys)
        
        legacy_params = {key: config[key] for key in found_keys if key in config}
        
        return has_legacy, legacy_params
    
    def generate_ial_config(self, legacy_params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate new IALConfig from legacy parameters.
        
        Args:
            legacy_params: Legacy TokenVaultClient parameters
            
        Returns:
            New IAL configuration dictionary
            
        Requirements: 24.2, 24.3
        """
        # Create IAL configuration with Auth0 adapter
        ial_config = {
            "identity_provider": "auth0",
            "auth0_config": {
                "domain": legacy_params.get("auth0_domain"),
                "client_id": legacy_params.get("auth0_client_id"),
                "client_secret": legacy_params.get("auth0_client_secret"),
                "timeout": 10.0  # Default timeout
            }
        }
        
        # Add optional token_vault_url if present
        if "auth0_token_vault_url" in legacy_params and legacy_params["auth0_token_vault_url"]:
            ial_config["auth0_config"]["token_vault_url"] = legacy_params["auth0_token_vault_url"]
        
        self.changes.append(f"✓ Set identity_provider to 'auth0'")
        self.changes.append(f"✓ Migrated auth0_domain to ial_auth0_domain")
        self.changes.append(f"✓ Migrated auth0_client_id to ial_auth0_client_id")
        self.changes.append(f"✓ Migrated auth0_client_secret to ial_auth0_client_secret")
        
        if "token_vault_url" in ial_config["auth0_config"]:
            self.changes.append(f"✓ Migrated auth0_token_vault_url to ial_auth0_token_vault_url")
        
        self.changes.append(f"✓ Set default timeout to 10.0 seconds")
        
        return ial_config
    
    def validate_ial_config(self, ial_config: Dict[str, Any]) -> bool:
        """Validate generated IAL configuration using Pydantic models.
        
        Args:
            ial_config: IAL configuration dictionary
            
        Returns:
            True if valid, False otherwise
            
        Requirements: 24.4
        """
        try:
            # Validate using IALConfig model
            validated_config = IALConfig(**ial_config)
            self.changes.append(f"✓ Configuration validation passed")
            return True
        except ValidationError as e:
            print(f"❌ Configuration validation failed:")
            print(e)
            return False
    
    def create_backup(self) -> Optional[Path]:
        """Create backup of original configuration file.
        
        Returns:
            Path to backup file, or None if backup failed
            
        Requirements: 24.5
        """
        if not self.backup:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.config_file.with_suffix(f".backup_{timestamp}{self.config_file.suffix}")
        
        try:
            shutil.copy2(self.config_file, backup_path)
            self.changes.append(f"✓ Created backup at {backup_path}")
            return backup_path
        except Exception as e:
            print(f"❌ Failed to create backup: {e}")
            return None
    
    def convert_to_env_format(self, ial_config: Dict[str, Any]) -> Dict[str, str]:
        """Convert IAL config to environment variable format.
        
        Args:
            ial_config: IAL configuration dictionary
            
        Returns:
            Dictionary of environment variables
        """
        env_vars = {
            "IDENTITY_PROVIDER": ial_config["identity_provider"]
        }
        
        if "auth0_config" in ial_config:
            auth0 = ial_config["auth0_config"]
            env_vars["IAL_AUTH0_DOMAIN"] = auth0["domain"]
            env_vars["IAL_AUTH0_CLIENT_ID"] = auth0["client_id"]
            env_vars["IAL_AUTH0_CLIENT_SECRET"] = auth0["client_secret"]
            env_vars["IAL_AUTH0_TIMEOUT"] = str(auth0.get("timeout", 10.0))
            
            if "token_vault_url" in auth0:
                env_vars["IAL_AUTH0_TOKEN_VAULT_URL"] = auth0["token_vault_url"]
        
        return env_vars
    
    def write_config_file(self, env_vars: Dict[str, str]) -> bool:
        """Write new configuration file.
        
        Args:
            env_vars: Environment variables to write
            
        Returns:
            True if successful, False otherwise
            
        Requirements: 24.6
        """
        if self.dry_run:
            self.changes.append(f"✓ [DRY RUN] Would write configuration to {self.config_file}")
            return True
        
        try:
            # Read existing file to preserve other settings
            existing_lines = []
            legacy_keys_to_remove = {
                "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET",
                "AUTH0_AUDIENCE", "AUTH0_TOKEN_VAULT_URL"
            }
            
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    for line in f:
                        # Skip legacy Auth0 config lines
                        if '=' in line:
                            key = line.split('=')[0].strip()
                            if key not in legacy_keys_to_remove:
                                existing_lines.append(line)
                        else:
                            existing_lines.append(line)
            
            # Write updated configuration
            with open(self.config_file, 'w') as f:
                # Write existing non-Auth0 lines
                for line in existing_lines:
                    f.write(line)
                
                # Add IAL configuration section
                f.write("\n# Identity Abstraction Layer Configuration\n")
                f.write("# Migrated from legacy TokenVaultClient configuration\n")
                for key, value in env_vars.items():
                    f.write(f"{key}={value}\n")
            
            self.changes.append(f"✓ Wrote new configuration to {self.config_file}")
            return True
        except Exception as e:
            print(f"❌ Failed to write configuration file: {e}")
            return False
    
    def output_summary(self):
        """Output summary of migration changes.
        
        Requirements: 24.7
        """
        print("\n" + "=" * 70)
        print("IAL Configuration Migration Summary")
        print("=" * 70)
        print(f"\nConfiguration file: {self.config_file}")
        print(f"Dry run mode: {'Yes' if self.dry_run else 'No'}")
        print(f"\nChanges:")
        for change in self.changes:
            print(f"  {change}")
        print("\n" + "=" * 70)
        
        if not self.dry_run:
            print("\n✅ Migration completed successfully!")
            print("\nNext steps:")
            print("1. Review the migrated configuration")
            print("2. Update any deployment scripts to use new IAL environment variables")
            print("3. Test the Permission Broker with the new configuration")
            print("4. Remove legacy Auth0 environment variables from your deployment")
        else:
            print("\n📋 This was a dry run. No files were modified.")
            print("Run without --dry-run to apply changes.")
    
    def migrate(self) -> bool:
        """Perform the migration.
        
        Returns:
            True if migration successful, False otherwise
        """
        print(f"Starting IAL configuration migration...")
        print(f"Config file: {self.config_file}")
        
        # Check if file exists
        if not self.config_file.exists():
            print(f"❌ Configuration file not found: {self.config_file}")
            return False
        
        # Read configuration file
        try:
            config = {}
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip().lower()] = value.strip()
        except Exception as e:
            print(f"❌ Failed to read configuration file: {e}")
            return False
        
        # Detect legacy configuration
        has_legacy, legacy_params = self.detect_legacy_config(config)
        
        if not has_legacy:
            print("ℹ️  No legacy TokenVaultClient configuration detected.")
            print("   Configuration may already be migrated or using a different format.")
            return False
        
        print(f"✓ Detected legacy TokenVaultClient configuration")
        
        # Generate IAL configuration
        ial_config = self.generate_ial_config(legacy_params)
        
        # Validate configuration
        if not self.validate_ial_config(ial_config):
            return False
        
        # Create backup
        if self.backup and not self.dry_run:
            backup_path = self.create_backup()
            if backup_path is None and self.backup:
                print("❌ Backup creation failed. Aborting migration.")
                return False
        
        # Convert to environment variable format
        env_vars = self.convert_to_env_format(ial_config)
        
        # Write new configuration
        if not self.write_config_file(env_vars):
            return False
        
        # Output summary
        self.output_summary()
        
        return True


def main():
    """Main entry point for migration script."""
    parser = argparse.ArgumentParser(
        description="Migrate TokenVaultClient configuration to IAL format"
    )
    parser.add_argument(
        "config_file",
        type=Path,
        help="Path to configuration file to migrate (e.g., .env)"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup of original file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    
    args = parser.parse_args()
    
    migrator = ConfigMigrator(
        config_file=args.config_file,
        backup=not args.no_backup,
        dry_run=args.dry_run
    )
    
    success = migrator.migrate()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
