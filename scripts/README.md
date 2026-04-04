# Operational Scripts

This directory contains operational scripts for managing the Zero-Trust Agentic Guardian system.

## Scripts

### 1. setup_all.sh / setup_all.bat

**Purpose:** Complete system setup script that executes all configuration steps.

**Requirements:** 17.1, 17.4, 17.5

**What it does:**
- Validates prerequisites (Python 3.14.2, pip, OpenSSL, Docker)
- Sets up Python virtual environment
- Installs dependencies
- Executes Auth0 setup (if credentials are provided)
- Generates mTLS certificates
- Initializes services
- Generates resource summary

**Usage:**

Linux/Mac:
```bash
# Set Auth0 credentials (optional)
export AUTH0_DOMAIN='your-tenant.auth0.com'
export AUTH0_MANAGEMENT_TOKEN='your-token-here'

# Run setup
bash scripts/setup_all.sh
```

Windows:
```cmd
REM Set Auth0 credentials (optional)
set AUTH0_DOMAIN=your-tenant.auth0.com
set AUTH0_MANAGEMENT_TOKEN=your-token-here

REM Run setup
scripts\setup_all.bat
```

**Output:**
- `setup.log` - Detailed setup log
- `setup_summary.json` - Resource summary in JSON format
- `infra/auth0/auth0_manifest.json` - Auth0 configuration (if Auth0 setup was run)
- `infra/certificates/` - Generated certificates

**Prerequisites:**
- Python 3.14.2
- pip
- OpenSSL
- Docker and Docker Compose (optional, for deployment)

---

### 2. run_integration_tests.sh / run_integration_tests.bat

**Purpose:** Run all integration tests and generate test reports.

**Requirement:** 17.2

**What it does:**
- Activates virtual environment
- Runs unit tests
- Runs integration tests
- Runs attack scenario tests
- Runs property-based tests
- Generates test report

**Usage:**

Linux/Mac:
```bash
bash scripts/run_integration_tests.sh
```

Windows:
```cmd
scripts\run_integration_tests.bat
```

**Output:**
- `integration_tests.log` - Detailed test log
- `integration_test_report.json` - Test results summary
- `*_test_results.xml` - JUnit XML test results

**Exit Codes:**
- `0` - All tests passed
- `1` - Some tests failed

**Test Suites:**
1. **Unit Tests** - Tests for individual components
2. **Integration Tests** - End-to-end flow tests
3. **Attack Scenario Tests** - Security validation tests
4. **Property-Based Tests** - Hypothesis-based correctness tests

---

### 3. rotate_certificates.sh / rotate_certificates.bat

**Purpose:** Perform zero-downtime certificate rotation.

**Requirement:** 17.3

**What it does:**
- Backs up existing certificates
- Generates new root CA and service certificates
- Verifies new certificates
- Updates service configurations
- Gracefully reloads services (if running)
- Cleans up old backups (keeps last 10)

**Usage:**

Linux/Mac:
```bash
bash scripts/rotate_certificates.sh
```

Windows:
```cmd
scripts\rotate_certificates.bat
```

**Interactive Prompt:**
The script will ask for confirmation before proceeding with rotation.

**Output:**
- `cert_rotation.log` - Detailed rotation log
- `infra/certificates/backups/YYYYMMDD_HHMMSS/` - Backup of old certificates
- `infra/certificates/` - New certificates

**Safety Features:**
- Automatic backup before rotation
- Certificate verification after generation
- Automatic rollback on failure
- Keeps last 10 backups for disaster recovery

**Zero-Downtime Rotation:**
If services are running in Docker Compose, the script will:
1. Generate new certificates
2. Reload services one by one with a 2-second delay between each
3. Maintain service availability during rotation

**Manual Service Restart:**
If services are running but not in Docker Compose, you'll need to manually restart them:
```bash
cd infra/docker
docker-compose restart
```

---

## Common Workflows

### Initial Setup

1. Run the setup script:
   ```bash
   bash scripts/setup_all.sh
   ```

2. Review the setup summary:
   ```bash
   cat setup_summary.json
   ```

3. Start services:
   ```bash
   cd infra/docker
   docker-compose up -d
   ```

4. Run integration tests:
   ```bash
   bash scripts/run_integration_tests.sh
   ```

### Regular Maintenance

**Weekly:**
- Run integration tests to verify system health
- Review audit logs

**Monthly:**
- Rotate certificates (recommended every 90 days, but can be done monthly)
- Review and clean up old backups

**As Needed:**
- Re-run setup script after configuration changes
- Rotate certificates after security incidents

### Certificate Rotation

1. Rotate certificates:
   ```bash
   bash scripts/rotate_certificates.sh
   ```

2. Verify services are healthy:
   ```bash
   cd infra/docker
   docker-compose ps
   ```

3. Run integration tests:
   ```bash
   bash scripts/run_integration_tests.sh
   ```

### Troubleshooting

**Setup fails:**
- Check `setup.log` for detailed error messages
- Verify prerequisites are installed
- Ensure Auth0 credentials are correct (if using Auth0 setup)

**Tests fail:**
- Check `integration_tests.log` for detailed error messages
- Verify services are running: `docker-compose ps`
- Check service logs: `docker-compose logs <service-name>`

**Certificate rotation fails:**
- Check `cert_rotation.log` for detailed error messages
- Certificates are automatically restored from backup on failure
- Verify OpenSSL is installed and accessible

---

## Environment Variables

### Auth0 Setup (Optional)

Required for Auth0 configuration:
- `AUTH0_DOMAIN` - Your Auth0 domain (e.g., 'your-tenant.auth0.com')
- `AUTH0_MANAGEMENT_TOKEN` - Auth0 Management API token

If not set, Auth0 setup will be skipped.

### Service Configuration

Services read configuration from:
- `infra/auth0/auth0_manifest.json` - Auth0 credentials
- `infra/certificates/` - mTLS certificates
- `.env` files in service directories

---

## Script Compatibility

All scripts are provided in two versions:
- `.sh` - For Linux and macOS (Bash)
- `.bat` - For Windows (Batch)

The functionality is identical across platforms.

---

## Logs and Reports

All scripts generate logs and reports in the project root:

| File | Description |
|------|-------------|
| `setup.log` | Detailed setup log |
| `setup_summary.json` | Setup resource summary |
| `integration_tests.log` | Test execution log |
| `integration_test_report.json` | Test results summary |
| `cert_rotation.log` | Certificate rotation log |

These files are useful for:
- Troubleshooting issues
- Auditing system changes
- Tracking test results over time

---

## Security Considerations

1. **Credentials:** Never commit Auth0 credentials or private keys to version control
2. **Backups:** Certificate backups contain private keys - store securely
3. **Logs:** Logs may contain sensitive information - review before sharing
4. **Permissions:** Ensure scripts have appropriate execute permissions

---

## Support

For issues or questions:
1. Check the logs for detailed error messages
2. Review the main README.md for system documentation
3. Consult the design document: `.kiro/specs/zero-trust-agentic-guardian/design.md`
