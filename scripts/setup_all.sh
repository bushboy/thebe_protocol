#!/bin/bash
# Zero-Trust Agentic Guardian - Complete System Setup Script
# Requirements: 17.1, 17.4, 17.5
#
# This script executes all configuration steps including:
# - Prerequisite validation
# - Auth0 setup
# - Certificate generation
# - Service initialization
# - Resource summary output

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Output files
SETUP_LOG="$PROJECT_ROOT/setup.log"
RESOURCE_SUMMARY="$PROJECT_ROOT/setup_summary.json"

# Initialize log file
echo "Zero-Trust Agentic Guardian Setup - $(date)" > "$SETUP_LOG"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$SETUP_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $1" >> "$SETUP_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$SETUP_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $1" >> "$SETUP_LOG"
}

# Print header
print_header() {
    echo ""
    echo "============================================================"
    echo "  Zero-Trust Agentic Guardian - System Setup"
    echo "============================================================"
    echo ""
}

# Validate prerequisites (Requirement 17.4)
validate_prerequisites() {
    log_info "Validating prerequisites..."

    local missing_deps=()

    # Check Python 3.14.2+
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f1)
        PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f2)
        PYTHON_PATCH=$(echo "$PYTHON_VERSION" | cut -d'.' -f3)

        if [ "$PYTHON_MAJOR" -gt 3 ] || \
           { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -gt 14 ]; } || \
           { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -eq 14 ] && [ "$PYTHON_PATCH" -ge 2 ]; }; then
            log_success "Python $PYTHON_VERSION found"
        else
            log_error "Python 3.14.2+ required (found $PYTHON_VERSION)"
            missing_deps+=("python3.14.2+")
        fi
    else
        log_error "Python 3 not found"
        missing_deps+=("python3.14.2+")
    fi

    # Check pip
    if command -v pip3 &> /dev/null; then
        log_success "pip3 found"
    else
        log_error "pip3 not found"
        missing_deps+=("pip3")
    fi

    # Check OpenSSL
    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version | cut -d' ' -f2)
        log_success "OpenSSL $OPENSSL_VERSION found"
    else
        log_error "OpenSSL not found"
        missing_deps+=("openssl")
    fi

    # Check Docker (optional but recommended)
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
        log_success "Docker $DOCKER_VERSION found"
    else
        log_warning "Docker not found (optional for deployment)"
    fi

    # Check Docker Compose (optional but recommended)
    if command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version | cut -d' ' -f4 | tr -d ',')
        log_success "Docker Compose $COMPOSE_VERSION found"
    else
        log_warning "Docker Compose not found (optional for deployment)"
    fi

    # Check for required environment variables
    if [ -z "$AUTH0_DOMAIN" ]; then
        log_warning "AUTH0_DOMAIN not set (required for Auth0 setup)"
    fi

    if [ -z "$AUTH0_MANAGEMENT_TOKEN" ]; then
        log_warning "AUTH0_MANAGEMENT_TOKEN not set (required for Auth0 setup)"
    fi

    # Check if virtual environment exists
    if [ -d "$PROJECT_ROOT/venv" ]; then
        log_success "Virtual environment found"
    else
        log_warning "Virtual environment not found (will be created)"
    fi

    # Report missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install missing dependencies and try again."
        echo ""
        exit 1
    fi

    log_success "All prerequisites validated"
    echo ""
}

# Setup Python virtual environment
setup_virtualenv() {
    log_info "Setting up Python virtual environment..."

    cd "$PROJECT_ROOT"

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log_success "Virtual environment created"
    else
        log_info "Virtual environment already exists"
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip >> "$SETUP_LOG" 2>&1

    # Install dependencies
    if [ -f "requirements.txt" ]; then
        log_info "Installing Python dependencies..."
        pip install -r requirements.txt >> "$SETUP_LOG" 2>&1
        log_success "Dependencies installed"
    fi

    # Install package in development mode
    if [ -f "setup.py" ]; then
        pip install -e . >> "$SETUP_LOG" 2>&1
        log_success "Package installed in development mode"
    fi

    echo ""
}

# Execute Auth0 setup (Requirement 17.1)
setup_auth0() {
    log_info "Executing Auth0 setup..."

    if [ -z "$AUTH0_DOMAIN" ] || [ -z "$AUTH0_MANAGEMENT_TOKEN" ]; then
        log_warning "Skipping Auth0 setup (environment variables not set)"
        log_warning "Set AUTH0_DOMAIN and AUTH0_MANAGEMENT_TOKEN to configure Auth0"
        echo ""
        return 0
    fi

    cd "$PROJECT_ROOT"

    # Run Auth0 setup script
    python3 infra/auth0/setup_auth0.py >> "$SETUP_LOG" 2>&1

    if [ $? -eq 0 ]; then
        log_success "Auth0 configuration complete"

        # Check if manifest was created
        if [ -f "infra/auth0/auth0_manifest.json" ]; then
            log_success "Auth0 manifest created: infra/auth0/auth0_manifest.json"
        fi
    else
        log_error "Auth0 setup failed (see $SETUP_LOG for details)"
        return 1
    fi

    echo ""
}

# Generate certificates (Requirement 17.1)
generate_certificates() {
    log_info "Generating mTLS certificates..."

    cd "$PROJECT_ROOT/infra/certificates"

    # Run certificate generation script
    if [ -f "generate_all_certs.sh" ]; then
        bash generate_all_certs.sh >> "$SETUP_LOG" 2>&1

        if [ $? -eq 0 ]; then
            log_success "Certificates generated successfully"

            # Verify root CA was created
            if [ -f "root_ca.crt" ] && [ -f "root_ca.key" ]; then
                log_success "Root CA created"
            fi

            # Count service certificates
            local cert_count=$(find . -name "*.crt" -not -name "root_ca.crt" | wc -l)
            log_success "Generated $cert_count service certificates"
        else
            log_error "Certificate generation failed (see $SETUP_LOG for details)"
            return 1
        fi
    else
        log_error "Certificate generation script not found"
        return 1
    fi

    cd "$PROJECT_ROOT"
    echo ""
}

# Initialize services (Requirement 17.1)
initialize_services() {
    log_info "Initializing services..."

    cd "$PROJECT_ROOT"

    # Create necessary directories
    local dirs=("logs" "data" "tmp")
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_success "Created directory: $dir"
        fi
    done

    # Initialize database (if needed)
    if [ -f "services/audit/init_db.py" ]; then
        log_info "Initializing audit database..."
        python3 services/audit/init_db.py >> "$SETUP_LOG" 2>&1
        if [ $? -eq 0 ]; then
            log_success "Audit database initialized"
        else
            log_warning "Audit database initialization failed (may already exist)"
        fi
    fi

    # Validate Docker Compose configuration
    if [ -f "infra/docker/docker-compose.yml" ]; then
        log_info "Validating Docker Compose configuration..."
        cd infra/docker
        docker-compose config >> "$SETUP_LOG" 2>&1
        if [ $? -eq 0 ]; then
            log_success "Docker Compose configuration valid"
        else
            log_warning "Docker Compose validation failed (Docker may not be available)"
        fi
        cd "$PROJECT_ROOT"
    fi

    echo ""
}

# Generate resource summary (Requirement 17.5)
generate_summary() {
    log_info "Generating resource summary..."

    local summary_json="{"
    summary_json+="\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    summary_json+="\"setup_status\":\"complete\","

    # Auth0 resources
    if [ -f "infra/auth0/auth0_manifest.json" ]; then
        local service_count=$(jq '.services | length' infra/auth0/auth0_manifest.json)
        local provider_count=$(jq '.provider_connections | length' infra/auth0/auth0_manifest.json)
        summary_json+="\"auth0\":{"
        summary_json+="\"manifest_file\":\"infra/auth0/auth0_manifest.json\","
        summary_json+="\"services_configured\":$service_count,"
        summary_json+="\"providers_configured\":$provider_count"
        summary_json+="},"
    else
        summary_json+="\"auth0\":{"
        summary_json+="\"status\":\"not_configured\""
        summary_json+="},"
    fi

    # Certificate resources
    if [ -f "infra/certificates/root_ca.crt" ]; then
        local cert_count=$(find infra/certificates -name "*.crt" -not -name "root_ca.crt" | wc -l)
        summary_json+="\"certificates\":{"
        summary_json+="\"root_ca\":\"infra/certificates/root_ca.crt\","
        summary_json+="\"service_certificates\":$cert_count"
        summary_json+="},"
    else
        summary_json+="\"certificates\":{"
        summary_json+="\"status\":\"not_generated\""
        summary_json+="},"
    fi

    # Service resources
    local service_dirs=$(find services -maxdepth 1 -type d -not -name "__pycache__" -not -name "services" | wc -l)
    summary_json+="\"services\":{"
    summary_json+="\"count\":$service_dirs,"
    summary_json+="\"directory\":\"services/\""
    summary_json+="},"

    # Docker resources
    if [ -f "infra/docker/docker-compose.yml" ]; then
        summary_json+="\"docker\":{"
        summary_json+="\"compose_file\":\"infra/docker/docker-compose.yml\","
        summary_json+="\"status\":\"ready\""
        summary_json+="},"
    fi

    # OPA resources
    if [ -f "infra/opa/policies.rego" ]; then
        summary_json+="\"opa\":{"
        summary_json+="\"policies_file\":\"infra/opa/policies.rego\""
        summary_json+="},"
    fi

    # Log file
    summary_json+="\"logs\":{"
    summary_json+="\"setup_log\":\"$SETUP_LOG\""
    summary_json+="}"

    summary_json+="}"

    # Save summary to file
    echo "$summary_json" | jq '.' > "$RESOURCE_SUMMARY"

    log_success "Resource summary saved to: $RESOURCE_SUMMARY"
    echo ""
}

# Display summary (Requirement 17.5)
display_summary() {
    echo ""
    echo "============================================================"
    echo "  Setup Complete!"
    echo "============================================================"
    echo ""

    if [ -f "$RESOURCE_SUMMARY" ]; then
        echo "Resource Summary:"
        echo ""
        jq '.' "$RESOURCE_SUMMARY"
        echo ""
    fi

    echo "Next Steps:"
    echo "  1. Review setup log: $SETUP_LOG"
    echo "  2. Review resource summary: $RESOURCE_SUMMARY"

    if [ -f "infra/auth0/auth0_manifest.json" ]; then
        echo "  3. Configure Auth0 Token Vault (Enterprise plan required)"
        echo "  4. Configure provider connections in Auth0 Dashboard"
    else
        echo "  3. Set AUTH0_DOMAIN and AUTH0_MANAGEMENT_TOKEN environment variables"
        echo "  4. Re-run this script to configure Auth0"
    fi

    echo "  5. Start services: cd infra/docker && docker-compose up"
    echo "  6. Run integration tests: bash scripts/run_integration_tests.sh"
    echo ""
    echo "For more information, see README.md"
    echo ""
}

# Main execution
main() {
    print_header

    # Step 1: Validate prerequisites
    validate_prerequisites

    # Step 2: Setup virtual environment
    setup_virtualenv

    # Step 3: Execute Auth0 setup
    setup_auth0

    # Step 4: Generate certificates
    generate_certificates

    # Step 5: Initialize services
    initialize_services

    # Step 6: Generate resource summary
    generate_summary

    # Step 7: Display summary
    display_summary

    log_success "Setup completed successfully!"
}

# Run main function
main
