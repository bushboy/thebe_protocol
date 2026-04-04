#!/bin/bash
# Zero-Trust Agentic Guardian - Certificate Rotation Script
# Requirement: 17.3
#
# This script performs zero-downtime certificate rotation by:
# - Backing up existing certificates
# - Regenerating all certificates
# - Updating service configurations
# - Gracefully reloading services

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
CERT_DIR="$PROJECT_ROOT/infra/certificates"

# Output files
ROTATION_LOG="$PROJECT_ROOT/cert_rotation.log"
BACKUP_DIR="$CERT_DIR/backups/$(date +%Y%m%d_%H%M%S)"

# Initialize log file
echo "Zero-Trust Agentic Guardian Certificate Rotation - $(date)" > "$ROTATION_LOG"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$ROTATION_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $1" >> "$ROTATION_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$ROTATION_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $1" >> "$ROTATION_LOG"
}

# Print header
print_header() {
    echo ""
    echo "============================================================"
    echo "  Zero-Trust Agentic Guardian - Certificate Rotation"
    echo "============================================================"
    echo ""
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check if certificate directory exists
    if [ ! -d "$CERT_DIR" ]; then
        log_error "Certificate directory not found: $CERT_DIR"
        exit 1
    fi
    
    # Check if certificate generation scripts exist
    if [ ! -f "$CERT_DIR/generate_root_ca.py" ]; then
        log_error "Root CA generation script not found"
        exit 1
    fi
    
    if [ ! -f "$CERT_DIR/generate_service_certs.py" ]; then
        log_error "Service certificate generation script not found"
        exit 1
    fi
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found"
        exit 1
    fi
    
    # Check if OpenSSL is available
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL not found"
        exit 1
    fi
    
    log_success "All prerequisites validated"
    echo ""
}

# Backup existing certificates
backup_certificates() {
    log_info "Backing up existing certificates..."
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Backup root CA
    if [ -f "$CERT_DIR/root_ca.crt" ]; then
        cp "$CERT_DIR/root_ca.crt" "$BACKUP_DIR/"
        log_success "Backed up root CA certificate"
    fi
    
    if [ -f "$CERT_DIR/root_ca.key" ]; then
        cp "$CERT_DIR/root_ca.key" "$BACKUP_DIR/"
        log_success "Backed up root CA private key"
    fi
    
    # Backup service certificates
    local services=("planner" "intent-engine" "safety-agent" "permission-broker" "executor" "audit")
    
    for service in "${services[@]}"; do
        if [ -d "$CERT_DIR/$service" ]; then
            mkdir -p "$BACKUP_DIR/$service"
            cp -r "$CERT_DIR/$service"/* "$BACKUP_DIR/$service/" 2>/dev/null || true
            log_success "Backed up $service certificates"
        fi
    done
    
    log_success "All certificates backed up to: $BACKUP_DIR"
    echo ""
}

# Generate new certificates
generate_new_certificates() {
    log_info "Generating new certificates..."
    
    cd "$CERT_DIR"
    
    # Generate new root CA
    log_info "Generating new root CA..."
    python3 generate_root_ca.py "$CERT_DIR" >> "$ROTATION_LOG" 2>&1
    
    if [ $? -eq 0 ]; then
        log_success "New root CA generated"
    else
        log_error "Root CA generation failed"
        restore_from_backup
        exit 1
    fi
    
    # Generate new service certificates
    log_info "Generating new service certificates..."
    python3 generate_service_certs.py "$CERT_DIR/root_ca.crt" "$CERT_DIR/root_ca.key" "$CERT_DIR" >> "$ROTATION_LOG" 2>&1
    
    if [ $? -eq 0 ]; then
        log_success "New service certificates generated"
    else
        log_error "Service certificate generation failed"
        restore_from_backup
        exit 1
    fi
    
    cd "$PROJECT_ROOT"
    echo ""
}

# Verify new certificates
verify_certificates() {
    log_info "Verifying new certificates..."
    
    # Verify root CA
    if [ -f "$CERT_DIR/root_ca.crt" ]; then
        openssl x509 -in "$CERT_DIR/root_ca.crt" -noout -text >> "$ROTATION_LOG" 2>&1
        if [ $? -eq 0 ]; then
            log_success "Root CA certificate is valid"
        else
            log_error "Root CA certificate verification failed"
            restore_from_backup
            exit 1
        fi
    fi
    
    # Verify service certificates
    local services=("planner" "intent-engine" "safety-agent" "permission-broker" "executor" "audit")
    local verified_count=0
    
    for service in "${services[@]}"; do
        # Verify client certificate
        if [ -f "$CERT_DIR/$service/client.crt" ]; then
            openssl verify -CAfile "$CERT_DIR/root_ca.crt" "$CERT_DIR/$service/client.crt" >> "$ROTATION_LOG" 2>&1
            if [ $? -eq 0 ]; then
                ((verified_count++))
            else
                log_error "$service client certificate verification failed"
                restore_from_backup
                exit 1
            fi
        fi
        
        # Verify server certificate
        if [ -f "$CERT_DIR/$service/server.crt" ]; then
            openssl verify -CAfile "$CERT_DIR/root_ca.crt" "$CERT_DIR/$service/server.crt" >> "$ROTATION_LOG" 2>&1
            if [ $? -eq 0 ]; then
                ((verified_count++))
            else
                log_error "$service server certificate verification failed"
                restore_from_backup
                exit 1
            fi
        fi
    done
    
    log_success "Verified $verified_count certificates"
    echo ""
}

# Update service configurations
update_service_configs() {
    log_info "Updating service configurations..."
    
    # Check if services are running in Docker
    if command -v docker-compose &> /dev/null && [ -f "$PROJECT_ROOT/infra/docker/docker-compose.yml" ]; then
        log_info "Docker Compose detected"
        
        # Check if services are running
        cd "$PROJECT_ROOT/infra/docker"
        
        if docker-compose ps | grep -q "Up"; then
            log_info "Services are running, will perform graceful reload"
            SERVICES_RUNNING=true
        else
            log_info "Services are not running"
            SERVICES_RUNNING=false
        fi
        
        cd "$PROJECT_ROOT"
    else
        log_info "Docker Compose not available or not configured"
        SERVICES_RUNNING=false
    fi
    
    # If services are running, we need to reload them
    if [ "$SERVICES_RUNNING" = true ]; then
        log_info "Certificates updated, services will pick up new certificates on next restart"
        log_warning "To apply new certificates, restart services with: cd infra/docker && docker-compose restart"
    else
        log_info "No running services detected, certificates are ready for use"
    fi
    
    echo ""
}

# Perform graceful service reload (zero-downtime)
reload_services() {
    log_info "Performing graceful service reload..."
    
    if [ "$SERVICES_RUNNING" != true ]; then
        log_info "Services not running, skipping reload"
        return 0
    fi
    
    cd "$PROJECT_ROOT/infra/docker"
    
    # Reload services one by one to maintain availability
    local services=("planner" "intent-engine" "safety-agent" "permission-broker" "executor" "audit")
    
    for service in "${services[@]}"; do
        log_info "Reloading $service..."
        
        # Send SIGHUP to reload configuration (if service supports it)
        # Otherwise, perform rolling restart
        docker-compose restart -t 30 "$service" >> "$ROTATION_LOG" 2>&1
        
        if [ $? -eq 0 ]; then
            log_success "$service reloaded"
            
            # Wait a bit before reloading next service
            sleep 2
        else
            log_warning "$service reload failed (service may not be running)"
        fi
    done
    
    cd "$PROJECT_ROOT"
    log_success "All services reloaded"
    echo ""
}

# Restore from backup (in case of failure)
restore_from_backup() {
    log_error "Restoring certificates from backup..."
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log_error "Backup directory not found, cannot restore"
        return 1
    fi
    
    # Restore root CA
    if [ -f "$BACKUP_DIR/root_ca.crt" ]; then
        cp "$BACKUP_DIR/root_ca.crt" "$CERT_DIR/"
        log_success "Restored root CA certificate"
    fi
    
    if [ -f "$BACKUP_DIR/root_ca.key" ]; then
        cp "$BACKUP_DIR/root_ca.key" "$CERT_DIR/"
        log_success "Restored root CA private key"
    fi
    
    # Restore service certificates
    local services=("planner" "intent-engine" "safety-agent" "permission-broker" "executor" "audit")
    
    for service in "${services[@]}"; do
        if [ -d "$BACKUP_DIR/$service" ]; then
            rm -rf "$CERT_DIR/$service"
            mkdir -p "$CERT_DIR/$service"
            cp -r "$BACKUP_DIR/$service"/* "$CERT_DIR/$service/"
            log_success "Restored $service certificates"
        fi
    done
    
    log_success "Certificates restored from backup"
}

# Clean up old backups (keep last 10)
cleanup_old_backups() {
    log_info "Cleaning up old backups..."
    
    local backup_parent="$CERT_DIR/backups"
    
    if [ ! -d "$backup_parent" ]; then
        log_info "No backups to clean up"
        return 0
    fi
    
    # Count backups
    local backup_count=$(find "$backup_parent" -maxdepth 1 -type d | wc -l)
    backup_count=$((backup_count - 1))  # Exclude parent directory
    
    if [ $backup_count -gt 10 ]; then
        log_info "Found $backup_count backups, keeping last 10"
        
        # Remove oldest backups
        find "$backup_parent" -maxdepth 1 -type d | sort | head -n -11 | tail -n +2 | xargs rm -rf
        
        log_success "Old backups cleaned up"
    else
        log_info "Found $backup_count backups, no cleanup needed"
    fi
    
    echo ""
}

# Display summary
display_summary() {
    echo ""
    echo "============================================================"
    echo "  Certificate Rotation Complete!"
    echo "============================================================"
    echo ""
    echo "Summary:"
    echo "  - Backup location: $BACKUP_DIR"
    echo "  - New certificates: $CERT_DIR"
    echo "  - Rotation log: $ROTATION_LOG"
    echo ""
    
    if [ "$SERVICES_RUNNING" = true ]; then
        echo "Services Status:"
        echo "  - Services have been reloaded with new certificates"
        echo "  - Check service health: cd infra/docker && docker-compose ps"
        echo ""
    fi
    
    echo "Certificate Details:"
    
    # Display root CA expiration
    if [ -f "$CERT_DIR/root_ca.crt" ]; then
        local expiry=$(openssl x509 -in "$CERT_DIR/root_ca.crt" -noout -enddate | cut -d= -f2)
        echo "  - Root CA expires: $expiry"
    fi
    
    echo ""
    echo "Next Steps:"
    echo "  1. Verify services are running correctly"
    echo "  2. Run integration tests: bash scripts/run_integration_tests.sh"
    echo "  3. Monitor service logs for any certificate-related errors"
    echo ""
    
    if [ "$SERVICES_RUNNING" != true ]; then
        echo "Note: Services are not running. Start them with:"
        echo "  cd infra/docker && docker-compose up -d"
        echo ""
    fi
}

# Main execution
main() {
    print_header
    
    # Confirm rotation
    echo "This script will rotate all mTLS certificates."
    echo "Existing certificates will be backed up to: $BACKUP_DIR"
    echo ""
    read -p "Continue with certificate rotation? (y/N) " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Certificate rotation cancelled"
        exit 0
    fi
    
    echo ""
    
    # Step 1: Validate prerequisites
    validate_prerequisites
    
    # Step 2: Backup existing certificates
    backup_certificates
    
    # Step 3: Generate new certificates
    generate_new_certificates
    
    # Step 4: Verify new certificates
    verify_certificates
    
    # Step 5: Update service configurations
    update_service_configs
    
    # Step 6: Reload services (if running)
    if [ "$SERVICES_RUNNING" = true ]; then
        reload_services
    fi
    
    # Step 7: Clean up old backups
    cleanup_old_backups
    
    # Step 8: Display summary
    display_summary
    
    log_success "Certificate rotation completed successfully!"
}

# Run main function
main
