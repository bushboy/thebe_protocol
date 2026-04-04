#!/bin/bash
# Zero-Trust Agentic Guardian - Integration Test Runner
# Requirement: 17.2
#
# This script runs all integration tests and reports results

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
TEST_LOG="$PROJECT_ROOT/integration_tests.log"
TEST_REPORT="$PROJECT_ROOT/integration_test_report.json"

# Test configuration
PYTEST_ARGS="-v --tb=short --color=yes"
INTEGRATION_TEST_DIR="$PROJECT_ROOT/tests/integration"
ATTACK_SCENARIO_DIR="$PROJECT_ROOT/tests/attack-scenarios"

# Initialize log file
echo "Zero-Trust Agentic Guardian Integration Tests - $(date)" > "$TEST_LOG"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$TEST_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $1" >> "$TEST_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$TEST_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $1" >> "$TEST_LOG"
}

# Print header
print_header() {
    echo ""
    echo "============================================================"
    echo "  Zero-Trust Agentic Guardian - Integration Tests"
    echo "============================================================"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if virtual environment is activated
    if [ -z "$VIRTUAL_ENV" ]; then
        log_warning "Virtual environment not activated"
        
        if [ -d "$PROJECT_ROOT/venv" ]; then
            log_info "Activating virtual environment..."
            source "$PROJECT_ROOT/venv/bin/activate"
            log_success "Virtual environment activated"
        else
            log_error "Virtual environment not found. Run setup_all.sh first."
            exit 1
        fi
    else
        log_success "Virtual environment active: $VIRTUAL_ENV"
    fi
    
    # Check if pytest is installed
    if ! command -v pytest &> /dev/null; then
        log_error "pytest not found. Install with: pip install pytest"
        exit 1
    fi
    
    log_success "pytest found: $(pytest --version | head -n1)"
    
    # Check if test directories exist
    if [ ! -d "$INTEGRATION_TEST_DIR" ]; then
        log_warning "Integration test directory not found: $INTEGRATION_TEST_DIR"
    fi
    
    if [ ! -d "$ATTACK_SCENARIO_DIR" ]; then
        log_warning "Attack scenario directory not found: $ATTACK_SCENARIO_DIR"
    fi
    
    echo ""
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run all unit tests (excluding integration and attack scenarios)
    pytest tests/ \
        --ignore=tests/integration \
        --ignore=tests/attack-scenarios \
        $PYTEST_ARGS \
        --junitxml=unit_test_results.xml \
        >> "$TEST_LOG" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Unit tests passed"
        return 0
    else
        log_error "Unit tests failed (exit code: $exit_code)"
        return $exit_code
    fi
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    cd "$PROJECT_ROOT"
    
    if [ ! -d "$INTEGRATION_TEST_DIR" ] || [ -z "$(ls -A $INTEGRATION_TEST_DIR/*.py 2>/dev/null)" ]; then
        log_warning "No integration tests found in $INTEGRATION_TEST_DIR"
        return 0
    fi
    
    # Run integration tests
    pytest "$INTEGRATION_TEST_DIR" \
        $PYTEST_ARGS \
        --junitxml=integration_test_results.xml \
        >> "$TEST_LOG" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Integration tests passed"
        return 0
    else
        log_error "Integration tests failed (exit code: $exit_code)"
        return $exit_code
    fi
}

# Run attack scenario tests
run_attack_scenarios() {
    log_info "Running attack scenario tests..."
    
    cd "$PROJECT_ROOT"
    
    if [ ! -d "$ATTACK_SCENARIO_DIR" ] || [ -z "$(ls -A $ATTACK_SCENARIO_DIR/*.py 2>/dev/null)" ]; then
        log_warning "No attack scenario tests found in $ATTACK_SCENARIO_DIR"
        return 0
    fi
    
    # Run attack scenario tests
    pytest "$ATTACK_SCENARIO_DIR" \
        $PYTEST_ARGS \
        --junitxml=attack_scenario_results.xml \
        >> "$TEST_LOG" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Attack scenario tests passed"
        return 0
    else
        log_error "Attack scenario tests failed (exit code: $exit_code)"
        return $exit_code
    fi
}

# Run property-based tests
run_property_tests() {
    log_info "Running property-based tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run all property tests (tests with "properties" in the name)
    pytest tests/ \
        -k "properties" \
        $PYTEST_ARGS \
        --junitxml=property_test_results.xml \
        >> "$TEST_LOG" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Property-based tests passed"
        return 0
    else
        log_error "Property-based tests failed (exit code: $exit_code)"
        return $exit_code
    fi
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    cd "$PROJECT_ROOT"
    
    # Count test results
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local skipped_tests=0
    
    # Parse JUnit XML files if they exist
    for xml_file in *_test_results.xml; do
        if [ -f "$xml_file" ]; then
            # Extract test counts from XML (simplified parsing)
            local tests=$(grep -oP 'tests="\K[0-9]+' "$xml_file" | head -n1)
            local failures=$(grep -oP 'failures="\K[0-9]+' "$xml_file" | head -n1)
            local skipped=$(grep -oP 'skipped="\K[0-9]+' "$xml_file" | head -n1)
            
            total_tests=$((total_tests + ${tests:-0}))
            failed_tests=$((failed_tests + ${failures:-0}))
            skipped_tests=$((skipped_tests + ${skipped:-0}))
        fi
    done
    
    passed_tests=$((total_tests - failed_tests - skipped_tests))
    
    # Generate JSON report
    cat > "$TEST_REPORT" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "total_tests": $total_tests,
    "passed": $passed_tests,
    "failed": $failed_tests,
    "skipped": $skipped_tests,
    "success_rate": $(awk "BEGIN {printf \"%.2f\", ($passed_tests / $total_tests) * 100}")
  },
  "test_suites": {
    "unit_tests": {
      "status": "$unit_test_status",
      "results_file": "unit_test_results.xml"
    },
    "integration_tests": {
      "status": "$integration_test_status",
      "results_file": "integration_test_results.xml"
    },
    "attack_scenarios": {
      "status": "$attack_scenario_status",
      "results_file": "attack_scenario_results.xml"
    },
    "property_tests": {
      "status": "$property_test_status",
      "results_file": "property_test_results.xml"
    }
  },
  "logs": {
    "test_log": "$TEST_LOG"
  }
}
EOF
    
    log_success "Test report saved to: $TEST_REPORT"
    echo ""
}

# Display summary
display_summary() {
    echo ""
    echo "============================================================"
    echo "  Test Results Summary"
    echo "============================================================"
    echo ""
    
    if [ -f "$TEST_REPORT" ]; then
        # Display report using jq if available, otherwise cat
        if command -v jq &> /dev/null; then
            jq '.' "$TEST_REPORT"
        else
            cat "$TEST_REPORT"
        fi
        echo ""
    fi
    
    echo "Detailed Results:"
    echo "  - Test log: $TEST_LOG"
    echo "  - Test report: $TEST_REPORT"
    echo ""
    
    # Display pass/fail status
    if [ $overall_status -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
    else
        echo -e "${RED}✗ Some tests failed. See $TEST_LOG for details.${NC}"
    fi
    
    echo ""
}

# Main execution
main() {
    print_header
    
    # Check prerequisites
    check_prerequisites
    
    # Initialize status variables
    unit_test_status="not_run"
    integration_test_status="not_run"
    attack_scenario_status="not_run"
    property_test_status="not_run"
    overall_status=0
    
    # Run unit tests
    echo ""
    if run_unit_tests; then
        unit_test_status="passed"
    else
        unit_test_status="failed"
        overall_status=1
    fi
    echo ""
    
    # Run integration tests
    if run_integration_tests; then
        integration_test_status="passed"
    else
        integration_test_status="failed"
        overall_status=1
    fi
    echo ""
    
    # Run attack scenario tests
    if run_attack_scenarios; then
        attack_scenario_status="passed"
    else
        attack_scenario_status="failed"
        overall_status=1
    fi
    echo ""
    
    # Run property-based tests
    if run_property_tests; then
        property_test_status="passed"
    else
        property_test_status="failed"
        overall_status=1
    fi
    echo ""
    
    # Generate report
    generate_report
    
    # Display summary
    display_summary
    
    # Exit with overall status
    exit $overall_status
}

# Run main function
main
