#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ML_DETECTOR_DIR="/opt/ml-ad-detector"
MODELS_DIR="${ML_DETECTOR_DIR}/models"
BACKUP_DIR="${ML_DETECTOR_DIR}/models/backups"
LOG_FILE="${ML_DETECTOR_DIR}/logs/deployment.log"

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "${LOG_FILE}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "${LOG_FILE}"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "${LOG_FILE}"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "${LOG_FILE}"
}

usage() {
    cat <<EOF
Usage: $0 --model MODEL_PATH [OPTIONS]

Deploy new trained model to production

Options:
    --model PATH        Path to new .tflite model (required)
    --scaler PATH       Path to new scaler.pkl
    --dry-run           Validate only, don't deploy
    --rollback          Rollback to previous version
    --help              Show this help

Examples:
    $0 --model models/ad_detector_v2.tflite --scaler models/ad_detector_v2_scaler.pkl
    $0 --dry-run --model models/ad_detector_v2.tflite
    $0 --rollback
EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

validate_model() {
    local model_path=$1

    print_status "Validating model: ${model_path}"

    if [[ ! -f "${model_path}" ]]; then
        print_error "Model file not found: ${model_path}"
        return 1
    fi

    if [[ ! "${model_path}" =~ \.tflite$ ]]; then
        print_error "Model must be a .tflite file"
        return 1
    fi

    local file_size=$(stat -c%s "${model_path}")
    local size_mb=$((file_size / 1024 / 1024))

    if [[ ${size_mb} -gt 50 ]]; then
        print_warning "Model is large: ${size_mb}MB"
    fi

    python3 -c "
import sys
try:
    import tflite_runtime.interpreter as tflite
except ImportError:
    import tensorflow.lite as tflite

try:
    interpreter = tflite.Interpreter(model_path='${model_path}')
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    print(f'Input shape: {input_details[0][\"shape\"]}')
    sys.exit(0)
except Exception as e:
    print(f'Model validation failed: {e}', file=sys.stderr)
    sys.exit(1)
"

    if [[ $? -eq 0 ]]; then
        print_success "Model validated"
        return 0
    else
        print_error "Model validation failed"
        return 1
    fi
}

backup_current_model() {
    print_status "Backing up current model..."

    mkdir -p "${BACKUP_DIR}"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    if [[ -f "${MODELS_DIR}/ad_detector.tflite" ]]; then
        cp "${MODELS_DIR}/ad_detector.tflite" "${BACKUP_DIR}/ad_detector_${TIMESTAMP}.tflite"
        print_success "Model backed up"
    fi

    if [[ -f "${MODELS_DIR}/ad_detector_scaler.pkl" ]]; then
        cp "${MODELS_DIR}/ad_detector_scaler.pkl" "${BACKUP_DIR}/ad_detector_scaler_${TIMESTAMP}.pkl"
        print_success "Scaler backed up"
    fi

    echo "${TIMESTAMP}" > "${BACKUP_DIR}/latest_backup.txt"
}

deploy_model() {
    local model_path=$1
    local scaler_path=$2

    print_status "Deploying model..."

    cp "${model_path}" "${MODELS_DIR}/ad_detector.tflite"
    print_success "Model deployed"

    if [[ -n "${scaler_path}" && -f "${scaler_path}" ]]; then
        cp "${scaler_path}" "${MODELS_DIR}/ad_detector_scaler.pkl"
        print_success "Scaler deployed"
    fi

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    echo "${TIMESTAMP}" > "${MODELS_DIR}/version.txt"
    print_success "Version updated: ${TIMESTAMP}"
}

restart_slips() {
    print_status "Restarting SLIPS..."

    if systemctl is-active --quiet slips; then
        systemctl restart slips
        sleep 3

        if systemctl is-active --quiet slips; then
            print_success "SLIPS restarted successfully"
        else
            print_error "SLIPS failed to restart"
            return 1
        fi
    else
        print_warning "SLIPS is not running as a service"
        print_warning "Please restart SLIPS manually"
    fi
}

verify_deployment() {
    print_status "Verifying deployment..."

    if [[ ! -f "${MODELS_DIR}/ad_detector.tflite" ]]; then
        print_error "Model file missing after deployment"
        return 1
    fi

    if [[ ! -f "${MODELS_DIR}/version.txt" ]]; then
        print_error "Version file missing"
        return 1
    fi

    VERSION=$(cat "${MODELS_DIR}/version.txt")
    print_success "Deployment verified (version: ${VERSION})"
}

rollback_to_previous() {
    print_status "Rolling back to previous version..."

    if [[ ! -f "${BACKUP_DIR}/latest_backup.txt" ]]; then
        print_error "No backup found"
        return 1
    fi

    BACKUP_VERSION=$(cat "${BACKUP_DIR}/latest_backup.txt")

    if [[ ! -f "${BACKUP_DIR}/ad_detector_${BACKUP_VERSION}.tflite" ]]; then
        print_error "Backup model not found"
        return 1
    fi

    cp "${BACKUP_DIR}/ad_detector_${BACKUP_VERSION}.tflite" "${MODELS_DIR}/ad_detector.tflite"
    print_success "Model rolled back"

    if [[ -f "${BACKUP_DIR}/ad_detector_scaler_${BACKUP_VERSION}.pkl" ]]; then
        cp "${BACKUP_DIR}/ad_detector_scaler_${BACKUP_VERSION}.pkl" "${MODELS_DIR}/ad_detector_scaler.pkl"
        print_success "Scaler rolled back"
    fi

    echo "rollback_${BACKUP_VERSION}" > "${MODELS_DIR}/version.txt"

    restart_slips

    print_success "Rollback complete"
}

main() {
    MODEL_PATH=""
    SCALER_PATH=""
    DRY_RUN=false
    ROLLBACK=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --model)
                MODEL_PATH="$2"
                shift 2
                ;;
            --scaler)
                SCALER_PATH="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    echo
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}ML AD DETECTOR - MODEL UPDATE${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    check_root

    mkdir -p "$(dirname "${LOG_FILE}")"

    if [[ "${ROLLBACK}" == true ]]; then
        rollback_to_previous
        exit 0
    fi

    if [[ -z "${MODEL_PATH}" ]]; then
        print_error "Model path required"
        usage
    fi

    validate_model "${MODEL_PATH}"

    if [[ "${DRY_RUN}" == true ]]; then
        print_success "Dry run complete - model is valid"
        exit 0
    fi

    backup_current_model
    deploy_model "${MODEL_PATH}" "${SCALER_PATH}"
    restart_slips
    verify_deployment

    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}MODEL UPDATE COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo "Model: ${MODELS_DIR}/ad_detector.tflite"
    echo "Version: $(cat ${MODELS_DIR}/version.txt)"
    echo "Backup: ${BACKUP_DIR}/"
    echo
    echo "To rollback: $0 --rollback"
    echo
}

main "$@"

exit 0
