#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SLIPS_DIR="/opt/StratosphereLinuxIPS"
ML_DETECTOR_DIR="/opt/ml-ad-detector"
CONFIG_DIR="/etc/ml-ad-detector"
MODULE_DIR="${SLIPS_DIR}/modules/ml_ad_detector"

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Uninstall ML Ad Detector from SLIPS

Options:
    --keep-data         Keep training data and logs
    --keep-db           Keep SQLite database
    --force             No confirmation prompts
    --help              Show this help

Examples:
    $0                  # Interactive uninstall
    $0 --force          # Uninstall without prompts
    $0 --keep-data      # Keep data files
EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

confirm_uninstall() {
    if [[ "${FORCE}" == true ]]; then
        return 0
    fi

    echo
    echo -e "${YELLOW}WARNING: This will remove ML Ad Detector from your system${NC}"
    echo
    echo "The following will be removed:"
    echo "  - Module: ${MODULE_DIR}"
    echo "  - Data:   ${ML_DETECTOR_DIR}"
    echo "  - Config: ${CONFIG_DIR}"
    echo

    read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Uninstall cancelled"
        exit 0
    fi
}

stop_slips() {
    print_status "Stopping SLIPS..."

    if systemctl is-active --quiet slips; then
        systemctl stop slips
        print_success "SLIPS stopped"
    else
        print_warning "SLIPS is not running"
    fi
}

disable_module() {
    print_status "Disabling module in SLIPS config..."

    SLIPS_CONF="${SLIPS_DIR}/slips.conf"

    if [[ -f "${SLIPS_CONF}" ]]; then
        if grep -q "ml_ad_detector" "${SLIPS_CONF}"; then
            sed -i '/ml_ad_detector/d' "${SLIPS_CONF}"
            print_success "Module disabled in config"
        else
            print_warning "Module not found in config"
        fi
    else
        print_warning "SLIPS config not found"
    fi
}

remove_module() {
    print_status "Removing module files..."

    if [[ -d "${MODULE_DIR}" ]]; then
        rm -rf "${MODULE_DIR}"
        print_success "Module directory removed"
    else
        print_warning "Module directory not found"
    fi
}

remove_detector_dir() {
    print_status "Removing detector directory..."

    if [[ ! -d "${ML_DETECTOR_DIR}" ]]; then
        print_warning "Detector directory not found"
        return
    fi

    if [[ "${KEEP_DATA}" == true ]]; then
        print_status "Keeping data files"

        find "${ML_DETECTOR_DIR}" -type f -not -path "*/data/*" -not -path "*/logs/*" -delete
        find "${ML_DETECTOR_DIR}" -type d -empty -delete

        print_success "Non-data files removed"
    else
        if [[ "${KEEP_DB}" == true ]]; then
            print_status "Backing up database..."

            DB_PATH="${ML_DETECTOR_DIR}/data/detector.db"
            if [[ -f "${DB_PATH}" ]]; then
                BACKUP_PATH="/tmp/ml_detector_db_backup_$(date +%Y%m%d_%H%M%S).db"
                cp "${DB_PATH}" "${BACKUP_PATH}"
                print_success "Database backed up to ${BACKUP_PATH}"
            fi
        fi

        rm -rf "${ML_DETECTOR_DIR}"
        print_success "Detector directory removed"
    fi
}

remove_config() {
    print_status "Removing configuration..."

    if [[ -d "${CONFIG_DIR}" ]]; then
        rm -rf "${CONFIG_DIR}"
        print_success "Configuration removed"
    else
        print_warning "Configuration directory not found"
    fi
}

remove_database() {
    if [[ "${KEEP_DB}" == true ]]; then
        print_status "Keeping database"
        return
    fi

    print_status "Removing database..."

    DB_PATH="${ML_DETECTOR_DIR}/data/detector.db"

    if [[ -f "${DB_PATH}" ]]; then
        rm -f "${DB_PATH}"
        print_success "Database removed"
    fi
}

remove_python_packages() {
    if [[ "${FORCE}" == true ]]; then
        return
    fi

    echo
    read -p "Remove Python packages? (tflite-runtime, etc.) [y/N]: " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Removing Python packages..."

        python3 -m pip uninstall -y tflite-runtime 2>/dev/null || true
        print_success "Python packages removed"
    else
        print_status "Keeping Python packages"
    fi
}

log_uninstall() {
    LOG_FILE="/var/log/ml_detector_uninstall.log"

    cat >> "${LOG_FILE}" <<EOF
========================================
ML Ad Detector Uninstall
Date: $(date)
Keep Data: ${KEEP_DATA}
Keep DB: ${KEEP_DB}
Force: ${FORCE}
========================================
EOF

    print_status "Uninstall logged to ${LOG_FILE}"
}

verify_removal() {
    print_status "Verifying removal..."

    ISSUES=0

    if [[ -d "${MODULE_DIR}" ]]; then
        print_warning "Module directory still exists"
        ((ISSUES++))
    fi

    if [[ -d "${CONFIG_DIR}" ]]; then
        print_warning "Config directory still exists"
        ((ISSUES++))
    fi

    if [[ "${KEEP_DATA}" == false && -d "${ML_DETECTOR_DIR}" ]]; then
        print_warning "Detector directory still exists"
        ((ISSUES++))
    fi

    if [[ ${ISSUES} -eq 0 ]]; then
        print_success "Removal verified"
    else
        print_warning "Some files may remain"
    fi
}

print_summary() {
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}UNINSTALL COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo

    if [[ "${KEEP_DATA}" == true ]]; then
        echo "Data preserved in: ${ML_DETECTOR_DIR}/data"
        echo "Logs preserved in: ${ML_DETECTOR_DIR}/logs"
    fi

    if [[ "${KEEP_DB}" == true ]]; then
        echo "Database preserved"
    fi

    echo
    echo "ML Ad Detector has been removed from your system"
    echo
}

main() {
    KEEP_DATA=false
    KEEP_DB=false
    FORCE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-data)
                KEEP_DATA=true
                shift
                ;;
            --keep-db)
                KEEP_DB=true
                shift
                ;;
            --force)
                FORCE=true
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
    echo -e "${BLUE}ML AD DETECTOR UNINSTALLER${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    check_root
    confirm_uninstall
    stop_slips
    disable_module
    remove_module
    remove_detector_dir
    remove_config
    remove_python_packages
    log_uninstall
    verify_removal
    print_summary
}

main "$@"

exit 0
