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
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 3
    fi
}

check_prerequisites() {
    print_status "Checking prerequisites..."

    if [[ ! -d "${SLIPS_DIR}" ]]; then
        print_error "SLIPS not found at ${SLIPS_DIR}"
        print_error "Please install SLIPS first"
        exit 2
    fi
    print_success "SLIPS found"

    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    REQUIRED_VERSION="3.10"
    if [[ $(echo -e "${PYTHON_VERSION}\n${REQUIRED_VERSION}" | sort -V | head -n1) != "${REQUIRED_VERSION}" ]]; then
        print_error "Python 3.10+ required (found ${PYTHON_VERSION})"
        exit 1
    fi
    print_success "Python ${PYTHON_VERSION} found"

    if ! command -v redis-cli &> /dev/null; then
        print_error "Redis not found"
        exit 1
    fi

    if ! redis-cli -p 6379 ping &> /dev/null; then
        print_warning "Redis on port 6379 not responding"
    else
        print_success "Redis 6379 accessible"
    fi

    if ! redis-cli -p 6380 ping &> /dev/null; then
        print_warning "Redis on port 6380 not responding"
    else
        print_success "Redis 6380 accessible"
    fi

    AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
    REQUIRED_SPACE=$((500 * 1024))
    if [[ ${AVAILABLE_SPACE} -lt ${REQUIRED_SPACE} ]]; then
        print_error "Insufficient disk space (need 500MB)"
        exit 1
    fi
    print_success "Sufficient disk space available"

    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [[ ${TOTAL_MEM} -lt 16 ]]; then
        print_warning "Less than 16GB RAM detected (${TOTAL_MEM}GB)"
        print_warning "System may experience memory pressure"
    fi
}

setup_swap() {
    print_status "Checking swap configuration..."

    SWAP_SIZE=$(free -h | awk '/^Swap:/{print $2}')
    if [[ "${SWAP_SIZE}" == "0B" ]]; then
        print_warning "No swap detected"

        AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
        REQUIRED_SPACE=$((5 * 1024 * 1024))

        if [[ ${AVAILABLE_SPACE} -gt ${REQUIRED_SPACE} ]]; then
            print_status "Creating 4GB swap file..."

            fallocate -l 4G /swapfile
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile

            if ! grep -q "/swapfile" /etc/fstab; then
                echo "/swapfile none swap sw 0 0" >> /etc/fstab
            fi

            print_success "4GB swap created and enabled"
        else
            print_warning "Insufficient space for swap file (need 5GB)"
        fi
    else
        print_success "Swap already configured (${SWAP_SIZE})"
    fi
}

install_dependencies() {
    print_status "Installing Python dependencies..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        python3 -m pip install --upgrade pip
        python3 -m pip install -r "${SCRIPT_DIR}/requirements.txt"
        print_success "Dependencies installed"
    else
        print_warning "requirements.txt not found, skipping"
    fi
}

create_directories() {
    print_status "Creating directories..."

    mkdir -p "${ML_DETECTOR_DIR}"/{models,data,logs}
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${MODULE_DIR}"

    print_success "Directories created"
}

install_module() {
    print_status "Installing SLIPS modules..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ ! -d "${SCRIPT_DIR}/src" ]]; then
        print_error "Source directory not found: ${SCRIPT_DIR}/src"
        exit 4
    fi

    cp -r "${SCRIPT_DIR}"/src/* "${MODULE_DIR}/"

    if [[ -f "${MODULE_DIR}/slips_module.py" ]]; then
        ln -sf "${MODULE_DIR}/slips_module.py" "${MODULE_DIR}/__init__.py"
        print_success "Module linked"
    fi

    print_success "Module files copied"
    
    if [[ -d "${SCRIPT_DIR}/slips_integration/modules/ad_flow_blocker" ]]; then
        print_status "Installing ad_flow_blocker module..."
        cp -r "${SCRIPT_DIR}/slips_integration/modules/ad_flow_blocker" "${SLIPS_DIR}/modules/"
        print_success "ad_flow_blocker module installed"
    fi
}

install_models() {
    print_status "Installing models..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -d "${SCRIPT_DIR}/models" ]]; then
        cp -r "${SCRIPT_DIR}"/models/* "${ML_DETECTOR_DIR}/models/" 2>/dev/null || true
        print_success "Models copied"
    else
        print_warning "No pre-trained models found"
        print_warning "You'll need to train a model first"
    fi
}

install_config() {
    print_status "Installing configuration..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "${SCRIPT_DIR}/config/ml_detector.yaml" ]]; then
        cp "${SCRIPT_DIR}/config/ml_detector.yaml" "${CONFIG_DIR}/"
        print_success "Configuration installed"
    else
        print_warning "Config file not found, creating default"

        cat > "${CONFIG_DIR}/ml_detector.yaml" <<EOF
redis:
  host: localhost
  ports: [6379, 6380]
  dbs: [1, 0]

model:
  path: /opt/ml-ad-detector/models/ad_detector.tflite
  scaler_path: /opt/ml-ad-detector/models/ad_detector_scaler.pkl

detector:
  confidence_threshold: 0.75
  blocking_timeout: 30
  batch_size: 10

logging:
  level: INFO
  file: /opt/ml-ad-detector/logs/detector.log
EOF
        print_success "Default config created"
    fi
}

setup_database() {
    print_status "Setting up SQLite database..."

    DB_PATH="${ML_DETECTOR_DIR}/data/detector.db"

    sqlite3 "${DB_PATH}" <<EOF
CREATE TABLE IF NOT EXISTS ml_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    dst_ip TEXT NOT NULL,
    confidence REAL NOT NULL,
    prediction INTEGER NOT NULL,
    actual INTEGER
);

CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON ml_predictions(timestamp);
CREATE INDEX IF NOT EXISTS idx_predictions_dst_ip ON ml_predictions(dst_ip);

CREATE TABLE IF NOT EXISTS ml_stats (
    date TEXT PRIMARY KEY,
    predictions INTEGER DEFAULT 0,
    blocks INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0
);
EOF

    print_success "Database initialized"
}

configure_redis_thresholds() {
    print_status "Configuring Redis detection thresholds..."

    if redis-cli -p 6379 ping &> /dev/null; then
        redis-cli -p 6379 HSET stream_ad_blocker:thresholds youtube_threshold 0.60 > /dev/null
        redis-cli -p 6379 HSET stream_ad_blocker:thresholds cdn_threshold 0.85 > /dev/null
        redis-cli -p 6379 HSET stream_ad_blocker:thresholds control_plane_threshold 0.70 > /dev/null
        redis-cli -p 6379 HSET stream_ad_blocker:thresholds llm_min_threshold 0.30 > /dev/null
        redis-cli -p 6379 HSET stream_ad_blocker:thresholds llm_max_threshold 0.95 > /dev/null

        print_success "Detection thresholds configured"
    else
        print_warning "Redis not available, skipping threshold configuration"
    fi
}

enable_slips_module() {
    print_status "Enabling ad_flow_blocker in SLIPS config..."
    
    SLIPS_CONFIG="${SLIPS_DIR}/config/slips.yaml"
    
    if [[ -f "${SLIPS_CONFIG}" ]]; then
        if grep -q "ad_flow_blocker" "${SLIPS_CONFIG}"; then
            print_success "ad_flow_blocker already enabled"
        else
            sed -i '/^  enable:/a\    - ad_flow_blocker' "${SLIPS_CONFIG}"
            print_success "ad_flow_blocker enabled in SLIPS config"
        fi
    else
        print_warning "SLIPS config not found, skipping auto-enable"
    fi
    
    if command -v conntrack &> /dev/null; then
        print_success "conntrack already installed"
    else
        print_status "Installing conntrack for flow-level blocking..."
        apt-get update -qq
        apt-get install -y conntrack > /dev/null 2>&1
        print_success "conntrack installed"
    fi
}

set_permissions() {
    print_status "Setting permissions..."

    chown -R root:root "${ML_DETECTOR_DIR}"
    chmod -R 755 "${ML_DETECTOR_DIR}"

    chown -R root:root "${MODULE_DIR}"
    chmod -R 755 "${MODULE_DIR}"

    chown -R root:root "${CONFIG_DIR}"
    chmod -R 644 "${CONFIG_DIR}"/*

    print_success "Permissions set"
}

validate_installation() {
    print_status "Validating installation..."

    if [[ ! -f "${MODULE_DIR}/__init__.py" ]]; then
        print_error "Module init file missing"
        return 1
    fi

    if [[ ! -f "${CONFIG_DIR}/ml_detector.yaml" ]]; then
        print_error "Config file missing"
        return 1
    fi

    python3 -c "import sys; sys.path.insert(0, '${MODULE_DIR}'); import utils" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_success "Module imports successfully"
    else
        print_warning "Module import test failed (may need dependencies)"
    fi

    print_success "Installation validated"
}

print_next_steps() {
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}ML AD DETECTOR INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo "Installation summary:"
    echo "  - 4GB swap configured (if not present)"
    echo "  - Redis detection thresholds set"
    echo "  - LLM auto-labeling range: 0.30 - 0.95"
    echo "  - Enterprise whitelist: Tanium, Rapid7, Microsoft, etc."
    echo "  - ad_flow_blocker module enabled in SLIPS"
    echo "  - conntrack installed for flow-level blocking"
    echo
    echo "System architecture:"
    echo "  - ML-first detection (runs on all flows)"
    echo "  - Pattern matching as confidence boost"
    echo "  - LLM auto-labeling for training data"
    echo "  - Self-improving hybrid ML+LLM pipeline"
    echo "  - Flow-level ad blocking via conntrack (surgical precision)"
    echo
    echo "Blocking methods:"
    echo "  - Slips blocking module: IP-level blocking (malicious IPs)"
    echo "  - ad_flow_blocker module: Flow-level blocking (in-stream ads)"
    echo "  - Thresholds: YouTube=0.60, CDN=0.85, ControlPlane=0.70"
    echo
    echo "Next steps:"
    echo
    echo "1. Train a model:"
    echo "   cd /path/to/karens-ips"
    echo "   python3 training/collect_data.py --hours 24"
    echo "   python3 training/label_helper.py --input training/data/raw/flows_*.csv"
    echo "   python3 training/train_model.py --data training/data/labeled/labeled_flows.csv"
    echo
    echo "2. Deploy the model:"
    echo "   sudo ./deployment/update_model.sh --model models/ad_detector.tflite"
    echo
    echo "3. Restart SLIPS:"
    echo "   sudo systemctl restart slips"
    echo
    echo "4. Monitor ad flow blocking:"
    echo "   tail -f ${SLIPS_DIR}/output/*/slips.log | grep 'FLOW BLOCKED'"
    echo "   redis-cli -n 1 HGETALL stream_ad_blocker:stats"
    echo
    echo "Installation directory: ${ML_DETECTOR_DIR}"
    echo "Configuration: ${CONFIG_DIR}/ml_detector.yaml"
    echo "Database: ${ML_DETECTOR_DIR}/data/detector.db"
    echo "Redis thresholds: stream_ad_blocker:thresholds"
    echo
    SWAP_SIZE=$(free -h | awk '/^Swap:/{print $2}')
    TOTAL_MEM=$(free -h | awk '/^Mem:/{print $2}')
    echo "System resources: ${TOTAL_MEM} RAM, ${SWAP_SIZE} swap"
    echo
}

rollback() {
    print_warning "Rolling back installation..."

    rm -rf "${MODULE_DIR}"
    rm -rf "${ML_DETECTOR_DIR}"
    rm -rf "${CONFIG_DIR}"

    print_success "Rollback complete"
}

main() {
    echo
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}ML AD DETECTOR INSTALLER${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    check_root
    check_prerequisites
    setup_swap
    install_dependencies
    create_directories
    install_module
    install_models
    install_config
    setup_database
    configure_redis_thresholds
    enable_slips_module
    set_permissions
    validate_installation

    print_next_steps
}

trap 'print_error "Installation failed"; rollback; exit 4' ERR

main

exit 0
