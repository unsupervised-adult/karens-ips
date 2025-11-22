# Claude Code Build Guide - Karen's IPS ML Ad Detector

This guide contains **19 sequential prompts** to build the ML Ad/Telemetry Detector for your existing SLIPS+Suricata setup.

**Prerequisites**: Your base system is already installed via `karens-ips-installer.sh`

---

## Quick Reference

**Project Location**: `/home/ficus/Documents/Project-Code/IPS/karens-ips/`

**Build these in order - each prompt builds on the previous:**

### Phase 1: Project Setup (Prompts 1-3)
- Prompt 1: Initialize project structure
- Prompt 2: Create requirements.txt
- Prompt 3: Create configuration file

### Phase 2: Core Components (Prompts 4-7)
- Prompt 4: Feature extractor (30 features from SLIPS Redis)
- Prompt 5: TFLite predictor
- Prompt 6: SLIPS module integration
- Prompt 7: Utility functions

### Phase 3: Training Pipeline (Prompts 8-11)
- Prompt 8: Data collection from Redis
- Prompt 9: Interactive labeling helper
- Prompt 10: LSTM training pipeline
- Prompt 11: Model evaluation

### Phase 4: Deployment (Prompts 12-14)
- Prompt 12: Main installer
- Prompt 13: Model update script
- Prompt 14: Uninstaller

### Phase 5: Operations (Prompts 15-17)
- Prompt 15: Live monitor
- Prompt 16: Statistics viewer
- Prompt 17: Continuous learning/retraining

### Phase 6: Testing (Prompts 18-19)
- Prompt 18: Unit tests
- Prompt 19: Integration tests

---

## PROMPT 1: Initialize Project

```
Create project structure at /home/ficus/Documents/Project-Code/IPS/karens-ips/

Directory structure:
- src/ (Python modules)
- models/ (TFLite models)
- training/ (data collection & training)
- deployment/ (installation scripts)
- scripts/ (utilities)
- tests/ (unit tests)
- config/ (YAML config)

Create empty __init__.py files in src/ and tests/
Create README.md with project overview
Create .gitignore for Python, models, and data files
```

---

## PROMPT 2: Requirements File

```
Create requirements.txt with:
tflite-runtime==2.14.0
numpy==1.24.3
scikit-learn==1.3.2
redis==5.0.1
pandas==2.0.3
pyyaml==6.0.1
python-dateutil==2.8.2

Add development dependencies section:
pytest==7.4.0
black==23.7.0
flake8==6.1.0
```

---

## PROMPT 3: Configuration File

```
Create config/ml_detector.yaml with settings:
- Redis connection (host, ports, dbs)
- Model paths
- Confidence threshold (0.75)
- Feature extraction params
- Blocking timeout (30s)
- Training parameters
- Logging configuration

Use YAML format with comments explaining each setting
```

---

## PROMPT 4: Feature Extractor

```
Build src/feature_extractor.py based on SLIPS Redis data format:

Class: AdTrafficFeatureExtractor
- Connect to SLIPS Redis (localhost:6379 db 1, localhost:6380 db 0)
- Query flow profiles using keys: profile_<IP>_timewindow_<timestamp>
- Extract 30 features per flow:
  * Flow basics (7): duration, sbytes, dbytes, spkts, dpkts, byte_ratio, pkt_ratio
  * Timing (6): inter-arrival, burst_score, time_since_last, request_freq, duration_std, flow_rate
  * Connection patterns (8): concurrent_count, avg_size, std_size, min_size, max_size, small_request_ratio, short_duration_ratio, connection_variance
  * CDN detection (5): is_ad_cdn, cdn_consistency, subnet_changes, endpoint_diversity, known_tracker
  * Behavior (4): user_agent_changes, cookie_tracking, redirect_chains, data_exfiltration_score

Methods:
- extract_flow_features(flow_data: dict) -> np.ndarray shape (30,)
- extract_time_series(dst_ip: str, window_seconds: int = 60) -> np.ndarray shape (10, 30)
- _get_recent_flows(dst_ip: str, current_time: float, window: int) -> list
- _get_concurrent_flows(dst_ip: str, current_time: float) -> list
- is_ad_cdn(ip: str) -> bool

Include:
- Type hints
- Comprehensive docstrings
- Error handling for missing Redis data
- Caching for performance
- Ad CDN IP ranges (Google Ads, DoubleClick, Facebook Ads, etc.)

Target: <5ms per extraction
```

---

## PROMPT 5: TFLite Predictor

```
Build src/predictor.py for fast inference:

Class: AdPredictor
- Load TFLite model (not full TensorFlow)
- Use tflite-runtime
- Load StandardScaler from pickle
- Normalize features before prediction
- Return probability [0-1]

Methods:
- __init__(model_path: str, scaler_path: str)
- predict(features: np.ndarray) -> float
- predict_batch(features_list: list) -> list[float]
- _normalize(features: np.ndarray) -> np.ndarray

Include:
- Fallback to full TensorFlow if tflite-runtime unavailable
- Model loading validation
- Performance timing (log inference time)
- Thread-safe operation
- Error handling

Target: <10ms inference on i5-8350U
```

---

## PROMPT 6: SLIPS Module Integration

```
Build src/slips_module.py implementing SLIPS IModule interface:

Import: from slips_files.common.abstracts.module import IModule

Class: MLAdDetector(IModule)
Attributes:
- name = 'ML Ad Detector'
- description = 'Machine learning detection of ads and telemetry'
- authors = ['Karen's IPS Project']

Methods to implement:
- init(): Load config, initialize feature extractor and predictor
- pre_main(): Subscribe to 'new_flow' Redis channel
- main(): Process flows, extract features, predict, set evidence
- shutdown_gracefully(): Cleanup and save stats
- set_evidence_ad_detected(): Create SLIPS evidence format

Evidence format:
{
    'type': 'AdTelemetryDetected',
    'attacker': dst_ip,
    'threat_level': 'medium' or 'high',
    'confidence': float,
    'description': 'ML detected ad/telemetry (confidence: X%)',
    'profile': profileid,
    'timewindow': twid,
    'source': 'ml_ad_detector'
}

Requirements:
- Only process outbound traffic (not local IPs)
- Batch predictions for efficiency
- Log all predictions to SQLite
- Publish evidence to SLIPS evidence channel
- Statistics tracking (predictions, blocks, false positives)
- Integration with existing blocking (nftables via SLIPS)

CRITICAL: Use SLIPS evidence system - don't block directly
SLIPS will accumulate evidence and handle blocking
```

---

## PROMPT 7: Utils Module

```
Build src/utils.py with helper functions:

- load_config(config_path: str) -> dict
- setup_logging(log_level: str, log_file: str) -> logging.Logger
- is_private_ip(ip: str) -> bool
- get_flow_key(profileid: str, twid: str) -> str
- parse_redis_flow(flow_data: dict) -> dict
- save_stats(stats: dict, filepath: str)
- load_stats(filepath: str) -> dict

Include validation, error handling, type hints
```

---

## PROMPT 8: Data Collection

```
Build training/collect_data.py:

Script to extract flows from SLIPS Redis for labeling

Functions:
- collect_flows(hours_back: int = 24, output_dir: str = 'training/data/raw') -> pd.DataFrame
  * Query SLIPS Redis profile keys
  * Extract flow data
  * Filter out local traffic
  * Save to timestamped CSV

CSV columns:
timestamp, src_ip, dst_ip, dst_port, protocol, duration, 
bytes_sent, bytes_recv, packets_sent, packets_recv, 
flow_state, ttl, syn_count, ack_count, 
label (empty for manual labeling)

Command-line interface:
- --hours: Hours to look back (default 24)
- --output: Output directory
- --filter: Filter by IP/port
- --verbose: Detailed logging

Include progress bar, duplicate detection, error handling
```

---

## PROMPT 9: Labeling Helper

```
Build training/label_helper.py:

Interactive CLI tool for labeling flows

Features:
- Load unlabeled CSV
- Display flow details (duration, bytes, concurrent flows, timing)
- Prompt for label: 0=content, 1=ad, 2=telemetry, 3=tracking, s=skip
- Show statistics (labeled vs remaining)
- Save progress periodically
- Export labeled data

Command-line interface:
- --input: CSV file to label
- --output: Output labeled CSV
- --resume: Resume from saved session
- --batch-size: Flows per session

Include keyboard shortcuts, undo, batch labeling for similar flows
```

---

## PROMPT 10: Training Pipeline

```
Build training/train_model.py:

Complete LSTM training pipeline

Steps:
1. Load labeled CSV data
2. Build time-series dataset (10-flow windows)
3. Train/val/test split (70/15/15)
4. Normalize features (StandardScaler)
5. Build LSTM model:
   - Input: (10, 30)
   - Bidirectional LSTM(64) + Dropout(0.3)
   - Bidirectional LSTM(32) + Dropout(0.3)
   - Dense(32) + Dropout(0.4)
   - Dense(1, activation='sigmoid')
6. Train with callbacks:
   - EarlyStopping(patience=10)
   - ModelCheckpoint(save_best_only=True)
   - ReduceLROnPlateau(patience=5)
7. Evaluate on test set
8. Convert to TFLite with INT8 quantization
9. Save model, scaler, metrics

Command-line interface:
- --data: Labeled CSV path
- --epochs: Max epochs (default 50)
- --batch-size: Training batch size (default 32)
- --output-dir: Model output directory
- --validate: Run validation only

Metrics to log:
- Accuracy, Precision, Recall, F1-score
- Confusion matrix
- ROC-AUC
- Inference time benchmarks

Target: >80% accuracy, <5MB model, <10ms inference
```

---

## PROMPT 11: Model Evaluation

```
Build training/evaluate_model.py:

Comprehensive model evaluation script

Functions:
- evaluate_model(model_path, test_data_path) -> dict
  * Load TFLite model
  * Run predictions on test set
  * Calculate metrics
  * Generate confusion matrix
  * Plot ROC curve
  * Measure inference time

- compare_models(model_paths: list) -> pd.DataFrame
  * Compare multiple model versions
  * Show accuracy, size, speed
  * Recommend best model

Command-line interface:
- --model: TFLite model path
- --test-data: Test CSV path
- --output: Report output directory
- --benchmark: Run speed benchmarks

Generate report as:
- JSON metrics file
- HTML report with plots
- Console summary
```

---

## PROMPT 12: Main Installer

```
Build deployment/install.sh:

Bash script to install ML Ad Detector into existing SLIPS setup

Prerequisites check:
- SLIPS installed at /opt/StratosphereLinuxIPS
- Redis running on ports 6379/6380
- Python 3.10+
- Sufficient disk space

Installation steps:
1. Check prerequisites
2. Install Python dependencies (requirements.txt)
3. Create module directory: /opt/StratosphereLinuxIPS/modules/ml_ad_detector/
4. Copy/symlink src/slips_module.py as __init__.py
5. Copy models/ to /opt/ml-ad-detector/models/
6. Copy config to /etc/ml-ad-detector/
7. Create SQLite tables:
   - ml_predictions (id, timestamp, dst_ip, confidence, prediction, actual)
   - ml_stats (date, predictions, blocks, false_positives)
8. Enable module in SLIPS config
9. Set permissions
10. Validate installation
11. Print next steps

Exit codes:
- 0: Success
- 1: Missing prerequisites
- 2: SLIPS not found
- 3: Permission denied
- 4: Installation failed

Include rollback on failure, logging, colored output
```

---

## PROMPT 13: Model Update Script

```
Build deployment/update_model.sh:

Script to deploy new trained models to production

Steps:
1. Validate new model (test predictions)
2. Backup current model
3. Copy new model to /opt/ml-ad-detector/models/
4. Update version.txt
5. Restart SLIPS (or just reload module)
6. Verify model loaded correctly
7. Log deployment

Command-line options:
- --model: Path to new .tflite model
- --scaler: Path to new scaler.pkl
- --dry-run: Validate only, don't deploy
- --rollback: Rollback to previous version

Include safety checks, graceful restart, deployment logging
```

---

## PROMPT 14: Uninstaller

```
Build deployment/uninstall.sh:

Clean removal of ML Ad Detector

Steps:
1. Confirm with user
2. Stop SLIPS if running
3. Disable module in SLIPS config
4. Remove module from /opt/StratosphereLinuxIPS/modules/
5. Remove /opt/ml-ad-detector/
6. Remove /etc/ml-ad-detector/
7. Remove SQLite tables (optional)
8. Remove Python packages (optional)
9. Log uninstallation

Options:
- --keep-data: Keep training data and logs
- --keep-db: Keep SQLite database
- --force: No confirmation prompts

Include verification, logs, status messages
```

---

## PROMPT 15: Live Monitor

```
Build scripts/monitor.py:

Real-time monitoring of ML detector

Features:
- Connect to SLIPS Redis
- Subscribe to detection events
- Display live predictions
- Show statistics (predictions/min, blocks/min)
- Alert on high false positive rate
- Color-coded output (green=content, red=ad, yellow=uncertain)

Display:
┌─ ML Ad Detector Monitor ─────────────────────┐
│ Status: Running                              │
│ Predictions: 1,234 (5.2/sec)                 │
│ Blocks: 42 (3.4%)                            │
│ False Positives: 2 (0.16%)                   │
├──────────────────────────────────────────────┤
│ Recent Detections:                           │
│ [12:34:56] 142.250.1.1 → Ad (0.89)          │
│ [12:34:57] 172.217.2.2 → Content (0.12)     │
│ [12:34:58] 216.58.3.3 → Ad (0.92) BLOCKED   │
└──────────────────────────────────────────────┘

Keyboard commands:
- q: Quit
- p: Pause
- c: Clear screen
- s: Show statistics
- f: Filter by IP/confidence

Use curses for terminal UI
```

---

## PROMPT 16: Statistics Viewer

```
Build scripts/stats.py:

Generate statistics reports from SQLite database

Functions:
- daily_stats() -> Show daily predictions, blocks, accuracy
- weekly_trend() -> Plot weekly trends
- top_blocked_ips(n: int) -> List most blocked IPs
- false_positive_analysis() -> Analyze FP patterns
- model_performance() -> Accuracy over time

Command-line interface:
- --period: daily, weekly, monthly, all
- --metric: predictions, blocks, accuracy, fps
- --format: table, json, csv, html
- --export: Export to file

Generate visualizations using matplotlib (save as PNG/HTML)
```

---

## PROMPT 17: Continuous Learning

```
Build scripts/retrain.py:

Automated retraining script for continuous learning

Steps:
1. Check if retraining needed (>100 new labeled samples)
2. Collect new data from SQLite (predictions + user feedback)
3. Merge with existing training data
4. Balance dataset (handle class imbalance)
5. Train new model
6. Validate on holdout set
7. Compare with current model
8. If improved: Deploy via update_model.sh
9. Log retraining metrics
10. Send notification (optional)

Criteria for retraining:
- Accuracy drop >5%
- >100 new labeled samples
- Weekly schedule
- Manual trigger

Command-line interface:
- --force: Force retraining
- --dry-run: Test without deploying
- --notify: Send email/webhook on completion
- --schedule: Set up cron job

Include model versioning, A/B testing capability
```

---

## PROMPT 18: Unit Tests

```
Build tests/test_feature_extraction.py:

pytest tests for feature extractor

Test cases:
- test_connect_redis(): Connection handling
- test_extract_flow_features(): Feature extraction accuracy
- test_extract_time_series(): Time-series generation
- test_handle_missing_data(): Graceful degradation
- test_ad_cdn_detection(): Known ad CDN detection
- test_performance(): <5ms extraction time
- test_caching(): Cache effectiveness

Use pytest fixtures for mock Redis data
Include edge cases, error conditions
```

---

## PROMPT 19: Integration Tests

```
Build tests/test_integration.py:

End-to-end integration tests

Test scenarios:
- test_slips_module_init(): Module initialization
- test_flow_processing(): Full flow: receive → extract → predict → evidence
- test_blocking_integration(): Evidence sets correctly
- test_model_update(): Model hot-reload
- test_redis_failure(): Graceful handling of Redis downtime
- test_high_load(): Performance under load (1000 flows/sec)

Use docker-compose to spin up test SLIPS instance
Mock external dependencies
```

---

## Usage Instructions

1. **Navigate to project directory:**
   ```bash
   cd /home/ficus/Documents/Project-Code/IPS/karens-ips/
   ```

2. **Open Claude Code** in this directory

3. **Execute prompts sequentially** (1 through 19)
   - Copy each prompt
   - Paste into Claude Code
   - Verify output
   - Move to next prompt

4. **After Prompt 19**, you'll have:
   - Complete ML detector implementation
   - Training pipeline
   - Deployment scripts
   - Monitoring tools
   - Test suite

5. **Deploy:**
   ```bash
   sudo ./deployment/install.sh
   ```

---

## Post-Installation

**Week 1**: Data collection
```bash
python3 training/collect_data.py --hours 24
```

**Week 2**: Labeling
```bash
python3 training/label_helper.py --input training/data/raw/flows_*.csv
```

**Week 3**: Training & deployment
```bash
python3 training/train_model.py --data training/data/labeled/labeled_flows.csv
sudo ./deployment/update_model.sh --model models/ad_detector_v1.tflite
```

**Ongoing**: Monitoring
```bash
python3 scripts/monitor.py
```

---

## Expected Results

- **Accuracy**: 82-88% (week 2) → 88-93% (month 2+)
- **Model size**: 3-4 MB
- **Inference**: 6-12ms
- **False positives**: 2-5% initially → <2% with continuous learning

---

**Ready to build? Start with Prompt 1!**
