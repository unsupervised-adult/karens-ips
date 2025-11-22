# Quick Start - Karen's IPS ML Ad Detector

**One file, 19 prompts, complete ML ad detection system**

---

## What This Builds

Adds ML-based ad/telemetry detection to your existing **Suricata + SLIPS + Kalipso** stack.

**Your Current Stack** (already installed):
- ✅ Suricata IPS (NFQUEUE bridge mode)
- ✅ SLIPS (behavioral ML)
- ✅ Kalipso (terminal UI)
- ✅ SLIPS Web UI (port 55000)
- ✅ nftables blocking
- ✅ Redis (ports 6379/6380)

**What You're Adding**:
- 🔨 ML Ad/Telemetry Detector
  - SLIPS custom module
  - 30-feature extraction from flows
  - TFLite LSTM model (<5MB, <10ms)
  - Training pipeline
  - Continuous learning

---

## 3-Minute Setup

### 1. Download Files
Place `BUILD_GUIDE.md` in your karens-ips directory:
```bash
~/karens-ips/
# Or wherever you cloned the repository
```

### 2. Open Claude Code
```bash
cd ~/karens-ips/
# Open Claude Code here
```

### 3. Execute 19 Prompts
Open `BUILD_GUIDE.md` and copy/paste each prompt (1→19) into Claude Code.

---

## Prompt Phases (Quick Reference)

| Phase | Prompts | What It Builds | Time |
|-------|---------|----------------|------|
| **Setup** | 1-3 | Project structure, config | 10 min |
| **Core** | 4-7 | Feature extractor, predictor, SLIPS module | 30 min |
| **Training** | 8-11 | Data collection, labeling, LSTM training | 20 min |
| **Deploy** | 12-14 | Installer, updater, uninstaller | 15 min |
| **Ops** | 15-17 | Monitor, stats, continuous learning | 15 min |
| **Test** | 18-19 | Unit & integration tests | 10 min |
| **Total** | | | ~2 hours |

---

## After Building (Week-by-Week)

### Week 1: Collect Data
```bash
cd ~/karens-ips/
python3 training/collect_data.py --hours 24 --output training/data/raw/
```
**Goal**: 2,500+ flows collected

### Week 2: Label Data
```bash
python3 training/label_helper.py --input training/data/raw/flows_*.csv
```
**Goal**: Label 2,000+ flows (70% content, 30% ads)

### Week 3: Train & Deploy
```bash
# Train model
python3 training/train_model.py --data training/data/labeled/labeled_flows.csv

# Deploy to production
sudo ./deployment/install.sh
sudo systemctl restart slips
```
**Goal**: >80% accuracy, <10ms inference

### Ongoing: Monitor
```bash
# Live dashboard
python3 scripts/monitor.py

# Daily stats
python3 scripts/stats.py --period day
```

---

## Architecture

```
Internet Traffic
      ↓
┌─────────────────┐
│   Your Router   │
└─────────────────┘
      ↓
┌─────────────────────────────────────────┐
│         Karen's IPS (Proxmox VM)        │
│                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐│
│  │Suricata │→ │  SLIPS  │→ │ML Detect││
│  │ Rules   │  │Behavior │  │Patterns ││ 
│  └─────────┘  └─────────┘  └─────────┘│
│                     ↓                   │
│              ┌────────────┐             │
│              │  nftables  │             │
│              │  Blocking  │             │
│              └────────────┘             │
└─────────────────────────────────────────┘
      ↓
  Protected LAN
```

**3-Layer Defense:**
1. **Suricata**: Signature-based rules
2. **SLIPS**: Behavioral analysis
3. **ML Detector**: Pattern recognition for ads/telemetry (NEW!)

---

## Key Files After Build

```
~/karens-ips/
├── src/
│   ├── feature_extractor.py    # 30 features from SLIPS Redis
│   ├── predictor.py             # TFLite inference (<10ms)
│   ├── slips_module.py          # SLIPS integration
│   └── utils.py                 # Helpers
├── training/
│   ├── collect_data.py          # Extract from Redis
│   ├── label_helper.py          # Interactive labeling
│   ├── train_model.py           # LSTM training
│   └── evaluate_model.py        # Model evaluation
├── deployment/
│   ├── install.sh               # Main installer
│   ├── update_model.sh          # Hot-swap models
│   └── uninstall.sh             # Clean removal
└── scripts/
    ├── monitor.py               # Live dashboard
    ├── stats.py                 # Reports
    └── retrain.py               # Continuous learning
```

---

## Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| Feature extraction | <5ms | 2-4ms |
| Prediction | <10ms | 6-8ms |
| Total latency | <15ms | 10-12ms |
| Model size | <5MB | 3-4MB |
| Accuracy (week 2) | >80% | 82-88% |
| Accuracy (month 2+) | >88% | 88-93% |
| False positives | <5% | 2-4% |
| Memory overhead | <500MB | ~300MB |

---

## Common Issues

### "Redis connection failed"
```bash
# Check Redis is running
sudo systemctl status redis-server

# Check SLIPS is running
sudo systemctl status slips
```

### "Model not found"
```bash
# You need to train a model first (Week 3)
python3 training/train_model.py --data training/data/labeled/labeled_flows.csv
```

### "Import errors"
```bash
# Install dependencies
pip3 install -r requirements.txt
```

### "Permission denied"
```bash
# Run installer with sudo
sudo ./deployment/install.sh
```

---

## Monitoring Commands

```bash
# Live monitor
python3 scripts/monitor.py

# Daily stats
python3 scripts/stats.py --period day

# SLIPS logs
sudo journalctl -fu slips

# Suricata logs
tail -f /var/log/suricata/fast.log

# Web UI
# http://YOUR_VM_IP:55000
```

---

## Next Steps After Installation

1. **Verify SLIPS sees the module:**
   ```bash
   sudo journalctl -fu slips | grep "ML Ad Detector"
   ```

2. **Check web UI:**
   - Open http://YOUR_VM_IP:55000
   - Look for "ML Ad Detector" in modules list

3. **Start collecting data:**
   ```bash
   python3 training/collect_data.py --hours 24
   ```

4. **Begin labeling:**
   ```bash
   python3 training/label_helper.py --input training/data/raw/flows_*.csv
   ```

---

## Support

- **Documentation**: `BUILD_GUIDE.md` (full 19 prompts)
- **Logs**: `/var/log/ips-installer.log`
- **SLIPS docs**: https://stratosphereips.org/
- **Your setup**: Based on `karens-ips-installer.sh`

---

**Ready? Open BUILD_GUIDE.md and start with Prompt 1!**
