#!/usr/bin/env python3
"""
Configuration Adjustment Tool
Interactive CLI for tuning detection thresholds
"""
import json
import os

CONFIG_FILE = '/opt/StratosphereLinuxIPS/webinterface/ml_detector/detector_config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    else:
        print(f"❌ Config file not found: {CONFIG_FILE}")
        return None

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"✅ Configuration saved to {CONFIG_FILE}")

def display_config(config):
    print("\n" + "="*80)
    print("CURRENT DETECTION SETTINGS")
    print("="*80)
    
    print("\n📊 DURATION THRESHOLDS (seconds)")
    print(f"  Content minimum:     {config['detection_thresholds']['streaming_min_duration']:>6.0f}s  (videos shorter than this = not content)")
    print(f"  Ad minimum:          {config['detection_thresholds']['ad_duration_min']:>6.0f}s  (flows shorter than this = ignored)")
    print(f"  Ad maximum:          {config['detection_thresholds']['ad_duration_max']:>6.0f}s  (ads longer than this = false positive)")
    
    print("\n📦 SIZE THRESHOLDS (bytes)")
    print(f"  Content minimum:     {config['detection_thresholds']['streaming_min_bytes']:>6d} bytes")
    print(f"  Ad minimum:          {config['detection_thresholds']['ad_min_bytes']:>6d} bytes")
    
    print("\n🎯 DETECTION SENSITIVITY")
    print(f"  Duration ratio:      {config['detection_thresholds']['duration_ratio_threshold']:>6.1%}  (ad must be <{config['detection_thresholds']['duration_ratio_threshold']:.0%} of content)")
    print(f"  Confidence threshold:{config['detection_thresholds']['confidence_threshold']:>6.1%}  (minimum to report)")
    
    print("\n🔐 PROTOCOL SETTINGS")
    print(f"  QUIC detection:      {'✓ Enabled' if config['protocol_detection']['enable_quic_detection'] else '✗ Disabled'}")
    print(f"  Encrypted analysis:  {'✓ Enabled' if config['protocol_detection']['enable_encrypted_analysis'] else '✗ Disabled'}")
    print(f"  Timing analysis:     {'✓ Enabled' if config['protocol_detection']['analyze_timing_patterns'] else '✗ Disabled'}")
    print(f"  Packet size analysis:{'✓ Enabled' if config['protocol_detection']['analyze_packet_sizes'] else '✗ Disabled'}")
    
    print("\n🤖 ML MODEL PARAMETERS")
    print(f"  Model type:          {config['model_type']}")
    print(f"  Trees/estimators:    {config['ml_parameters']['n_estimators']}")
    print(f"  Max depth:           {config['ml_parameters']['max_depth']}")
    
    print("\n⚖️  FEATURE WEIGHTS")
    print(f"  Duration importance: {config['feature_weights']['duration_importance']}")
    print(f"  Timing importance:   {config['feature_weights']['timing_importance']}")
    print(f"  Size importance:     {config['feature_weights']['size_importance']}")

def interactive_menu():
    config = load_config()
    if not config:
        return
    
    while True:
        display_config(config)
        
        print("\n" + "="*80)
        print("ADJUSTMENT OPTIONS")
        print("="*80)
        print("1. Increase sensitivity (catch more ads, more false positives)")
        print("2. Decrease sensitivity (fewer false positives, might miss ads)")
        print("3. Adjust for shorter videos (catch ads in short clips)")
        print("4. Adjust for QUIC/encrypted traffic")
        print("5. Custom threshold adjustment")
        print("6. Reset to defaults")
        print("7. Save and apply changes")
        print("q. Quit without saving")
        
        choice = input("\nSelect option: ").strip().lower()
        
        if choice == '1':
            config['detection_thresholds']['confidence_threshold'] = max(0.5, config['detection_thresholds']['confidence_threshold'] - 0.05)
            config['detection_thresholds']['duration_ratio_threshold'] = min(0.5, config['detection_thresholds']['duration_ratio_threshold'] + 0.05)
            print("✅ Increased sensitivity")
        
        elif choice == '2':
            config['detection_thresholds']['confidence_threshold'] = min(0.95, config['detection_thresholds']['confidence_threshold'] + 0.05)
            config['detection_thresholds']['duration_ratio_threshold'] = max(0.15, config['detection_thresholds']['duration_ratio_threshold'] - 0.05)
            print("✅ Decreased sensitivity")
        
        elif choice == '3':
            config['detection_thresholds']['streaming_min_duration'] = 60.0
            config['detection_thresholds']['ad_duration_max'] = 60.0
            print("✅ Adjusted for shorter videos (1min+ content, ads up to 1min)")
        
        elif choice == '4':
            config['protocol_detection']['enable_quic_detection'] = True
            config['protocol_detection']['enable_encrypted_analysis'] = True
            config['feature_weights']['timing_importance'] = 2.5
            config['feature_weights']['size_importance'] = 1.5
            print("✅ Optimized for QUIC/encrypted traffic (timing + size patterns)")
        
        elif choice == '5':
            print("\n📝 Custom Threshold Adjustment")
            print("Leave blank to keep current value")
            
            try:
                val = input(f"Content min duration (currently {config['detection_thresholds']['streaming_min_duration']}s): ")
                if val:
                    config['detection_thresholds']['streaming_min_duration'] = float(val)
                
                val = input(f"Ad max duration (currently {config['detection_thresholds']['ad_duration_max']}s): ")
                if val:
                    config['detection_thresholds']['ad_duration_max'] = float(val)
                
                val = input(f"Confidence threshold 0-1 (currently {config['detection_thresholds']['confidence_threshold']}): ")
                if val:
                    config['detection_thresholds']['confidence_threshold'] = float(val)
                
                print("✅ Custom thresholds updated")
            except ValueError:
                print("❌ Invalid input, skipping")
        
        elif choice == '6':
            confirm = input("⚠️  Reset to defaults? [y/N]: ").lower()
            if confirm == 'y':
                config['detection_thresholds']['streaming_min_duration'] = 120.0
                config['detection_thresholds']['ad_duration_max'] = 120.0
                config['detection_thresholds']['confidence_threshold'] = 0.75
                config['detection_thresholds']['duration_ratio_threshold'] = 0.3
                print("✅ Reset to defaults")
        
        elif choice == '7':
            save_config(config)
            print("\n✅ Configuration saved!")
            print("\n📝 To apply changes:")
            print("   sudo systemctl restart stream-monitor")
            break
        
        elif choice == 'q':
            print("Exiting without saving")
            break

if __name__ == '__main__':
    print("⚙️  Ad Detection Configuration Tool")
    interactive_menu()
