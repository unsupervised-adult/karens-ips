from flask import Blueprint, render_template, jsonify, request
import subprocess
import json
import os
import yaml
from datetime import datetime
import re

suricata_bp = Blueprint('suricata', __name__, 
                       template_folder='templates',
                       static_folder='static',
                       static_url_path='/suricata/static')

SURICATA_YAML = "/etc/suricata/suricata.yaml"
RULES_DIR = "/var/lib/suricata/rules"
CUSTOM_RULES = "/etc/suricata/rules/custom.rules"
EVE_JSON = "/var/log/suricata/eve.json"

@suricata_bp.route('/')
def index():
    return render_template('suricata_dashboard.html')

@suricata_bp.route('/api/status')
def get_status():
    try:
        result = subprocess.run(['sudo', 'systemctl', 'is-active', 'suricata'], 
                              capture_output=True, text=True, timeout=5)
        active = result.stdout.strip() == 'active'
        
        uptime_result = subprocess.run(['sudo', 'systemctl', 'show', 'suricata', '-p', 'ActiveEnterTimestamp'],
                                      capture_output=True, text=True, timeout=5)
        uptime = uptime_result.stdout.split('=')[1].strip() if '=' in uptime_result.stdout else 'Unknown'
        
        stats = get_suricata_stats()
        
        return jsonify({
            'status': 'running' if active else 'stopped',
            'uptime': uptime,
            'stats': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/stats')
def get_stats():
    try:
        stats = get_suricata_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_suricata_stats():
    try:
        result = subprocess.run(['sudo', 'suricatasc', '-c', 'dump-counters'],
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            
            packets = 0
            alerts = 0
            dropped = 0
            
            if 'message' in data:
                for key, value in data['message'].items():
                    if 'packets' in key.lower():
                        packets += value
                    elif 'alert' in key.lower():
                        alerts += value
                    elif 'drop' in key.lower():
                        dropped += value
            
            return {
                'packets': packets,
                'alerts': alerts,
                'dropped': dropped
            }
        else:
            return {'packets': 0, 'alerts': 0, 'dropped': 0}
    except Exception:
        return {'packets': 0, 'alerts': 0, 'dropped': 0}

@suricata_bp.route('/api/alerts')
def get_alerts():
    try:
        limit = int(request.args.get('limit', 100))
        severity = request.args.get('severity', None)
        
        alerts = []
        if os.path.exists(EVE_JSON):
            with open(EVE_JSON, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get('event_type') == 'alert':
                            alert_data = entry.get('alert', {})
                            
                            if severity and alert_data.get('severity') != int(severity):
                                continue
                            
                            alerts.append({
                                'timestamp': entry.get('timestamp'),
                                'src_ip': entry.get('src_ip'),
                                'dest_ip': entry.get('dest_ip'),
                                'proto': entry.get('proto'),
                                'signature': alert_data.get('signature'),
                                'severity': alert_data.get('severity'),
                                'category': alert_data.get('category')
                            })
                            
                            if len(alerts) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
        
        return jsonify({'alerts': alerts[::-1]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/rules')
def get_rules():
    try:
        rules = []
        
        if os.path.exists(CUSTOM_RULES):
            with open(CUSTOM_RULES, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        enabled = not line.startswith('#')
                        rules.append({
                            'line': line_num,
                            'rule': line,
                            'enabled': enabled
                        })
        
        return jsonify({'rules': rules})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/rules', methods=['POST'])
def add_rule():
    try:
        data = request.get_json()
        rule = data.get('rule', '').strip()
        
        if not rule:
            return jsonify({'error': 'Rule cannot be empty'}), 400
        
        if not (rule.startswith('alert') or rule.startswith('drop') or 
                rule.startswith('pass') or rule.startswith('reject')):
            return jsonify({'error': 'Invalid rule format'}), 400
        
        os.makedirs(os.path.dirname(CUSTOM_RULES), exist_ok=True)
        
        with open(CUSTOM_RULES, 'a') as f:
            f.write(rule + '\n')
        
        reload_suricata()
        
        return jsonify({'success': True, 'message': 'Rule added'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/rules/<int:line_num>', methods=['DELETE'])
def delete_rule(line_num):
    try:
        if not os.path.exists(CUSTOM_RULES):
            return jsonify({'error': 'No custom rules file'}), 404
        
        with open(CUSTOM_RULES, 'r') as f:
            lines = f.readlines()
        
        if line_num < 1 or line_num > len(lines):
            return jsonify({'error': 'Invalid line number'}), 400
        
        lines.pop(line_num - 1)
        
        with open(CUSTOM_RULES, 'w') as f:
            f.writelines(lines)
        
        reload_suricata()
        
        return jsonify({'success': True, 'message': 'Rule deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/rules/<int:line_num>/toggle', methods=['POST'])
def toggle_rule(line_num):
    try:
        if not os.path.exists(CUSTOM_RULES):
            return jsonify({'error': 'No custom rules file'}), 404
        
        with open(CUSTOM_RULES, 'r') as f:
            lines = f.readlines()
        
        if line_num < 1 or line_num > len(lines):
            return jsonify({'error': 'Invalid line number'}), 400
        
        line = lines[line_num - 1]
        if line.strip().startswith('#'):
            lines[line_num - 1] = line.lstrip('#')
        else:
            lines[line_num - 1] = '#' + line
        
        with open(CUSTOM_RULES, 'w') as f:
            f.writelines(lines)
        
        reload_suricata()
        
        return jsonify({'success': True, 'message': 'Rule toggled'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/config')
def get_config():
    try:
        if not os.path.exists(SURICATA_YAML):
            return jsonify({'error': 'Config file not found'}), 404
        
        with open(SURICATA_YAML, 'r') as f:
            config = yaml.safe_load(f)
        
        simplified = {
            'home_net': config.get('vars', {}).get('address-groups', {}).get('HOME_NET', 'Not set'),
            'external_net': config.get('vars', {}).get('address-groups', {}).get('EXTERNAL_NET', 'Not set'),
            'interfaces': config.get('af-packet', []),
            'logging': {
                'eve': config.get('outputs', [{}])[0].get('eve-log', {}).get('enabled', False) if config.get('outputs') else False
            }
        }
        
        return jsonify(simplified)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/config/home_net', methods=['POST'])
def update_home_net():
    try:
        data = request.get_json()
        home_net = data.get('home_net', '').strip()
        
        if not home_net:
            return jsonify({'error': 'HOME_NET cannot be empty'}), 400
        
        with open(SURICATA_YAML, 'r') as f:
            config = yaml.safe_load(f)
        
        if 'vars' not in config:
            config['vars'] = {}
        if 'address-groups' not in config['vars']:
            config['vars']['address-groups'] = {}
        
        config['vars']['address-groups']['HOME_NET'] = home_net
        
        with open(SURICATA_YAML, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        reload_suricata()
        
        return jsonify({'success': True, 'message': 'HOME_NET updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/actions/reload', methods=['POST'])
def reload_rules():
    try:
        reload_suricata()
        return jsonify({'success': True, 'message': 'Suricata rules reloaded'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/actions/restart', methods=['POST'])
def restart_suricata():
    try:
        result = subprocess.run(['sudo', 'systemctl', 'restart', 'suricata'],
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'Suricata restarted'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/actions/update_rules', methods=['POST'])
def update_rulesets():
    try:
        result = subprocess.run(['sudo', 'suricata-update'],
                              capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            reload_suricata()
            return jsonify({'success': True, 'message': 'Rules updated from sources'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def reload_suricata():
    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'suricata'], 
                      check=True, timeout=30)
    except subprocess.CalledProcessError:
        subprocess.run(['sudo', 'systemctl', 'restart', 'suricata'],
                      check=True, timeout=30)
