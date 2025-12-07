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
BLOCKLISTS_DIR = "/var/lib/suricata/blocklists"
IPS_FILTER_DB = "/opt/ips-filter-db.py"
DB_PATH = "/var/lib/suricata/ips_filter.db"

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
                                'signature_id': alert_data.get('signature_id'),
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

@suricata_bp.route('/api/actions/whitelist', methods=['POST'])
def add_to_whitelist():
    try:
        data = request.get_json()
        whitelist_type = data.get('type')
        value = data.get('value', '').strip()
        
        if not value:
            return jsonify({'error': 'Value cannot be empty'}), 400
        
        if whitelist_type == 'ip':
            rule = f"pass ip {value} any -> any any (msg:\"Whitelisted IP {value}\"; sid:9000001; rev:1;)"
        elif whitelist_type == 'signature':
            sid = data.get('signature_id')
            if not sid:
                return jsonify({'error': 'Signature ID required'}), 400
            rule = f"# Suppressed signature {sid}"
            
            suppress_file = "/etc/suricata/threshold.config"
            suppress_line = f"suppress gen_id 1, sig_id {sid}\n"
            
            os.makedirs(os.path.dirname(suppress_file), exist_ok=True)
            with open(suppress_file, 'a') as f:
                f.write(suppress_line)
            
            reload_suricata()
            return jsonify({'success': True, 'message': f'Signature {sid} suppressed'})
        else:
            return jsonify({'error': 'Invalid whitelist type'}), 400
        
        with open(CUSTOM_RULES, 'a') as f:
            f.write(rule + '\n')
        
        reload_suricata()
        
        return jsonify({'success': True, 'message': 'Whitelist rule added'})
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

@suricata_bp.route('/api/blocklists')
def get_blocklists():
    try:
        blocklists = []
        
        if os.path.exists(BLOCKLISTS_DIR):
            if os.path.exists(os.path.join(BLOCKLISTS_DIR, 'PiHoleBlocklist')):
                blocklists.append({
                    'name': 'Perflyst/PiHoleBlocklist',
                    'type': 'perflyst',
                    'status': 'cloned',
                    'path': 'PiHoleBlocklist'
                })
            
            if os.path.exists(os.path.join(BLOCKLISTS_DIR, 'dns-blocklists')):
                blocklists.append({
                    'name': 'hagezi/dns-blocklists',
                    'type': 'hagezi',
                    'status': 'cloned',
                    'path': 'dns-blocklists'
                })
        
        return jsonify({'blocklists': blocklists})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/blocklists/update', methods=['POST'])
def update_blocklists():
    try:
        data = request.get_json()
        blocklist_type = data.get('type')
        
        os.makedirs(BLOCKLISTS_DIR, exist_ok=True)
        os.chdir(BLOCKLISTS_DIR)
        
        if blocklist_type == 'perflyst':
            if not os.path.exists('PiHoleBlocklist'):
                result = subprocess.run(['git', 'clone', '--depth', '1', 
                                       'https://github.com/Perflyst/PiHoleBlocklist.git'],
                                      capture_output=True, text=True, timeout=300)
            else:
                os.chdir('PiHoleBlocklist')
                result = subprocess.run(['git', 'pull'],
                                      capture_output=True, text=True, timeout=60)
                os.chdir('..')
        
        elif blocklist_type == 'hagezi':
            if not os.path.exists('dns-blocklists'):
                result = subprocess.run(['git', 'clone', '--depth', '1',
                                       'https://github.com/hagezi/dns-blocklists.git'],
                                      capture_output=True, text=True, timeout=300)
            else:
                os.chdir('dns-blocklists')
                result = subprocess.run(['git', 'pull'],
                                      capture_output=True, text=True, timeout=60)
                os.chdir('..')
        else:
            return jsonify({'error': 'Invalid blocklist type'}), 400
        
        if result.returncode == 0:
            return jsonify({'success': True, 'message': f'{blocklist_type} blocklist updated'})
        else:
            return jsonify({'error': result.stderr}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/blocklists/import', methods=['POST'])
def import_blocklist():
    try:
        data = request.get_json()
        blocklist_type = data.get('type')
        list_name = data.get('list')
        
        if not os.path.exists(IPS_FILTER_DB):
            return jsonify({'error': 'Blocklist manager not installed'}), 500
        
        file_map = {
            'perflyst_smarttv': 'PiHoleBlocklist/SmartTV.txt',
            'perflyst_android': 'PiHoleBlocklist/android-tracking.txt',
            'perflyst_firetv': 'PiHoleBlocklist/AmazonFireTV.txt',
            'perflyst_sessionreplay': 'PiHoleBlocklist/SessionReplay.txt',
            'hagezi_light': 'dns-blocklists/domains/light.txt',
            'hagezi_normal': 'dns-blocklists/domains/multi.txt',
            'hagezi_pro': 'dns-blocklists/domains/pro.txt',
            'hagezi_proplus': 'dns-blocklists/domains/pro.plus.txt',
            'hagezi_ultimate': 'dns-blocklists/domains/ultimate.txt',
            'hagezi_native': 'dns-blocklists/domains/native.txt'
        }
        
        full_list_name = f"{blocklist_type}_{list_name}"
        if full_list_name not in file_map:
            return jsonify({'error': 'Invalid blocklist selection'}), 400
        
        file_path = os.path.join(BLOCKLISTS_DIR, file_map[full_list_name])
        if not os.path.exists(file_path):
            return jsonify({'error': 'Blocklist file not found'}), 404
        
        result = subprocess.run([
            IPS_FILTER_DB,
            '--db-path', DB_PATH,
            '--import-file', file_path,
            '--source-name', full_list_name,
            '--source-description', f'{blocklist_type} {list_name}',
            '--category', 'ads'
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            sync_result = subprocess.run([
                IPS_FILTER_DB,
                '--db-path', DB_PATH,
                '--sync-to-suricata'
            ], capture_output=True, text=True, timeout=300)
            
            if sync_result.returncode == 0:
                reload_suricata()
                return jsonify({'success': True, 'message': f'Imported {full_list_name} and synced to Suricata'})
            else:
                return jsonify({'warning': 'Import succeeded but sync failed', 'details': sync_result.stderr}), 500
        else:
            return jsonify({'error': result.stderr}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/blocklists/stats')
def get_blocklist_stats():
    try:
        if not os.path.exists(IPS_FILTER_DB):
            return jsonify({'error': 'Blocklist manager not installed'}), 500
        
        result = subprocess.run([
            IPS_FILTER_DB,
            '--db-path', DB_PATH,
            '--stats'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            stats = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    stats[key.strip()] = value.strip()
            return jsonify({'stats': stats})
        else:
            return jsonify({'error': result.stderr}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/database/query', methods=['POST'])
def query_database():
    try:
        import sqlite3
        data = request.get_json()
        table = data.get('table')
        action = data.get('action')
        filters = data.get('filters', {})
        limit = data.get('limit', 100)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if action == 'select':
            query = f"SELECT * FROM {table}"
            params = []
            
            if filters:
                conditions = []
                for key, value in filters.items():
                    conditions.append(f"{key} LIKE ?")
                    params.append(f"%{value}%")
                query += " WHERE " + " AND ".join(conditions)
            
            query += f" ORDER BY id DESC LIMIT {limit}"
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return jsonify({'success': True, 'data': results})
            
        elif action == 'delete':
            domain_id = filters.get('id')
            if domain_id:
                cursor.execute("DELETE FROM blocked_domains WHERE id = ?", (domain_id,))
                conn.commit()
                conn.close()
                return jsonify({'success': True, 'message': 'Entry deleted'})
            
        elif action == 'whitelist':
            domain = filters.get('domain')
            if domain:
                cursor.execute("DELETE FROM blocked_domains WHERE domain = ?", (domain,))
                conn.commit()
                conn.close()
                return jsonify({'success': True, 'message': f'Domain {domain} whitelisted'})
        
        conn.close()
        return jsonify({'error': 'Invalid action'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/database/tables')
def get_database_tables():
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        return jsonify({'success': True, 'tables': tables})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/database/count')
def get_database_counts():
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        counts = {}
        cursor.execute("SELECT COUNT(*) FROM blocklist_sources")
        counts['sources'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM blocked_domains")
        counts['domains'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT source_id) FROM blocked_domains")
        counts['active_sources'] = cursor.fetchone()[0]
        
        conn.close()
        return jsonify({'success': True, 'counts': counts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@suricata_bp.route('/api/database/sync', methods=['POST'])
def sync_database_to_suricata():
    try:
        if not os.path.exists(IPS_FILTER_DB):
            return jsonify({'error': 'Blocklist manager not installed'}), 500
        
        result = subprocess.run([
            IPS_FILTER_DB,
            '--db-path', DB_PATH,
            '--sync'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            reload_suricata()
            return jsonify({
                'success': True, 
                'message': 'Database synced to Suricata rules and reloaded',
                'output': result.stdout
            })
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
