#!/usr/bin/env python3
"""
Simple standalone web interface for Karen's IPS ML Detector
Minimal login with username then password entry
"""
import os
import sys
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour
app.config["JSON_SORT_KEYS"] = False

# Simple hardcoded credentials (change these!)
USERNAME = "admin"
PASSWORD = "karens-ips-2025"

# Register blueprints for ML detector and Suricata pages
try:
    # Add parent directory to path for imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from ml_detector.ml_detector import ml_detector
    from suricata_config.suricata_config import suricata_bp

    app.register_blueprint(ml_detector, url_prefix="/ml_detector")
    app.register_blueprint(suricata_bp, url_prefix="/suricata")

    BLUEPRINTS_LOADED = True
except ImportError as e:
    print(f"Warning: Could not import blueprints: {e}")
    print("ML Detector and Suricata pages will not be available")
    BLUEPRINTS_LOADED = False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def require_login():
    """Protect all routes except login and auth with authentication"""
    allowed_routes = ['login', 'authenticate', 'static']
    if request.endpoint and request.endpoint not in allowed_routes:
        if not session.get('logged_in'):
            return redirect(url_for('login'))


@app.route('/')
def login():
    """Simple centered login page"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/auth', methods=['POST'])
def authenticate():
    """Handle login - username then password"""
    data = request.get_json()
    step = data.get('step')
    value = data.get('value')

    if step == 'username':
        # Check username
        if value == USERNAME:
            return jsonify({'success': True, 'next': 'password'})
        else:
            return jsonify({'success': False, 'message': 'Access denied'})

    elif step == 'password':
        # Check password
        if value == PASSWORD:
            session['logged_in'] = True
            session.permanent = True
            return jsonify({'success': True, 'next': 'dashboard'})
        else:
            return jsonify({'success': False, 'message': 'Access denied'})

    return jsonify({'success': False, 'message': 'Invalid request'})


@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard after login"""
    return render_template('app.html')


@app.route('/api/system_info')
@login_required
def get_system_info():
    """Get system information for dashboard"""
    try:
        import datetime
        from ..database.database import db
        
        # Get metadata from Redis
        slips_version = db.r.hget('analysis', 'slips_version') or 'Unknown'
        analysis_start = db.r.hget('analysis', 'analysis_start') or None
        
        # Calculate uptime
        uptime_str = 'Unknown'
        if analysis_start:
            try:
                # Parse the analysis start time and calculate uptime
                from dateutil import parser
                start_time = parser.parse(analysis_start)
                uptime_delta = datetime.datetime.now() - start_time
                days = uptime_delta.days
                hours, remainder = divmod(uptime_delta.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                if days > 0:
                    uptime_str = f"{days}d {hours}h {minutes}m"
                else:
                    uptime_str = f"{hours}h {minutes}m {seconds}s"
            except Exception as e:
                uptime_str = 'Unknown'
        
        # Get profile and alert counts
        profiles = len(db.get_profiles()) if hasattr(db, 'get_profiles') else 0
        alerts = 0  # TODO: implement alert counting
        
        return jsonify({
            'success': True,
            'version': slips_version.decode() if isinstance(slips_version, bytes) else slips_version,
            'uptime': uptime_str,
            'profiles': profiles,
            'alerts': alerts
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'version': 'Unknown',
            'uptime': 'Unknown',
            'profiles': 0,
            'alerts': 0
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=55000, debug=False)
