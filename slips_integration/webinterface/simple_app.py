#!/usr/bin/env python3
"""
Simple standalone web interface for Karen's IPS ML Detector
Minimal login with username then password entry
"""
import os
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour

# Simple hardcoded credentials (change these!)
USERNAME = "admin"
PASSWORD = "karens-ips-2025"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


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
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=55000, debug=False)
