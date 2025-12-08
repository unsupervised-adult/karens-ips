#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
"""
Authentication module for Karen's IPS web interface.
Provides session-based authentication with bcrypt password hashing.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session
from functools import wraps
import bcrypt
import os
from time import time
from collections import defaultdict

auth_bp = Blueprint('auth', __name__)

# Password hash file location
PASSWORD_FILE = os.environ.get('IPS_PASSWORD_FILE', '/etc/karens-ips/.password')

# Rate limiting: track failed login attempts
failed_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds

def load_password_hash():
    """Load the bcrypt password hash from file."""
    try:
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"Error loading password: {e}")
    return None

def check_password(password):
    """Verify password against stored hash."""
    password_hash = load_password_hash()
    if not password_hash:
        # If no password file, allow access (first-time setup)
        return True

    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        print(f"Error checking password: {e}")
        return False

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler with rate limiting."""
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    current_time = time()
    
    # Clean old failed attempts
    failed_attempts[client_ip] = [
        attempt_time for attempt_time in failed_attempts[client_ip]
        if current_time - attempt_time < LOCKOUT_DURATION
    ]
    
    # Check if IP is locked out
    if len(failed_attempts[client_ip]) >= MAX_ATTEMPTS:
        time_remaining = int(LOCKOUT_DURATION - (current_time - failed_attempts[client_ip][0]))
        return render_template('login.html', locked=True, time_remaining=time_remaining)
        return render_template('login.html', 
                             error='too_many_attempts',
                             lockout_time=time_remaining)
    
    if request.method == 'POST':
        password = request.form.get('password', '')

        if check_password(password):
            # Success - clear failed attempts
            failed_attempts[client_ip] = []
            session['authenticated'] = True
            session.permanent = True
            return redirect(url_for('index'))
        else:
            # Failed - record attempt
            failed_attempts[client_ip].append(current_time)
            attempts_left = MAX_ATTEMPTS - len(failed_attempts[client_ip])
            return redirect(url_for('auth.login', 
                                  error=1, 
                                  attempts_left=attempts_left))

    # GET request - show login page
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page and handler."""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validate current password
        if not check_password(current_password):
            return render_template('change_password.html', error='Current password is incorrect')

        # Validate new password
        if len(new_password) < 8:
            return render_template('change_password.html', error='New password must be at least 8 characters')

        if new_password != confirm_password:
            return render_template('change_password.html', error='New passwords do not match')

        # Hash and save new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        os.makedirs(os.path.dirname(PASSWORD_FILE), exist_ok=True)
        with open(PASSWORD_FILE, 'wb') as f:
            f.write(password_hash)

        # Logout to force re-login
        session.clear()
        return redirect(url_for('auth.login', changed=1))

    return render_template('change_password.html')
