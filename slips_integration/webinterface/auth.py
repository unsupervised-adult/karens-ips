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

auth_bp = Blueprint('auth', __name__)

# Password hash file location
PASSWORD_FILE = os.environ.get('IPS_PASSWORD_FILE', '/etc/karens-ips/.password')

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
    """Login page and handler."""
    if request.method == 'POST':
        password = request.form.get('password', '')

        if check_password(password):
            session['authenticated'] = True
            session.permanent = True  # Remember session
            return redirect(url_for('index'))
        else:
            return redirect(url_for('auth.login', error=1))

    # GET request - show login page
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('auth.login'))
