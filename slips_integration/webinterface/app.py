#!/usr/bin/env python3
"""
SLIPS Web Interface Application
Flask app entry point for the web-based dashboard
"""

from flask import Flask, render_template, jsonify, redirect, url_for
import logging
import os

app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(__file__), 'ml_detector/templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'ml_detector/static'))

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Import blueprints
try:
    from ml_detector.ml_detector_live import ml_detector
    app.register_blueprint(ml_detector, url_prefix='/ml_detector')
except ImportError as e:
    logger.error(f"Failed to import ml_detector: {e}")

@app.route('/')
def index():
    """Redirect to ML Detector dashboard"""
    return redirect(url_for('ml_detector.index'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "SLIPS Web Interface"})

if __name__ == '__main__':
    # Run on all interfaces for VM access
    app.run(host='0.0.0.0', port=55000, debug=False)
