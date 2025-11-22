# SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
# SPDX-License-Identifier: GPL-2.0-only
from flask import Blueprint, render_template, jsonify
from markupsafe import escape
import json
from typing import Dict, List
from ..database.database import db
from slips_files.common.slips_utils import utils

ml_detector = Blueprint(
    "ml_detector",
    __name__,
    static_folder="static",
    static_url_path="/ml_detector/static",
    template_folder="templates",
)


# ----------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------
def ts_to_date(ts, seconds=False):
    """Convert timestamp to human-readable date"""
    if seconds:
        return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S.%f")
    return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S")


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@ml_detector.route("/")
def index():
    """Main ML Detector page"""
    return render_template("ml_detector.html", title="ML Ad Detector")


@ml_detector.route("/stats")
def get_stats():
    """
    Get overall ML detector statistics
    Returns: Total detections, accuracy, etc.
    """
    try:
        # Fetch ML detector stats from Redis
        stats = db.r.hgetall("ml_detector:stats")

        if not stats:
            stats = {
                "total_analyzed": 0,
                "ads_detected": 0,
                "legitimate_traffic": 0,
                "accuracy": 0.0,
                "last_update": "N/A"
            }
        else:
            # Decode bytes to strings if needed
            stats = {k.decode() if isinstance(k, bytes) else k:
                    v.decode() if isinstance(v, bytes) else v
                    for k, v in stats.items()}

        return jsonify({"data": stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ml_detector.route("/detections/recent")
def get_recent_detections():
    """
    Get recent ad detections
    Returns: List of recent detections with details
    """
    try:
        # Fetch recent detections from Redis
        detections = db.r.lrange("ml_detector:recent_detections", 0, 99)

        data = []
        for detection in detections:
            if isinstance(detection, bytes):
                detection = detection.decode()
            detection_data = json.loads(detection)

            # Format timestamp if present
            if "timestamp" in detection_data:
                detection_data["timestamp_formatted"] = ts_to_date(
                    detection_data["timestamp"], seconds=True
                )

            data.append(detection_data)

        return jsonify({"data": data})
    except Exception as e:
        return jsonify({"error": str(e), "data": []}), 200


@ml_detector.route("/detections/timeline")
def get_detection_timeline():
    """
    Get detection timeline data for charts
    Returns: Time-series data of detections
    """
    try:
        # Fetch timeline data from Redis
        timeline = db.r.lrange("ml_detector:timeline", 0, 999)

        data = []
        for entry in timeline:
            if isinstance(entry, bytes):
                entry = entry.decode()
            timeline_data = json.loads(entry)
            data.append(timeline_data)

        return jsonify({"data": data})
    except Exception as e:
        return jsonify({"error": str(e), "data": []}), 200


@ml_detector.route("/model/info")
def get_model_info():
    """
    Get ML model information
    Returns: Model version, accuracy, features, etc.
    """
    try:
        # Fetch model info from Redis
        model_info = db.r.hgetall("ml_detector:model_info")

        if not model_info:
            model_info = {
                "model_type": "Random Forest",
                "version": "1.0.0",
                "accuracy": "95.5%",
                "features": "packets, bytes, duration, dest_port",
                "last_trained": "N/A"
            }
        else:
            # Decode bytes to strings if needed
            model_info = {k.decode() if isinstance(k, bytes) else k:
                         v.decode() if isinstance(v, bytes) else v
                         for k, v in model_info.items()}

        return jsonify({"data": model_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ml_detector.route("/features/importance")
def get_feature_importance():
    """
    Get feature importance data for visualization
    Returns: Feature names and their importance scores
    """
    try:
        # Fetch feature importance from Redis
        features = db.r.hgetall("ml_detector:feature_importance")

        if not features:
            # Default feature importance
            features = {
                "total_packets": "0.25",
                "total_bytes": "0.22",
                "duration": "0.18",
                "dest_port": "0.15",
                "avg_packet_size": "0.12",
                "protocol": "0.08"
            }
        else:
            # Decode bytes to strings if needed
            features = {k.decode() if isinstance(k, bytes) else k:
                       v.decode() if isinstance(v, bytes) else v
                       for k, v in features.items()}

        data = [{"feature": k, "importance": float(v)} for k, v in features.items()]
        data.sort(key=lambda x: x["importance"], reverse=True)

        return jsonify({"data": data})
    except Exception as e:
        return jsonify({"error": str(e), "data": []}), 200


@ml_detector.route("/alerts")
def get_alerts():
    """
    Get ML detector alerts
    Returns: List of alerts generated by the ML detector
    """
    try:
        # Fetch alerts from Redis
        alerts = db.r.lrange("ml_detector:alerts", 0, 49)

        data = []
        for alert in alerts:
            if isinstance(alert, bytes):
                alert = alert.decode()
            alert_data = json.loads(alert)

            # Format timestamp if present
            if "timestamp" in alert_data:
                alert_data["timestamp_formatted"] = ts_to_date(
                    alert_data["timestamp"], seconds=True
                )

            data.append(alert_data)

        return jsonify({"data": data})
    except Exception as e:
        return jsonify({"error": str(e), "data": []}), 200
