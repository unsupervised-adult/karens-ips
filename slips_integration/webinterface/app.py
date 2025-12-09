# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
from flask import Flask, render_template, redirect, url_for

from slips_files.common.parsers.config_parser import ConfigParser
from .database.database import db
from .ml_detector.ml_detector import ml_detector
from .suricata_config.suricata_config import suricata_bp
from .database.signals import message_sent
from .analysis.analysis import analysis
from .general.general import general
from .documentation.documentation import documentation
from .utils import get_open_redis_ports_in_order
from .auth import auth_bp, login_required


def create_app():
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False  # disable sorting of timewindows
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour session
    return app


app = create_app()

# Register blueprints - MUST be outside if __name__ == "__main__"
# because webinterface.sh runs with "python3 -m webinterface.app"
app.register_blueprint(auth_bp)
app.register_blueprint(analysis, url_prefix="/analysis")
app.register_blueprint(general, url_prefix="/general")
app.register_blueprint(documentation, url_prefix="/documentation")
app.register_blueprint(ml_detector, url_prefix="/ml_detector")
app.register_blueprint(suricata_bp, url_prefix="/suricata")


@app.route("/redis")
def read_redis_port():
    """
    is called when changing the db from the button at the top right
    prints the available redis dbs and ports for the user to choose ffrom
    """
    res = get_open_redis_ports_in_order()
    return {"data": res}

@app.route("/")
@login_required
def index():
    return render_template("app.html", title="Slips")
    return render_template("app.html", title="Slips")


@app.route("/db/<new_port>")
def get_post_javascript_data(new_port):
    """
    is called when the user chooses another db to connect to from the
    button at the top right (from /redis)
    should send a msg to update_db() in database.py
    """
    message_sent.send(int(new_port))
    return redirect(url_for("index"))


@app.route("/info")
def set_pcap_info():
    """
    Set information about the pcap.
    """
    info = db.get_analysis_info()

    profiles = db.get_profiles()
    info["num_profiles"] = len(profiles) if profiles else 0

    alerts_number = db.get_number_of_alerts_so_far()
    info["num_alerts"] = int(alerts_number) if alerts_number else 0

    return info


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=ConfigParser().web_interface_port)
