from flask import Blueprint, render_template, request, redirect, url_for, flash
from ..trust_engine import calculate_trust_score
from ..db import save_or_update_device, get_all_devices, get_db, reload_db

dashboard_routes = Blueprint("dashboard", __name__, template_folder=".")

# ✅ Shared database instance
db = get_db()

@dashboard_routes.route("/")
def home():
    return render_template("form.html")

@dashboard_routes.route("/submit", methods=["POST"])
def submit():
    mac = request.form.get("mac_address")
    firmware = request.form.get("firmware_hash")
    firmware_version = request.form.get("firmware_version")
    uptime = int(request.form.get("uptime", 0))
    patch_date = request.form.get("last_patch_date")
    interface = request.form.get("interface")

    open_ports = [int(p.strip()) for p in request.form.getlist("open_ports") if p.strip()]
    required_ports = [int(p.strip()) for p in request.form.getlist("required_ports") if p.strip()]

    telemetry = {
        "firmware_hash": firmware,
        "firmware_version": firmware_version,
        "uptime": uptime,
        "last_patch_date": patch_date,
        "open_ports": open_ports,
        "required_ports": required_ports,
        "interface": interface
    }

    trust_score, firmware_verified = calculate_trust_score(telemetry)
    save_or_update_device(mac, telemetry, trust_score, firmware_verified)

    flash("Device submitted successfully.", "success")
    return redirect(url_for("dashboard.dashboard_view"))

@dashboard_routes.route("/dashboard")
def dashboard_view():
    all_devices = get_all_devices()
    return render_template("dashboard.html", devices=all_devices)

@dashboard_routes.route("/delete_all", methods=["POST"])
def delete_all_devices():
    db.truncate()
    db.storage.flush()  # ✅ Write deletion to telemetry_db.json
    reload_db()
    flash("All devices have been deleted successfully.", "warning")
    return redirect(url_for("dashboard.dashboard_view"))
