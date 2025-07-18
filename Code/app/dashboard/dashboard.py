from flask import Blueprint, render_template, request, redirect, url_for, flash
from ..trust_engine import calculate_trust_score
from ..db import (
    save_or_update_device,
    get_all_devices,
    get_device,
    get_db,
    reload_db,
    update_enforced_policy
)
from ..policy_admin import determine_policy
from tinydb import where

dashboard_routes = Blueprint("dashboard", __name__, template_folder=".")
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
    pep_address = request.form.get("pep_address")

    open_ports_raw = request.form.get("open_ports", "")
    required_ports_raw = request.form.get("required_ports", "")

    open_ports = [int(p.strip()) for p in open_ports_raw.split(",") if p.strip()]
    required_ports = [int(p.strip()) for p in required_ports_raw.split(",") if p.strip()]

    telemetry = {
        "firmware_hash": firmware,
        "firmware_version": firmware_version,
        "uptime": uptime,
        "last_patch_date": patch_date,
        "open_ports": open_ports,
        "required_ports": required_ports,
        "interface": interface,
        "pep_address": pep_address
    }

    save_or_update_device(mac, telemetry, trust_score=None, firmware_verified=None)
    flash("✅ Device submitted. Awaiting trust evaluation.", "success")
    return redirect(url_for("dashboard.dashboard_view"))


@dashboard_routes.route("/dashboard")
def dashboard_view():
    all_devices = get_all_devices()

    stats = {
        "trusted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "trusted"),
        "restricted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "restricted"),
        "block": sum(1 for d in all_devices if d.get("last_enforced_policy") == "block"),
        "total": len(all_devices)
    }

    return render_template("dashboard.html", devices=all_devices, stats=stats)


@dashboard_routes.route("/dashboard/evaluate/<mac>", methods=["POST"])
def manual_evaluate(mac):
    device = get_device(mac)
    if not device:
        flash(f"❌ Device {mac} not found.", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    telemetry = device.get("telemetry", {})
    telemetry["required_ports"] = telemetry.get("required_ports", [])

    try:
        trust_score, firmware_verified = calculate_trust_score(telemetry)
        updated_record = save_or_update_device(mac, telemetry, trust_score, firmware_verified)
        result = determine_policy(mac, trust_score)
        update_enforced_policy(mac, result["policy_type"])
        flash(f"✅ {mac} evaluated. Policy: {result['policy_type']}", "success")

        all_devices = get_all_devices()
        stats = {
            "trusted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "trusted"),
            "restricted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "restricted"),
            "block": sum(1 for d in all_devices if d.get("last_enforced_policy") == "block"),
            "total": len(all_devices)
        }

        return render_template("dashboard.html", devices=all_devices, result=result, stats=stats)
    except Exception as e:
        flash(f"❌ Evaluation failed for {mac}: {str(e)}", "error")
        return redirect(url_for("dashboard.dashboard_view"))


@dashboard_routes.route("/delete_all", methods=["POST"])
def delete_all_devices():
    db.truncate()
    reload_db()
    flash("🗑️ All devices have been deleted.", "warning")

    stats = {"trusted": 0, "restricted": 0, "block": 0, "total": 0}
    return render_template("dashboard.html", devices=[], stats=stats)


@dashboard_routes.route("/delete/<mac>", methods=["POST"])
def delete_device(mac):
    try:
        device = get_device(mac)
        if not device:
            flash(f"❌ Device {mac} not found.", "error")
        else:
            db.remove(where("mac_address") == mac)
            flash(f"🗑️ Device {mac} deleted.", "warning")
    except Exception as e:
        flash(f"❌ Error deleting {mac}: {str(e)}", "error")

    all_devices = get_all_devices()
    stats = {
        "trusted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "trusted"),
        "restricted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "restricted"),
        "block": sum(1 for d in all_devices if d.get("last_enforced_policy") == "block"),
        "total": len(all_devices)
    }

    return render_template("dashboard.html", devices=all_devices, stats=stats)
