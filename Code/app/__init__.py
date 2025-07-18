import os
import atexit
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from apscheduler.schedulers.background import BackgroundScheduler
from .trust_engine import calculate_trust_score
from .db import save_or_update_device, update_enforced_policy, get_all_devices, get_device, delete_all_devices
from .policy_admin import determine_policy
from .dashboard.dashboard import dashboard_routes
import requests

def create_app():
    template_path = os.path.join(os.path.dirname(__file__), "dashboard")
    app = Flask(__name__, template_folder=template_path)

    app.secret_key = "super_secret_key"
    app.register_blueprint(dashboard_routes, url_prefix="/dashboard")

    @app.route("/")
    def home():
        return render_template("form.html")

    @app.route("/submit", methods=["POST"])
    def submit():
        try:
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

            trust_score, firmware_verified = calculate_trust_score(telemetry)
            save_or_update_device(mac, telemetry, trust_score, firmware_verified)
            result = determine_policy(mac, trust_score)
            update_enforced_policy(mac, result["policy_type"])

            all_devices = get_all_devices()
            return render_template("dashboard.html", devices=all_devices, result=result)

        except Exception as e:
            return f"❌ Error during submission: {str(e)}", 500

    @app.route("/dashboard")
    def dashboard():
        all_devices = get_all_devices()

        stats = {
        "trusted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "trusted"),
        "restricted": sum(1 for d in all_devices if d.get("last_enforced_policy") == "restricted"),
        "block": sum(1 for d in all_devices if d.get("last_enforced_policy") == "block"),
        "total": len(all_devices)
    }

        return render_template("dashboard.html", devices=all_devices, stats=stats)


    @app.route("/dashboard/evaluate/<mac>", methods=["POST"])
    def manual_evaluate(mac):
        try:
            device = get_device(mac)
            if not device:
                return jsonify({"error": "Device not found"}), 404

            telemetry = device.get("telemetry", {})
            trust_score, firmware_verified = calculate_trust_score(telemetry)
            updated = save_or_update_device(mac, telemetry, trust_score, firmware_verified)
            result = determine_policy(mac, trust_score)
            update_enforced_policy(mac, result["policy_type"])

            return jsonify({
                "mac_address": mac,
                "trust_score": trust_score,
                "firmware_verified": firmware_verified,
                "policy_type": result["policy_type"],
                "rollback": result["rollback"],
                "commands": result["commands"],
                "interface": result["interface"],
                "timestamp": result["timestamp"]
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/telemetry/upload", methods=["POST"])
    def upload_telemetry():
        try:
            data = request.get_json()
            mac = data.get("mac_address")
            telemetry = data.get("telemetry")

            if not mac or not telemetry:
                return jsonify({"error": "Missing mac_address or telemetry"}), 400

            existing = get_device(mac)
            if existing:
                existing_telemetry = existing.get("telemetry", {})
                for key in ["interface", "pep_address", "firmware_hash", "required_ports"]:
                    if key in existing_telemetry:
                        telemetry[key] = existing_telemetry[key]

            save_or_update_device(mac, telemetry, None, False)

            return jsonify({
                "mac_address": mac,
                "status": "stored",
                "telemetry": telemetry
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/telemetry/ingest", methods=["POST"])
    def ingest_telemetry():
        try:
            data = request.get_json()
            mac = data.get("mac_address")
            telemetry = data.get("telemetry")

            if not mac or not telemetry:
                return jsonify({"error": "Missing mac_address or telemetry"}), 400

            existing = get_device(mac)
            if existing:
                existing_telemetry = existing.get("telemetry", {})
                for key in ["interface", "pep_address", "firmware_hash", "required_ports"]:
                    if key in existing_telemetry:
                        telemetry[key] = existing_telemetry[key]

            save_or_update_device(mac, telemetry, None, False)

            return jsonify({
                "status": "ok",
                "mac_address": mac,
                "stored_telemetry": telemetry
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/policy-engine/evaluate", methods=["POST"])
    def evaluate_policy():
        data = request.get_json()
        mac_address = data.get("mac_address")
        telemetry = data.get("telemetry")

        if not mac_address or not telemetry:
            return jsonify({"error": "Missing mac_address or telemetry"}), 400

        try:
            trust_score, firmware_verified = calculate_trust_score(telemetry)
            updated_record = save_or_update_device(mac_address, telemetry, trust_score, firmware_verified)
            return jsonify({
                "mac_address": mac_address,
                "trust_score": trust_score,
                "firmware_verified": firmware_verified,
                "reboot_count": updated_record["reboot_count"],
                "last_seen_at": updated_record["last_seen_at"]
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/policy-admin/authorize", methods=["POST"])
    def authorize_device():
        data = request.get_json()
        mac_address = data.get("mac_address")
        telemetry = data.get("telemetry")

        if not mac_address or not telemetry:
            return jsonify({"error": "Missing mac_address or telemetry"}), 400

        try:
            trust_score, firmware_verified = calculate_trust_score(telemetry)
            device_record = save_or_update_device(mac_address, telemetry, trust_score, firmware_verified)
            result = determine_policy(mac_address, trust_score)
            update_enforced_policy(mac_address, result["policy_type"])

            return jsonify({
                "mac_address": mac_address,
                "trust_score": trust_score,
                "firmware_verified": firmware_verified,
                "policy_type": result["policy_type"],
                "rollback": result["rollback"],
                "commands": result["commands"],
                "interface": result["interface"],
                "timestamp": result["timestamp"]
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/submit-telemetry", methods=["GET", "POST"])
    def submit_telemetry():
        if request.method == "POST":
            try:
                mac_address = request.form["mac_address"]
                firmware_hash = request.form["firmware_hash"]
                firmware_version = request.form["firmware_version"]
                uptime = int(request.form["uptime"])
                last_patch_date = request.form["last_patch_date"]
                interface = request.form["interface"]
                pep_address = request.form.get("pep_address")

                open_ports_raw = request.form.get("open_ports", "")
                required_ports_raw = request.form.get("required_ports", "")

                open_ports = [int(p.strip()) for p in open_ports_raw.split(",") if p.strip()]
                required_ports = [int(p.strip()) for p in required_ports_raw.split(",") if p.strip()]

                telemetry = {
                    "firmware_hash": firmware_hash,
                    "firmware_version": firmware_version,
                    "uptime": uptime,
                    "last_patch_date": last_patch_date,
                    "interface": interface,
                    "open_ports": open_ports,
                    "required_ports": required_ports,
                    "pep_address": pep_address
                }

                payload = {
                    "mac_address": mac_address,
                    "telemetry": telemetry
                }

                response = requests.post("http://127.0.0.1:5000/policy-admin/authorize", json=payload)

                if response.status_code == 200:
                    result = response.json()
                    return render_template("dashboard.html", result=result, devices=get_all_devices())
                else:
                    return f"❌ Error: {response.status_code} - {response.text}", 500
            except Exception as e:
                return f"❌ Processing error: {str(e)}", 500

        return render_template("form.html")

    def run_hourly_check():
        print("⏰ Running hourly trust re-evaluation...")
        all_devices = get_all_devices()
        for device in all_devices:
            mac = device["mac_address"]
            telemetry = device.get("telemetry", {})
            telemetry["required_ports"] = telemetry.get("required_ports", [])
            try:
                trust_score, firmware_verified = calculate_trust_score(telemetry)
                save_or_update_device(mac, telemetry, trust_score, firmware_verified)
                result = determine_policy(mac, trust_score)
                update_enforced_policy(mac, result["policy_type"])
                print(f"✅ Re-evaluated {mac}: {result['policy_type']}")
            except Exception as e:
                print(f"❌ Error during scheduled check for {mac}: {e}")

    scheduler = BackgroundScheduler()
    scheduler.add_job(run_hourly_check, trigger="interval", hours=1)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))

    return app
