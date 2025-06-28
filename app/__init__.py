from flask import Flask, request, jsonify
from .trust_engine import calculate_trust_score
from .db import save_or_update_device, update_enforced_policy
from .policy_admin import determine_policy

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "Zero Trust IoT Framework API is up and running! ✅"

    @app.route("/policy-engine/evaluate", methods=["POST"])
    def evaluate_policy():
        """
        Accepts telemetry, calculates trust score, saves device state.
        """
        data = request.get_json()

        mac_address = data.get("mac_address")
        telemetry = data.get("telemetry")

        if not mac_address or not telemetry:
            return jsonify({"error": "Missing mac_address or telemetry"}), 400

        try:
            # Run trust algorithm
            trust_score, firmware_verified = calculate_trust_score(telemetry)

            # Save to DB
            updated_record = save_or_update_device(
                mac_address=mac_address,
                telemetry=telemetry,
                trust_score=trust_score,
                firmware_verified=firmware_verified
            )

            # Return result
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
        """
        Accepts telemetry, calculates trust score, generates policy actions.
        """
        data = request.get_json()

        mac_address = data.get("mac_address")
        telemetry = data.get("telemetry")

        if not mac_address or not telemetry:
            return jsonify({"error": "Missing mac_address or telemetry"}), 400

        try:
            # Step 1: Evaluate trust
            trust_score, firmware_verified = calculate_trust_score(telemetry)

            # Step 2: Save to DB
            device_record = save_or_update_device(
                mac_address=mac_address,
                telemetry=telemetry,
                trust_score=trust_score,
                firmware_verified=firmware_verified
            )

            # Step 3: Generate policy enforcement
            result = determine_policy(mac_address, trust_score)

            # Step 4: Update last enforced policy in DB
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

    return app
