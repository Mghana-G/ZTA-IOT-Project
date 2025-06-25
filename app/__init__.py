from flask import Flask, request, jsonify
from .trust_engine import calculate_trust_score
from .db import save_or_update_device

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

    return app
