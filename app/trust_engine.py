from datetime import datetime
from dateutil.parser import parse as parse_date

def calculate_trust_score(telemetry: dict) -> float:
    """
    Calculate the trust score based on IoT telemetry.
    Inputs expected in telemetry:
        - firmware_hash: str
        - reboot_frequency: float
        - patch_history: List of ISO date strings
        - port_exposure_ratio: float
        - historical_behavior: {
            average_reboots: float
        }
    """

    score = 0

    # --- 1. Firmware Hash (30 pts) ---
    known_good_hash = "abc123"
    current_hash = telemetry.get("firmware_hash")
    score += 30 if current_hash == known_good_hash else 0

    # --- 2. Reboot Frequency (20 pts) ---
    r_curr = telemetry.get("reboot_frequency", 0)
    r_avg = telemetry.get("historical_behavior", {}).get("average_reboots", 1)

    try:
        rf_score = max(0, (2 - (r_curr / r_avg)) * 20)
    except ZeroDivisionError:
        rf_score = 0

    score += rf_score

    # --- 3. Patch History (20 pts) ---
    patch_dates = telemetry.get("patch_history", [])
    if patch_dates:
        last_patch_date = max([parse_date(d) for d in patch_dates])
        days_since_patch = (datetime.now() - last_patch_date).days
        normalized = min(max((days_since_patch - 30) / 150, 0), 1)
        patch_score = (1 - normalized) * 20
    else:
        patch_score = 0

    score += patch_score

    # --- 4. Port Exposure Ratio (20 pts) ---
    per = telemetry.get("port_exposure_ratio", 1.0)  # default to risky
    per_score = max(0, (2 - 2 * per) * 20)
    score += per_score

    return round(score, 2)
