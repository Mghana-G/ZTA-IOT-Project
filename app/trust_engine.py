import json
from pathlib import Path
from datetime import datetime

# Load trusted firmware hashes
hash_file = Path(__file__).parent / "firmware_hashes.json"
with open(hash_file, "r") as f:
    TRUSTED_FIRMWARE_HASHES = json.load(f)

def calculate_trust_score(telemetry):
    """
    Calculates the trust score based on multiple telemetry metrics.
    Returns (score, firmware_verified)
    """
    score = 0

    # === 1. Firmware Hash ===
    version = telemetry.get("firmware_version")
    reported_hash = telemetry.get("firmware_hash")
    expected_hash = TRUSTED_FIRMWARE_HASHES.get(version)
    firmware_verified = (reported_hash == expected_hash)
    score += 30 if firmware_verified else 0

    # === 2. Patch History ===
    patch_date_str = telemetry.get("last_patch_date")
    try:
        patch_date = datetime.strptime(patch_date_str, "%Y-%m-%d")
        days_since_patch = (datetime.now() - patch_date).days
        if days_since_patch <= 60:
            score += 20
        # else: 0 points
    except:
        pass  # malformed or missing date = 0 points

    # === 3. Port Exposure Ratio (PER) ===
    open_ports = telemetry.get("open_ports", [])
    required_ports = telemetry.get("required_ports", [])
    if open_ports and required_ports:
        risky_ports = len(set(open_ports) - set(required_ports))
        per = risky_ports / max(len(open_ports), 1)  # prevent div by 0
        if per <= 0.5:
            score += 20
        elif per < 1.0:
            score += max(0, (2 - 2 * per) * 20)
        # else: 0 points

    # === 4. Uptime (Reboot Proxy) ===
    uptime = telemetry.get("uptime", 0)
    if uptime >= 86400:  # >= 1 day
        score += 20
    elif uptime >= 43200:  # >= 12 hours
        score += 10
    # else: 0

    # === Total Max Score = 90 (we’ll scale or extend later) ===
    return round(score, 2), firmware_verified
