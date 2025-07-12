import json
from pathlib import Path
from datetime import datetime

# Load trusted firmware hashes
hash_file = Path(__file__).parent / "firmware_hashes.json"
with open(hash_file, "r") as f:
    TRUSTED_FIRMWARE_HASHES = json.load(f)

# Define known risky ports
RISKY_PORTS = {23, 21, 69}  # Telnet, FTP, TFTP

def calculate_trust_score(telemetry):
    """
    Calculates the trust score based on multiple telemetry metrics.
    Returns (score, firmware_verified)
    """
    raw_score = 0

    # === 1. Firmware Hash ===
    version = telemetry.get("firmware_version")
    reported_hash = telemetry.get("firmware_hash")
    expected_hash = TRUSTED_FIRMWARE_HASHES.get(version)
    firmware_verified = (reported_hash == expected_hash)
    raw_score += 30 if firmware_verified else 0

    # === 2. Patch History ===
    patch_date_str = telemetry.get("last_patch_date")
    try:
        patch_date = datetime.strptime(patch_date_str, "%Y-%m-%d")
        days_since_patch = (datetime.now() - patch_date).days
        if days_since_patch <= 60:
            raw_score += 20
        # else: 0 points
    except:
        pass  # Malformed or missing date = 0 points

    # === 3. Port Exposure Ratio (PER) ===
    open_ports = telemetry.get("open_ports", [])
    required_ports = telemetry.get("required_ports", [])
    if open_ports and required_ports:
        risky_ports = len(set(open_ports) - set(required_ports))
        per = risky_ports / max(len(open_ports), 1)
        exposure_penalty = min(1.0, per)
        exposure_score = (1 - exposure_penalty) * 20
        raw_score += round(exposure_score, 2)

    # === 4. Uptime (Stability Proxy) ===
    uptime = telemetry.get("uptime", 0)
    if uptime >= 86400:       # >= 1 day
        raw_score += 20
    elif uptime >= 43200:     # >= 12 hours
        raw_score += 10
    # else: 0

    # === 5. Excessive Open Ports Penalty ===
    if open_ports:
        if len(open_ports) > 20:
            raw_score -= 10
        elif len(open_ports) > 10:
            raw_score -= 5

    # === 6. Known Dangerous Ports Penalty ===
    if any(port in RISKY_PORTS for port in open_ports):
        raw_score -= 10

    # === 7. Reboot Instability Penalty ===
    reboot_count = telemetry.get("reboot_count", 0)
    if reboot_count > 5:
        raw_score -= min(10, reboot_count * 1.5)
    elif reboot_count == 0:
        raw_score += 5  # Bonus for rock-solid uptime

    # === Normalize score to 0–100 ===
    final_score = min(100, max(0, round(raw_score, 2)))
    return final_score, firmware_verified
