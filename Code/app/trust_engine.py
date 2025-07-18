import json
from pathlib import Path
from datetime import datetime

# Load trusted firmware hashes
hash_file = Path(__file__).parent / "firmware_hashes.json"
with open(hash_file, "r") as f:
    TRUSTED_FIRMWARE_HASHES = json.load(f)

# Define known risky ports
RISKY_PORTS = {23, 21, 69, 445}  

def calculate_trust_score(telemetry):
    """
    The default start no implicit trust so the score starts at 0
    """
    raw_score = 0

    # Firmware Verification (30%) 
    version = telemetry.get("firmware_version")
    reported_hash = telemetry.get("firmware_hash")
    expected_hash = TRUSTED_FIRMWARE_HASHES.get(version)
    firmware_verified = (reported_hash == expected_hash)
    raw_score += 30 if firmware_verified else 0

    # Patch History (20%)
    patch_date_str = telemetry.get("last_patch_date")
    try:
        patch_date = datetime.strptime(patch_date_str, "%Y-%m-%d")
        days_since_patch = (datetime.now() - patch_date).days
        if days_since_patch <= 60:
            raw_score += 20
    except:
        pass  
    # if the data is Malformed or missing = no points

    #  Port Exposure Ratio (30%) 
    open_ports = telemetry.get("open_ports", [])
    required_ports = telemetry.get("required_ports", [])
    if open_ports and required_ports:
        risky = len(set(open_ports) - set(required_ports))
        per = risky / max(len(open_ports), 1)
        exposure_penalty = min(1.0, per)
        exposure_score = (1 - exposure_penalty) * 30 
        raw_score += round(exposure_score, 2)

    # Uptime (10%) 
    uptime = telemetry.get("uptime", 0)
    if uptime >= 86400:       # translated into days it is 1 day
        raw_score += 10
    elif uptime >= 43200:     # translated into hours it is 12 hours
        raw_score += 5
    # else: 0

    # Bonus: Reboot Stability 
    reboot_count = telemetry.get("reboot_count", 0)
    if reboot_count == 0:
        raw_score += 5

    # Penalty: Excessive Open Ports 
    if open_ports:
        if len(open_ports) > 20:
            raw_score -= 10
        elif len(open_ports) > 10:
            raw_score -= 5

    # Penalty: Known Dangerous Ports (-10) 
    risky_count = sum(1 for port in open_ports if port in RISKY_PORTS)
    raw_score -= risky_count * 10

    # Penalty: Excessive Reboots  
    if reboot_count > 5:
        raw_score -= min(10, reboot_count * 1.5)

    # Normalization 
    final_score = min(100, max(0, round(raw_score, 2)))
    return final_score, firmware_verified
