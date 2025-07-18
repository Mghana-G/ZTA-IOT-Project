from tinydb import TinyDB, Query
from pathlib import Path
from datetime import datetime

# Database file path
db_path = Path(__file__).parent / "telemetry_db.json"
db = TinyDB(db_path)
Device = Query()

def get_device(mac_address):
    """Retrieve the full device record by MAC address."""
    result = db.search(Device.mac_address == mac_address)
    return result[0] if result else None

def save_or_update_device(mac_address, telemetry, trust_score, firmware_verified):
    """
    Store or update device telemetry and trust state.
    Tracks reboot count using uptime comparisons.
    Adds last_enforced_policy tracking.
    """
    now = datetime.now().isoformat()
    current_uptime = telemetry.get("uptime", 0)

    existing = get_device(mac_address)

    if not existing:
        # First-time insert
        record = {
            "mac_address": mac_address,
            "telemetry": telemetry,
            "trust_score": trust_score,
            "firmware_verified": firmware_verified,
            "last_seen_at": now,
            "last_uptime": current_uptime,
            "reboot_count": 0,
            "last_enforced_policy": None  # NEW FIELD
        }
        db.insert(record)
        return record

    previous_uptime = existing.get("last_uptime", 0)
    reboot_count = existing.get("reboot_count", 0)

    if current_uptime < previous_uptime:
        reboot_count += 1

    updated = {
        "mac_address": mac_address,
        "telemetry": telemetry,
        "trust_score": trust_score,
        "firmware_verified": firmware_verified,
        "last_seen_at": now,
        "last_uptime": current_uptime,
        "reboot_count": reboot_count,
        "last_enforced_policy": existing.get("last_enforced_policy")  # preserve
    }

    db.update(updated, Device.mac_address == mac_address)
    return updated

def update_enforced_policy(mac_address, policy_type):
    """
    Store the last enforced policy (e.g., 'trusted', 'restricted', 'block').
    """
    db.update({"last_enforced_policy": policy_type}, Device.mac_address == mac_address)

def get_all_devices():
    """Return all records."""
    return db.all()

def reset_database():
    """Clear all records — use for testing."""
    db.truncate()
