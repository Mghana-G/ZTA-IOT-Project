from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from pathlib import Path
from datetime import datetime

# === Database Setup ===
db_path = Path(__file__).parent / "telemetry_db.json"
db = TinyDB(db_path, storage=CachingMiddleware(lambda p: JSONStorage(p, indent=4)))
Device = Query()


def get_db():
    """Return shared TinyDB instance."""
    return db


# === Device Operations ===

def get_device(mac_address):
    """Retrieve a single device record by MAC address."""
    result = db.search(Device.mac_address == mac_address)
    return result[0] if result else None


def get_all_devices():
    """Return all device records."""
    return db.all()


def save_or_update_device(mac_address, telemetry, trust_score, firmware_verified):
    now = datetime.now().isoformat()
    current_uptime = telemetry.get("uptime", 0)
    pep_address = telemetry.get("pep_address", "")

    existing = get_device(mac_address)

    if not existing:
        record = {
            "mac_address": mac_address,
            "telemetry": telemetry,
            "trust_score": trust_score,
            "firmware_verified": firmware_verified,
            "last_seen_at": now,
            "last_uptime": current_uptime,
            "reboot_count": 0,
            "last_enforced_policy": None,
        }
        db.insert(record)
        db.storage.flush()  # ✅ force save to telemetry_db.json
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
        "last_enforced_policy": existing.get("last_enforced_policy")
    }

    db.update(updated, Device.mac_address == mac_address)
    db.storage.flush()  # ✅ force save update to disk
    return updated


def update_enforced_policy(mac_address, policy_type):
    """Update the last enforced policy for a device."""
    db.update({"last_enforced_policy": policy_type}, Device.mac_address == mac_address)


def delete_all_devices():
    """Delete all records from the database and flush to disk."""
    db.truncate()
    db._read_table('_default')._cache.clear()  # Optional: clear in-memory cache
    db.storage.flush()  # Ensure changes are written to telemetry_db.json

def reload_db():
    """Reload the TinyDB instance from disk and reset the cache."""
    global db
    db.close()  # Close the current instance
    db = TinyDB(db_path, storage=CachingMiddleware(lambda p: JSONStorage(p, indent=4)))
    return db