from tinydb import TinyDB, Query
from pathlib import Path

# Create DB directory if it doesn't exist
db_path = Path(__file__).parent / "telemetry_db.json"
db = TinyDB(db_path)
Device = Query()

def save_telemetry(device_id, telemetry):
    db.upsert({
        "device_id": device_id,
        "telemetry": telemetry
    }, Device.device_id == device_id)

def get_device_telemetry(device_id):
    result = db.search(Device.device_id == device_id)
    return result[0] if result else None
