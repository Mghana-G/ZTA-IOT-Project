# mqtt_to_flask_bridge.py

import json
import datetime
import paho.mqtt.client as mqtt
import requests

# === CONFIGURATION ===
MQTT_BROKER = "127.0.0.1"         # Broker runs on localhost
MQTT_PORT = 1883
MQTT_TOPIC = "iot/+/telemetry"    # Wildcard to catch all telemetry messages
FLASK_ENDPOINT = "http://127.0.0.1:5000/telemetry/ingest"  # New endpoint for storage only

# === CALLBACK: On Connect ===
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Connected to MQTT Broker")
        client.subscribe(MQTT_TOPIC)
        print(f"📡 Subscribed to topic: {MQTT_TOPIC}")
    else:
        print(f"❌ MQTT connection failed with code {rc}")

# === CALLBACK: On Message ===
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        print(f"\n📥 MQTT message from {msg.topic}:\n{json.dumps(payload, indent=2)}")

        # Extract mac_address from payload or fallback to topic identifier
        mac_address = payload.get("mac_address")
        if not mac_address:
            topic_parts = msg.topic.split("/")
            mac_address = topic_parts[1] if len(topic_parts) > 1 else "unknown"

        # Build the data payload
        data_to_send = {
            "mac_address": mac_address,
            "telemetry": payload,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
        }

        # Forward to Flask ingestion endpoint
        response = requests.post(FLASK_ENDPOINT, json=data_to_send)

        if response.status_code == 200:
            print("✅ Telemetry successfully stored in Flask DB.")
        else:
            print(f"❌ Flask responded with {response.status_code}: {response.text}")

    except Exception as e:
        print(f"🚨 Error processing MQTT message: {e}")

# === MAIN LOOP ===
def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        print("🚀 Starting MQTT → Flask bridge...")
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n🛑 Bridge manually stopped by user.")
    except Exception as e:
        print(f"🚨 Bridge failed to start: {e}")

if __name__ == "__main__":
    main()
