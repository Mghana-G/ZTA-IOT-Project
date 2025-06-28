from .db import get_device  # assumes this retrieves device by mac
from datetime import datetime

# Policy ranges and associated enforcement logic
POLICY_CONFIG = {
    "block": {
        "min": 0,
        "max": 20,
        "action": "shutdown"
    },
    "restricted": {
        "min": 21,
        "max": 60,
        "vlan": 10
    },
    "trusted": {
        "min": 61,
        "max": 100,
        "vlan": 1
    }
}

# Command templates
COMMAND_TEMPLATES = {
    "shutdown": [
        "interface {INTERFACE}",
        "shutdown"
    ],
    "no_shutdown": [
        "interface {INTERFACE}",
        "no shutdown"
    ],
    "vlan_assign": [
        "mac-address-table static {MAC} vlan {VLAN} interface {INTERFACE}"
    ],
    "vlan_remove": [
        "no mac-address-table static {MAC} vlan {VLAN} interface {INTERFACE}"
    ]
}

def determine_policy(mac_address, trust_score):
    """
    Determine policy based on trust score, issue rollback if needed,
    return new enforcement commands and policy type.
    """
    # Get current device record
    device = get_device(mac_address)
    if not device:
        raise Exception("Device not found in database.")

    interface = device.get("telemetry", {}).get("interface")
    if not interface:
        raise Exception("No interface provided in device telemetry.")

    last_policy = device.get("last_enforced_policy")
    current_policy = None
    commands = []
    rollback = []

    # Normalize MAC formatting
    mac_clean = mac_address.replace(":", "").upper()

    # Determine current policy type
    for policy, config in POLICY_CONFIG.items():
        if config["min"] <= trust_score <= config["max"]:
            current_policy = policy
            break

    if not current_policy:
        raise Exception("Trust score does not fit any policy tier.")

    # === Step 1: Rollback previous policy
    if last_policy and last_policy != current_policy:
        if last_policy in ["trusted", "restricted"]:
            vlan = POLICY_CONFIG[last_policy]["vlan"]
            rollback += [
                cmd.format(MAC=mac_address, VLAN=vlan, INTERFACE=interface)
                for cmd in COMMAND_TEMPLATES["vlan_remove"]
            ]
        elif last_policy == "block":
            rollback += [
                cmd.format(INTERFACE=interface)
                for cmd in COMMAND_TEMPLATES["no_shutdown"]
            ]

    # === Step 2: Apply new policy
    if current_policy == "block":
        commands += [
            cmd.format(INTERFACE=interface)
            for cmd in COMMAND_TEMPLATES["shutdown"]
        ]
    else:
        vlan = POLICY_CONFIG[current_policy]["vlan"]
        commands += [
            cmd.format(MAC=mac_address, VLAN=vlan, INTERFACE=interface)
            for cmd in COMMAND_TEMPLATES["vlan_assign"]
        ]

    return {
        "mac_address": mac_address,
        "interface": interface,
        "trust_score": trust_score,
        "policy_type": current_policy,
        "rollback": rollback,
        "commands": commands,
        "timestamp": datetime.now().isoformat()
    }
