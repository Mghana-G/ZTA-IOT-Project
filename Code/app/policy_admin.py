from .db import get_device  # assumes this retrieves device by mac
from datetime import datetime
import os
import time
import socket
import pexpect
import logging
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
        "mac address-table static {MAC} vlan {VLAN} interface {INTERFACE}"
    ],
    "vlan_remove": [
        "no mac address-table static {MAC} vlan {VLAN} interface {INTERFACE}"
    ]
}

def determine_policy(mac_address, trust_score):
    device = get_device(mac_address)
    if not device:
        raise Exception("Device not found in database.")

    telemetry = device.get("telemetry", {})
    interface = telemetry.get("interface")
    pep_address = telemetry.get("pep_address")

    if not interface or not pep_address:
        raise Exception("Missing interface or PEP address in telemetry.")

    last_policy = device.get("last_enforced_policy")
    current_policy = None
    commands, rollback = [], []

    for policy, config in POLICY_CONFIG.items():
        if config["min"] <= trust_score <= config["max"]:
            current_policy = policy
            break

    if not current_policy:
        raise Exception("Trust score does not fit any policy tier.")

    # === Rollback Logic ===
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

    # === Enforcement Logic ===
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

    # === SSH Execution (only this is new) ===
    rollback_output = ""
    commands_output = ""
    try:
        if rollback:
            rollback_output = ssh_execute_commands(pep_address, command_list=rollback)
        commands_output = ssh_execute_commands(pep_address, command_list=commands)
    except Exception as e:
        rollback_output = f"❌ SSH error during rollback: {e}"
        commands_output = f"❌ SSH error during enforcement: {e}"

    return {
        "mac_address": mac_address,
        "interface": interface,
        "trust_score": trust_score,
        "policy_type": current_policy,
        "rollback": rollback,
        "commands": commands,
        "pep_address": pep_address,
        "rollback_output": rollback_output,
        "commands_output": commands_output,
        "timestamp": datetime.now().isoformat()
    }

# Enable logging
logging.basicConfig(level=logging.DEBUG)


def ssh_execute_commands(
    pep_address,
    username="admin",
    key_path="~/.ssh/id_rsa_cisco",
    command_list=None
):
    """
    Connects to a network device using the system's SSH client via pexpect
    and executes a list of commands. This version explicitly uses the
    working SSH command-line flags.
    """
    if command_list is None:
        command_list = []

    private_key_path = os.path.expanduser(key_path)
    
    # Construct the SSH command string with ALL the working -o flags
    ssh_command = (
        f"ssh -i {private_key_path} " # Identity file
        f"-o HostKeyAlgorithms=+ssh-rsa " # Explicitly enable ssh-rsa for host key
        f"-o PubkeyAcceptedKeyTypes=+ssh-rsa " # Explicitly enable ssh-rsa for pubkey auth (this was the tricky one!)
        f"-o KexAlgorithms=+diffie-hellman-group14-sha1 " # Explicitly enable Kex algorithm
        f"-o Ciphers=+aes256-cbc " # Explicitly enable Cipher
        f"-o StrictHostKeyChecking=no " # AutoAddPolicy equivalent for CLI SSH - use with caution
        f"-o UserKnownHostsFile=/dev/null " # To prevent issues with known_hosts file
        f"-o BatchMode=yes " # Ensures no password/prompts if key auth fails
        f"{username}@{pep_address}" # User and host
    )

    full_output = []
    
    try:
        print(f"🔐 Connecting to {pep_address} as {username} using pexpect...")
        print(f"🔑 Full SSH Command: {ssh_command}") # Log the exact command being run
        print(f"📡 Commands to send:\n{command_list}")

        # Spawn the SSH process
        # Increased timeout for initial connection, and encoding for output
        child = pexpect.spawn(ssh_command, encoding='utf-8', timeout=60)
        # Uncomment for very verbose pexpect debugging, shows exactly what's being sent/received
        # import sys
        # child.logfile_read = sys.stdout 

        # Expect the initial shell prompt after connection (Cisco devices)
        # We expect to land in either user exec (>) or privileged exec (#) mode directly
        # since key auth is configured.
        i = child.expect(['>', '#', pexpect.EOF, pexpect.TIMEOUT])

        if i == 0: # User exec mode ('>')
            logging.info("Detected user exec mode, attempting to elevate to privileged mode.")
            child.sendline('enable') # Try to enter enable mode
            j = child.expect(['Password:', '#', pexpect.EOF, pexpect.TIMEOUT])
            if j == 0: # Password prompt for enable
                # If your device has an enable password, you'd need to provide it here.
                # For now, assuming no enable password or it's empty, or you handle it elsewhere.
                # If there's an enable password, this will likely fail unless handled.
                logging.warning("Enable password prompt detected. This script does not automate enable password entry.")
                raise Exception("Enable password required for privileged access.")
            elif j == 1: # Successfully entered privileged mode ('#')
                logging.info("Successfully entered privileged exec mode.")
                pass
            else: # EOF or TIMEOUT
                raise Exception(f"Failed to reach privileged mode: {child.before}")
        elif i == 1: # Already in privileged exec mode ('#')
            logging.info("Already in privileged exec mode.")
            pass # Good to go
        elif i == 2: # EOF - connection closed prematurely
            raise Exception(f"SSH connection closed unexpectedly during initial connect: {child.before}")
        elif i == 3: # TIMEOUT
            raise Exception(f"SSH connection timed out during initial connect, no prompt: {child.before}")

        print("✅ Pexpect SSH connection and initial prompt successful.")
        
        # Send terminal length 0 for cleaner output
        child.sendline("terminal length 0")
        child.expect(['#', pexpect.TIMEOUT]) # Expect prompt or timeout
        full_output.append(child.before) 
        
        # Enter global configuration mode
        child.sendline("conf t")
        child.expect(['config#', '#', pexpect.TIMEOUT]) # Expect config prompt or already in config mode
        full_output.append(child.before)

        # Execute commands from the list
        for cmd in command_list:
            print(f"Sending command: {cmd}")
            child.sendline(cmd)
            # Expect config prompt, exec prompt, or error patterns
            index = child.expect(['config#', '#', 'Invalid input detected', 'Incomplete command', pexpect.TIMEOUT], timeout=15)
            chunk_output = child.before
            
            if index == 2 or index == 3: # Invalid input or Incomplete command
                logging.warning(f"Command '{cmd}' resulted in an error on the device: {chunk_output}")
            
            full_output.append(f"\n--- Output for '{cmd}' ---\n{chunk_output}")
            
            # If an error occurred, ensure we are back at a prompt before next command
            if index in [2, 3]:
                # Try to get back to a known prompt state if an error was detected
                child.expect(['config#', '#', pexpect.TIMEOUT], timeout=5)
                full_output.append(child.before) # Capture prompt after error

        # Exit config mode
        child.sendline("end")
        child.expect(['#', pexpect.TIMEOUT])
        full_output.append(child.before)

        # Write configuration to memory (save)
        child.sendline("wr")
        # Expect various outputs for 'wr' command
        index = child.expect(['Building configuration...', 'OK', '#', pexpect.TIMEOUT], timeout=30)
        output_wr = child.before
        if index == 0: # If it prints "Building configuration..."
             child.expect(['OK', '#', pexpect.TIMEOUT], timeout=10) # Wait for "OK" or the prompt
             output_wr += child.before # Append the rest of the output
        full_output.append(f"\n--- Write Memory Output ---\n{output_wr}")
        
        # Final exit from SSH session
        child.sendline("exit")
        child.expect(pexpect.EOF, timeout=10) # Expect the session to close
        full_output.append(child.before)

        child.close() # Close the pexpect spawned process

        # Check exit status of the SSH process
        if child.exitstatus != 0:
            logging.error(f"SSH process exited with non-zero status: {child.exitstatus}")
            logging.error(f"Child process output before exit: {child.before}")
            raise Exception(f"SSH command failed with exit status {child.exitstatus}")
        if child.signalstatus is not None:
            logging.error(f"SSH process terminated by signal: {child.signalstatus}")
            raise Exception(f"SSH command terminated by signal {child.signalstatus}")

        final_output_str = "".join(full_output)
        print("📤 Final SSH Output:\n", final_output_str)
        return final_output_str

    except pexpect.exceptions.EOF as eof_err:
        error_message = f"❌ Pexpect EOF Error (SSH session closed prematurely): {eof_err.value}\nLast received: {child.before}"
        print(error_message)
        raise Exception(error_message) # Re-raise as generic exception for determine_policy
    except pexpect.exceptions.TIMEOUT as timeout_err:
        error_message = f"❌ Pexpect Timeout Error (No expected response): {timeout_err.value}\nLast received: {child.before}"
        print(error_message)
        raise Exception(error_message)
    except Exception as e:
        error_message = f"❌ General Pexpect Exception: {e}"
        print(error_message)
        raise Exception(error_message)