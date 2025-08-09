# Zero Trust IoT Security System

![Python](https://img.shields.io/badge/python-3.12-blue)
![Flask](https://img.shields.io/badge/framework-Flask-orange)
![NIST SP 800-207](https://img.shields.io/badge/NIST%20SP-800--207-blue)

## Overview
This project implements a **Zero Trust Architecture (ZTA)** for IoT networks, developed as part of a **Third Year University Project**.  
It follows **NIST SP 800-207 guidelines**, integrating **real-time, risk-based trust scoring** and **policy automation** to secure IoT devices in a segmented network environment.

The system includes:
- **Flask Web Dashboard** for device onboarding & live trust score monitoring.
- **Python-based MQTT Bridge** for telemetry ingestion & storage in TinyDB.
- **Policy Engine** for risk-based trust evaluation using penalties and bonuses.
- **Policy Administrator** for automated VLAN and port control on Cisco IOSvL2 switches in EVE-NG.
- **SSH Public Key Authentication** for secure, passwordless enforcement.

---

## Key Features
- **Real-time Trust Scoring** – Evaluates IoT devices on:
  - Firmware Integrity (hash verification)
  - Patch History (last security update)
  - Uptime & Reboot Frequency
  - Port Exposure Ratio
- **Risk-Based Algorithm** – Dynamically assigns policies:
  - **Trusted** – Full network access
  - **Restricted** – Isolated VLAN
  - **Blocked** – Port shutdown
- **Automated Enforcement** – Commands pushed via SSH (Pexpect) to simulated Cisco IOSvL2 switches.
- **Lightweight Performance** – Sub-5s policy reaction time, <30% CPU usage on a 4-core system.
- **Modular Design** – Easily extendable for other telemetry sources (non-MQTT).

---

## Tech Stack
| Category | Technology |
|----------|------------|
| **Language** | Python 3.12, HTML, CSS, JavaScript |
| **Framework** | Flask |
| **Database** | TinyDB |
| **IoT Telemetry** | MQTT, Custom Python Scripts |
| **Networking** | Cisco IOSvL2 (EVE-NG), VLAN Segmentation |
| **Automation** | Pexpect (SSH Automation) |
| **Virtualization** | VMware Workstation |
| **Security** | Public Key SSH Authentication |
| **Standards** | NIST SP 800-207 (Zero Trust Architecture) |


---

## Installation & Setup

# Clone the repository
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python run.py



