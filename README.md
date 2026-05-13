# ALVSafe Antivirus

Cross-platform antivirus and endpoint protection platform developed in Python.

## Overview

ALVSafe is a security-focused application designed to provide malware detection, real-time monitoring and ransomware protection across multiple operating systems.

The project combines heuristic analysis, YARA-based detection and system monitoring features to create a lightweight and extensible security platform.

Compatible with:
- Windows
- Linux
- macOS

---

# Features

## Malware Detection
- File scanning engine
- Heuristic analysis
- YARA rule detection
- Signature-based scanning
- VirusTotal integration

## Protection Systems
- Real-time protection
- Ransomware monitoring
- File system monitoring
- Quarantine management
- Basic firewall module

## Interface & Monitoring
- Graphical user interface (GUI)
- Web dashboard
- Logs and reports
- Security event monitoring

## Architecture
- Modular Python structure
- Cross-platform support
- Extensible scanning engine
- Security-focused design

---

# Technologies Used

- Python
- YARA
- Flask
- SQLite
- Watchdog
- VirusTotal API

---

# Project Structure

```bash
ALVSafe/
├── engine/
├── yara_rules/
├── quarantine/
├── logs/
├── reports/
├── gui/
├── tests/
├── main.py
├── scanner.py
├── firewall.py
├── monitor.py
└── ransomware_protection.py
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/Alvaromra/AlvSafe.git
cd AlvSafe
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

## Full Scan

```bash
python3 main.py --scan ~/Downloads
```

## Real-Time Protection

```bash
python3 monitor.py
```

## Web Dashboard

```bash
python3 dashboard.py
```

---

# Security Modules

- Heuristic detection engine
- YARA scanning engine
- Ransomware behavior monitoring
- File integrity monitoring
- Quarantine system
- Firewall monitoring

---

# Roadmap

- Cloud threat intelligence
- AI-assisted malware classification
- Advanced firewall controls
- SIEM integration
- Threat hunting dashboard
- Distributed scanning architecture

---

# Disclaimer

This project is intended for educational, research and defensive cybersecurity purposes only.

---

# Author

**Alvaro Marcal de Araujo**

- Network & Communications Engineering — UnB
- Infrastructure • DevOps • Cybersecurity • AI Systems

GitHub:
https://github.com/Alvaromra
