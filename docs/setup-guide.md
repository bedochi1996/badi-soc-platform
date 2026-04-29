# BADI SOC Platform - Setup Guide

## Overview
This guide will help you set up and configure the BADI SOC Platform for your environment.

## Prerequisites
- Python 3.8+
- Git
- Basic understanding of SOC operations

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/bedochi1996/badi-soc-platform.git
cd badi-soc-platform
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration
Configure your SIEM connection and alert sources in `config/settings.json`

### 4. Running the Platform
```bash
python main.py
```

## Usage

### Alert Triage
Use the alert triage system to classify and prioritize incoming security alerts:
```bash
python tools/alert_triage.py
```

### Playbooks
Response playbooks are located in the `playbooks/` directory. Each playbook follows MITRE ATT&CK framework.

## Support
For questions and support, please open an issue on GitHub.
