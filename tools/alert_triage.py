#!/usr/bin/env python3
"""
Alert Triage System - BADI SOC Platform
Author: Badi Alosaimi | v1.0

Auto-classifies SIEM alerts by severity, MITRE ATT&CK technique,
and recommended response actions.
"""
import json
from typing import Dict

ALERT_RULES = {
    "brute_force": {"severity": "HIGH", "mitre": "T1110", "playbook": "PB-001"},
    "malware_detected": {"severity": "CRITICAL", "mitre": "T1204", "playbook": "PB-003"},
    "privilege_escalation": {"severity": "CRITICAL", "mitre": "T1078", "playbook": "PB-005"},
    "port_scan": {"severity": "MEDIUM", "mitre": "T1046", "playbook": "PB-007"},
}

def classify_alert(alert_type: str) -> Dict:
    rule = ALERT_RULES.get(alert_type, {"severity": "UNKNOWN", "mitre": "N/A", "playbook": "MANUAL"})
    return {"classification": rule, "recommended_action": f"Follow {rule['playbook']}"}

if __name__ == "__main__":
    alert = "brute_force"
    result = classify_alert(alert)
    print(json.dumps(result, indent=2))
