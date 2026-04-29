# SIEM Alert Rules — BADI SOC Platform

This document contains custom SIEM detection rules for Splunk and Microsoft Sentinel, organized by attack category.

---

## Category 1: Credential Attacks

### Rule 1: SSH Brute Force Detection

**Splunk SPL:**
```spl
index=linux_auth sourcetype=syslog "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip, host
| where failed_attempts > 50
| eval severity=case(failed_attempts>500, "Critical", failed_attempts>100, "High", true(), "Medium")
| table src_ip, host, failed_attempts, severity
| sort -failed_attempts
```

**Sentinel KQL:**
```kql
Syslog
| where SyslogMessage contains "Failed password for"
| parse SyslogMessage with * "from " src_ip " port" *
| summarize failed_count=count() by src_ip, Computer, bin(TimeGenerated, 5m)
| where failed_count > 50
| extend Severity = iff(failed_count > 200, "High", "Medium")
```

**MITRE:** T1110.001 | **Severity:** High | **False Positive Rate:** Low

---

### Rule 2: Successful Login After Multiple Failures (Brute Force Success)

**Splunk SPL:**
```spl
index=linux_auth sourcetype=syslog
| rex field=_raw "(?P<status>Failed password|Accepted password) for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(status=="Failed password")) as failures,
        count(eval(status=="Accepted password")) as successes by src_ip, user
| where failures > 10 AND successes > 0
| eval alert="BRUTE_FORCE_SUCCESS"
```

**MITRE:** T1110.001 + T1078 | **Severity:** Critical

---

## Category 2: Phishing & Email Threats

### Rule 3: Suspicious Outbound Connection After Email Attachment Open

**Sentinel KQL:**
```kql
let PhishingTime = EmailEvents
    | where AttachmentCount > 0
    | where ThreatTypes contains "Phish"
    | project DeviceName, Timestamp, Subject;
DeviceNetworkEvents
| join kind=inner PhishingTime on DeviceName
| where Timestamp between (Timestamp .. (Timestamp + 10m))
| where RemotePort in (80, 443, 4444, 8080)
| where ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp, Subject
```

**MITRE:** T1566.001 + T1071.001 | **Severity:** High

---

## Category 3: Privilege Escalation

### Rule 4: Sudo Privilege Escalation Attempt

**Splunk SPL:**
```spl
index=linux_auth sourcetype=syslog "sudo"
| rex field=_raw "(?P<user>\S+) : (?P<status>command not allowed|authentication failure|NOT in sudoers)"
| where isnotnull(status)
| stats count by user, host, status
| where count > 3
| eval alert="SUDO_ABUSE_DETECTED"
```

**MITRE:** T1548.003 | **Severity:** High

---

### Rule 5: New Admin Account Created

**Splunk SPL (Windows):**
```spl
index=wineventlog EventCode=4720 OR EventCode=4728
| eval event_type=case(EventCode=="4720", "New Account Created", EventCode=="4728", "Added to Admin Group")
| table _time, host, user, event_type, src_user
| sort -_time
```

**MITRE:** T1136.001 | **Severity:** High

---

## Category 4: Lateral Movement

### Rule 6: Unusual Internal RDP Connections

**Sentinel KQL:**
```kql
DeviceNetworkEvents
| where RemotePort == 3389
| where ActionType == "ConnectionSuccess"
| summarize rdp_connections=count(), target_hosts=make_set(DeviceName) by InitiatingProcessAccountName, RemoteIP
| where rdp_connections > 5 or array_length(target_hosts) > 3
| extend Alert = "LATERAL_MOVEMENT_RDP"
```

**MITRE:** T1021.001 | **Severity:** High

---

## Alert Severity Matrix

| Severity | Response Time | Escalation |
|---|---|---|
| Critical | < 15 minutes | Immediate — wake Tier 2 |
| High | < 1 hour | Notify Tier 2 lead |
| Medium | < 4 hours | Document and investigate |
| Low | < 24 hours | Log and monitor |

---

*Rules maintained by: Badi Alosaimi | BADI SOC Platform*
*Last updated: April 2026 | Version: 1.0*
