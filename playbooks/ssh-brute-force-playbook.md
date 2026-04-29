# Playbook: SSH Brute Force Attack Response

**Playbook ID:** PB-001
**Category:** Credential Attack
**Severity:** High
**MITRE ATT&CK:** T1110.001
**Last Updated:** April 2026

---

## Overview

This playbook provides step-by-step guidance for SOC analysts responding to SSH brute force attacks. It covers detection, triage, containment, and remediation.

---

## Step 1: Detection & Initial Triage (0–5 min)

```
CHECKLIST:
[ ] Verify SIEM alert is not a false positive
[ ] Check source IP reputation (AbuseIPDB, VirusTotal, Shodan)
[ ] Determine attack volume: How many failed attempts?
[ ] Identify target system: Is it internal or internet-facing?
[ ] Check if attacker IP has been seen before in logs
[ ] Determine if any login was SUCCESSFUL
```

**SIEM Query (Splunk):**
```spl
index=linux_auth sourcetype=syslog "Failed password"
| stats count by src_ip, user
| where count > 100
| sort -count
```

**SIEM Query (Sentinel KQL):**
```kql
Syslog
| where SyslogMessage contains "Failed password for"
| parse SyslogMessage with * "from " src_ip " port" *
| summarize count() by src_ip, bin(TimeGenerated, 1m)
| where count_ > 50
```

---

## Step 2: Containment (5–15 min)

```
IF successful login detected:
  [ ] Immediately isolate affected host from network
  [ ] Terminate active SSH session: kill -9 <pid>
  [ ] Force logout: pkill -u <username>

ALWAYS:
  [ ] Block source IP at perimeter firewall
  [ ] Block IP at host-level (iptables/ufw)
  [ ] Document time of block action
```

**Block IP at firewall (Linux):**
```bash
# UFW
sudo ufw deny from <ATTACKER_IP> to any

# iptables
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP

# Verify
sudo iptables -L -n | grep <ATTACKER_IP>
```

---

## Step 3: Investigation (15–45 min)

```
[ ] Review /var/log/auth.log for full timeline
[ ] Check for successful logins: grep "Accepted" /var/log/auth.log
[ ] Identify compromised accounts
[ ] Check if attacker ran any commands (bash_history, /tmp)
[ ] Check for persistence mechanisms (crontab, .ssh/authorized_keys)
[ ] Run threat intel on source IP
[ ] Document all IOCs
```

**Key Linux Commands:**
```bash
# Show all failed logins from specific IP
grep "Failed password" /var/log/auth.log | grep <ATTACKER_IP>

# Show successful logins
grep "Accepted" /var/log/auth.log

# Check authorized_keys for backdoors
cat ~/.ssh/authorized_keys

# Check crontabs for persistence
crontab -l
cat /etc/cron*

# Check running processes
ps aux | grep -v grep

# Check open network connections
ss -tnp
```

---

## Step 4: Eradication & Remediation

```
[ ] Reset password for any compromised accounts
[ ] Enforce strong password policy (min 16 chars, complexity)
[ ] Enable MFA for SSH (Google Authenticator or hardware key)
[ ] Implement fail2ban or equivalent
[ ] Implement account lockout after 5 failed attempts
[ ] Consider moving SSH to non-standard port (security through obscurity)
[ ] Implement SSH key-based authentication only
[ ] Review and clean .ssh/authorized_keys
```

**Install and configure fail2ban:**
```bash
sudo apt install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit jail.local
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 3600

sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## Step 5: Post-Incident Actions

```
[ ] Write formal incident report (use IR template)
[ ] Update firewall block list with attacker IP
[ ] Submit IOCs to threat intel platform
[ ] Update SIEM detection rules if needed
[ ] Notify management if high-value system targeted
[ ] Schedule lessons-learned meeting
[ ] Check for similar attacks in historical logs
```

---

## Escalation Criteria

Escalate to Tier 2 / Incident Commander if:
- Successful authentication was achieved
- Attacker gained root/admin access
- Lateral movement detected
- Attack targets critical infrastructure (SCADA, AD)
- More than 10 hosts targeted simultaneously

---

## NCA ECC Relevance

- **ECC-2-1:** Access Control — enforce least privilege
- **ECC-2-3:** Authentication — MFA requirement
- **ECC-3-1:** Logging & Monitoring — ensure SSH logs are captured

---

*Playbook authored by: Badi Alosaimi | SOC Analyst*
*Status: Active | Version: 1.0*
