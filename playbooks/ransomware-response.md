# Ransomware Response Playbook

## Metadata
- **Playbook ID**: PB-002
- **MITRE ATT&CK**: T1486 (Data Encrypted for Impact)
- **Severity**: Critical
- **Owner**: SOC Team
- **Last Updated**: 2026-04-29

## Overview
This playbook provides step-by-step guidance for responding to ransomware incidents, including detection, containment, eradication, and recovery procedures aligned with NCA ECC requirements.

## Initial Detection Indicators
- Mass file encryption activity detected
- Unusual file extensions appearing (.locked, .encrypted, .crypt)
- Ransom notes appearing on systems
- Volume Shadow Copy deletion
- Suspicious processes encrypting files
- Network shares becoming inaccessible

## Response Phases

### Phase 1: Initial Assessment (0-15 minutes)

#### Actions:
1. **Confirm the Incident**
   - Verify ransomware indicators
   - Identify patient zero (initial infected system)
   - Document ransom note details
   - Take screenshots of ransom messages

2. **Alert Senior Management**
   - Notify CISO/Security Manager
   - Activate incident response team
   - Consider NCA ECC notification requirements

3. **Preserve Evidence**
   ```bash
   # Capture memory dump
   winpmem.exe memory.raw
   
   # Capture system information
   systeminfo > system_info.txt
   
   # List running processes
   tasklist /v > processes.txt
   ```

### Phase 2: Containment (15-60 minutes)

#### Immediate Containment:
1. **Isolate Affected Systems**
   - Disconnect from network (physical if possible)
   - Do NOT power off systems (preserves memory)
   - Block lateral movement at firewall level

2. **Disable User Accounts**
   ```powershell
   # Disable compromised user accounts
   Disable-ADAccount -Identity <username>
   ```

3. **Network Segmentation**
   - Isolate affected network segments
   - Block SMB/RDP traffic between segments
   - Monitor for additional infection attempts

4. **Identify Scope**
   - Check file servers and network shares
   - Verify backup systems are isolated
   - Identify all affected systems using SIEM

#### SIEM Query Example (Splunk):
```spl
index=windows EventCode=4663 OR EventCode=4660
| where like(file_name, "%.locked") OR like(file_name, "%.encrypted")
| stats count by src_ip, user, file_name
| where count > 100
```

### Phase 3: Eradication (1-4 hours)

#### Actions:
1. **Identify Ransomware Variant**
   - Submit ransom note to ID Ransomware
   - Check file encryption patterns
   - Research decryption availability

2. **Remove Malware**
   - Use EDR tools to quarantine malware
   - Remove persistence mechanisms:
     - Registry run keys
     - Scheduled tasks
     - Services
   - Scan all systems with updated antivirus

3. **Patch Vulnerabilities**
   - Identify initial access vector
   - Apply security patches
   - Fix configuration weaknesses

### Phase 4: Recovery (4-24 hours)

#### Actions:
1. **Restore from Backups**
   - Verify backup integrity
   - Test restore on isolated system first
   - Restore critical systems in priority order
   - Scan restored data before production use

2. **Rebuild Compromised Systems**
   - Reimage infected endpoints
   - Apply latest patches before reconnecting
   - Restore from known-good backups

3. **Reset Credentials**
   ```powershell
   # Force password reset for all users
   Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true
   ```

4. **Monitor for Reinfection**
   - Enhanced logging for 30 days
   - Monitor for C2 communication
   - Check for persistence mechanisms

### Phase 5: Post-Incident (1-7 days)

#### Actions:
1. **Conduct Root Cause Analysis**
   - Document timeline
   - Identify entry point
   - Analyze security control failures

2. **Update Documentation**
   - Incident report
   - Lessons learned
   - Playbook improvements

3. **NCA ECC Reporting**
   - Submit incident report within required timeframe
   - Include impact assessment
   - Document remediation actions

4. **Implement Preventive Measures**
   - Deploy additional security controls
   - User awareness training
   - Backup testing schedule

## Communication Templates

### Internal Announcement
```
SUBJECT: URGENT - Security Incident Response

A ransomware incident has been detected. Please:
1. Save your work immediately
2. Do NOT open any suspicious emails or attachments
3. Report any unusual system behavior to IT Security
4. Do NOT attempt to decrypt files yourself

The IT Security team is actively responding. Updates will be provided every hour.
```

### NCA ECC Notification
```
Incident Type: Ransomware Attack
Detection Time: [TIMESTAMP]
Affected Systems: [COUNT] systems
Data Impact: [Classification level]
Current Status: Contained/Under Investigation
Estimated Recovery: [TIMEFRAME]
```

## Key Contacts

| Role | Contact | Phone |
|------|---------|-------|
| Incident Commander | [Name] | [Number] |
| CISO | [Name] | [Number] |
| IT Manager | [Name] | [Number] |
| Legal | [Name] | [Number] |
| External IR | [Company] | [Number] |

## Critical "Do NOT" List

❌ Do NOT pay ransom without legal/executive approval
❌ Do NOT power off systems (loses memory evidence)
❌ Do NOT attempt to decrypt files without backups
❌ Do NOT restore backups before cleaning malware
❌ Do NOT communicate over compromised channels

## Success Criteria

✅ All malware removed from environment
✅ No reinfection detected for 7 days
✅ Critical systems restored and operational
✅ Root cause identified and addressed
✅ NCA ECC reporting completed
✅ Post-incident review completed

## References

- NIST Ransomware Guide
- CISA Ransomware Response Checklist
- NCA ECC Incident Reporting Guidelines
- MITRE ATT&CK: T1486, T1490, T1491
