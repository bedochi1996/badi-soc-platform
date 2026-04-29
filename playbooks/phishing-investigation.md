# Phishing Email Investigation Playbook

## Metadata
- **Playbook ID**: PB-003
- **MITRE ATT&CK**: T1566 (Phishing)
- **Severity**: Medium to High
- **Owner**: SOC Team
- **Last Updated**: 2026-04-29

## Overview
Step-by-step playbook for investigating suspected phishing emails, determining impact, and preventing further compromise.

## Initial Triage (5-10 minutes)

### 1. Collect Email Information
```yaml
Email Subject:
From Address:
Reply-To:
Date/Time Received:
Recipient(s):
Reported By:
Attachments:
URLs in Email:
```

### 2. Quick Assessment
- [ ] Check if attachment is present
- [ ] Check if URLs are present  
- [ ] Check sending domain legitimacy
- [ ] Search for similar emails in mail logs
- [ ] Check if user clicked links or opened attachments

## Investigation Steps

### Phase 1: Email Header Analysis

#### Extract Full Headers
```bash
# View in Outlook
File > Properties > Internet Headers

# View in Gmail
Show Original > Download Original
```

#### Analyze SPF/DKIM/DMARC
```bash
# Check authentication results
grep -i "Authentication-Results" headers.txt
grep -i "Received-SPF" headers.txt
grep -i "DKIM-Signature" headers.txt
```

#### Key Fields to Review:
- **Return-Path**: Actual sending server
- **Received**: Email routing path
- **X-Originating-IP**: Source IP address
- **Message-ID**: Unique identifier

### Phase 2: URL Analysis

#### Extract URLs
```python
import re
import email

# Extract URLs from email body
with open('email.eml', 'r') as f:
    msg = email.message_from_file(f)
    body = msg.get_payload()
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    for url in urls:
        print(url)
```

#### Check URL Reputation
- VirusTotal: `https://www.virustotal.com/`
- URLScan: `https://urlscan.io/`
- Hybrid Analysis: `https://www.hybrid-analysis.com/`

#### Check for URL Obfuscation
```bash
# Decode base64 URLs
echo "aHR0cDovL2V4YW1wbGUuY29t" | base64 -d

# Check for URL shorteners
curl -I https://bit.ly/xxxxx
```

### Phase 3: Attachment Analysis

#### Safe Handling
⚠️ **NEVER open attachments on production systems**

#### File Hash Analysis
```bash
# Generate file hashes
md5sum suspicious_file.doc
sha256sum suspicious_file.doc

# Check on VirusTotal
curl --request POST \
  --url 'https://www.virustotal.com/api/v3/files' \
  --header 'x-apikey: YOUR_API_KEY' \
  --form file=@suspicious_file.doc
```

#### File Metadata
```bash
# Check file type
file suspicious_file.doc

# Extract metadata
exiftool suspicious_file.doc
```

#### Dynamic Analysis (Sandbox)
- Any.run
- Joe Sandbox  
- Cuckoo Sandbox

### Phase 4: Scope Identification

#### Search Email Logs (Exchange/O365)
```powershell
# Exchange
Get-MessageTrackingLog -Sender "phishing@example.com" -Start "04/29/2026 00:00:00" 

# Office 365
Get-MessageTrace -SenderAddress "phishing@example.com" -StartDate "04/29/2026" -EndDate "04/30/2026"
```

#### SIEM Query (Splunk)
```spl
index=email 
    sender="*phishing@example.com*" OR 
    subject="*Urgent: Verify Your Account*"
| stats count by recipient, subject, attachment_name
| where count > 0
```

#### Identify Affected Users
```sql
-- Query email gateway logs
SELECT recipient_email, COUNT(*) as email_count
FROM email_logs
WHERE sender = 'phishing@example.com'
  AND timestamp >= '2026-04-29 00:00:00'
GROUP BY recipient_email;
```

### Phase 5: Impact Assessment

#### Check for Credential Compromise
```spl
# Check for unusual login activity
index=windows EventCode=4624
| where user IN (affected_users_list)
| stats count by user, src_ip, logon_type
| where src_ip NOT IN (known_good_ips)
```

#### Check for Malware Execution
```spl
index=edr process_name="*suspicious*"
| where host IN (affected_hosts)
| stats count by host, process_name, command_line
```

#### Data Exfiltration Check
```spl
index=firewall action=allowed bytes_out>1000000
| where src_ip IN (affected_ips)
| stats sum(bytes_out) by dest_ip, dest_port
```

## Response Actions

### Immediate Containment

#### 1. Block Sender Domain
```powershell
# Exchange
New-TransportRule -Name "Block Phishing Domain" \
  -From "*@phishing-domain.com" \
  -DeleteMessage $true

# O365
New-TransportRule -Name "Block Phishing" \
  -SenderDomainIs "phishing-domain.com" \
  -RejectMessageReasonText "Blocked - Phishing"
```

#### 2. Quarantine Existing Emails
```powershell
# Search and delete
Search-Mailbox -Identity "*" \
  -SearchQuery 'From:"phishing@domain.com"' \
  -DeleteContent -Force
```

#### 3. Block Malicious URLs
```bash
# Add to firewall/proxy blocklist
for url in $(cat malicious_urls.txt); do
    firewall-cmd --add-block=$url
done
```

#### 4. Reset Compromised Credentials
```powershell
# Force password reset
Get-ADUser -Filter {EmailAddress -eq "user@company.com"} | 
  Set-ADUser -ChangePasswordAtLogon $true
```

### User Notification Template

```
SUBJECT: Security Alert - Phishing Email Detected

Dear [User],

We have identified a phishing email that was sent to your mailbox:

Subject: [SUBJECT]
From: [SENDER]
Date: [DATE]

IMPORTANT ACTIONS:
1. Do NOT click any links in this email
2. Do NOT open any attachments
3. Do NOT reply to this email
4. Delete the email immediately

If you already clicked a link or opened an attachment:
1. Change your password immediately
2. Contact IT Security at [CONTACT]
3. Disconnect from the network if instructed

This email has been removed from your mailbox automatically.

Thank you,
IT Security Team
```

## IOC Documentation

### Indicators to Collect
```yaml
Email IOCs:
  - Sender Address:
  - Sending IP:
  - Subject Line:
  - Message-ID:
  - URLs: []
  - Attachment Hashes: []
  - Attachment Names: []

Network IOCs:
  - C2 Domains: []
  - C2 IPs: []
  - File Download URLs: []

File IOCs:
  - MD5: 
  - SHA1:
  - SHA256:
  - File Name:
  - File Type:
```

## Reporting

### Internal Incident Report
```markdown
# Phishing Incident Report

## Executive Summary
- **Date**: [DATE]
- **Emails Sent**: [COUNT]
- **Users Affected**: [COUNT]
- **Users Clicked**: [COUNT]
- **Credentials Compromised**: [COUNT]
- **Malware Deployed**: Yes/No

## Attack Details
- **Phishing Type**: Credential harvesting / Malware delivery
- **Lure**: [Description]
- **Target Department**: [Name]
- **Success Rate**: X%

## Response Actions Taken
1. Blocked sender domain
2. Quarantined emails
3. Reset X user credentials
4. Deployed additional monitoring

## Recommendations
1. Enhanced email filtering
2. User security awareness training
3. MFA enforcement
```

### External Reporting

#### Report to Anti-Phishing Working Group (APWG)
```
Email: reportphishing@apwg.org
Include: Full email with headers
```

#### Report Malicious Domain
```bash
# Report to domain registrar
whois phishing-domain.com | grep -i "abuse"
```

## Prevention Measures

### Technical Controls
- [ ] Enable SPF/DKIM/DMARC
- [ ] Deploy DMARC monitoring
- [ ] Implement email banner for external emails
- [ ] Enable Safe Links (O365)
- [ ] Deploy email sandbox
- [ ] Block executable attachments

### User Training
- [ ] Phishing awareness training
- [ ] Simulated phishing campaigns
- [ ] Report phishing button in email client
- [ ] Monthly security updates

## Success Criteria

✅ All malicious emails quarantined
✅ Sender domain blocked
✅ All affected users notified
✅ Compromised credentials reset
✅ No lateral movement detected
✅ IOCs shared with threat intelligence
✅ Incident documentation completed

## Tools & Resources

### Analysis Tools
- **MXToolbox**: Header analysis
- **VirusTotal**: File/URL scanning  
- **URLScan.io**: URL analysis
- **PhishTool**: Automated analysis
- **Any.run**: Malware sandbox

### Useful Commands
```bash
# Extract email addresses from headers
grep -Eo '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' email_headers.txt

# Decode MIME attachments
ripmime -i email.eml -d output_dir/

# Convert .msg to .eml
msgconvert email.msg
```

## References
- NIST Phishing Guide
- Anti-Phishing Working Group (APWG)
- MITRE ATT&CK: T1566
- CISA Phishing Guidance
