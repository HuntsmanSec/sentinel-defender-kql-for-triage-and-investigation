# Microsoft Sentinel & Defender KQL Investigation Queries

A curated collection of KQL queries designed to assist security analysts with deep-dive investigations, threat hunting, and incident response using Microsoft Sentinel and Microsoft Defender.

## Contents

- Endpoint Investigation Queries
- Email Investigation Queries
- Identity Threat Detection
- IOC Hunting Queries
- Incident Response Queries

## Platforms Supported

- Microsoft Sentinel
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender for Office 365

## Use Cases

- Phishing investigations
- Malware execution tracking
- Credential theft detection
- Suspicious PowerShell detection
- Lateral movement investigation

## Example Query

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","lsadump")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
