# Security Incident Response Report: Suspicious Activity & Automated Containment

**Report Reference:** INC-2026-1002  
**Date:** October 2, 2026  
**Severity:** High  
**Status:** Closed / Mitigated  
**Lead Investigator:** SOC Team / Lead Security Analyst  

---

## 1. Executive Summary
On October 2, 2026, an automated detection alert flagged unauthorized execution, credential harvesting, and privilege escalation activity originating from host `192.168.65.151` (`win11-workstation`) under the account `corp\Administrator`. 

Following verification in Splunk SIEM, an analyst initiated an automated isolation action via Shuffle SOAR. A remote containment payload executed via WinRM (Port 5985) successfully applied an outbound blocking rule (`Shuffle-Isolation`) on the host, preventing lateral movement and data exfiltration.

---

## 2. Threat Technical Analysis & MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Details |
| :--- | :--- | :--- | :--- |
| **Credential Access** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | TGS ticket requests for SPNs (`EventCode 4769`). |
| **Credential Access** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Targeted accounts with `DONT_REQ_PREAUTH` (`EventCode 4768`). |
| **Lateral Movement** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass-the-Hash (PtH) | NTLM authentication via explicit credentials (`EventCode 4624`, LogonType 9). |
| **Credential Access** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | DCSync | Active Directory replication requests (`EventCode 4662`). |
| **Credential Access** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory Dumping | Process memory read on `lsass.exe` via `rundll32.exe` (`EventCode 10`). |
| **Privilege Escalation**| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | UAC Bypass | Auto-elevating registry hijacking (`fodhelper.exe`). |
| **Discovery** | [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner Discovery | Reconnaissance commands executed. |

---

## 3. Containment Verification

```powershell
New-NetFirewallRule -DisplayName "Shuffle-Isolation" -Direction Outbound -Action Block -Enabled True

Querying the endpoint confirmed the rule was successfully parsed and applied:

```text
Name                  : {c8796232-0b95-4ab5-9a7c-2ec8b98c8e73}
DisplayName           : Shuffle-Isolation
Enabled               : True
Direction             : Outbound
Action                : Block
Status                : The rule was parsed successfully from the store.
