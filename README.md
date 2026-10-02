# Enterprise Active Directory Attack Simulation, Threat Hunting & SOAR Automated Response Lab

![Framework](https://img.shields.io/badge/Framework-NIST%20SP%20800--61-blue)
![Status](https://img.shields.io/badge/Status-Mitigated%20%2F%20Closed-success)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![SOAR](https://img.shields.io/badge/SOAR-Shuffle-purple)

This repository documents a fully simulated end-to-end active adversary campaign targeting an enterprise Active Directory (AD) environment, followed by real-time automated threat detection via Splunk SIEM and automated incident containment using Shuffle SOAR.

---

## 🏗️ Environment & Network Architecture

```text
  +---------------------------------------------------------------------------------+
  |                                 Lab Architecture                                |
  |                                                                                 |
  |  +------------------------+        +------------------------+                   |
  |  | Active Directory DC    |        | Windows 11 Workstation |                   |
  |  | Windows Server 2022    |        | Target IP:             |                   |
  |  | Domain: corp.local     |        | 192.168.65.151         |                   |
  |  +-----------+------------+        +-----------+------------+                   |
  |              |                                 |                                |
  |              +----------------+----------------+                                |
  |                               |                                                 |
  |                               v (Sysmon / WinEventLog)                          |
  |                    +----------------------+                                     |
  |                    |  Splunk Enterprise   |                                     |
  |                    |  SIEM Ingestion      |                                     |
  |                    +----------+-----------+                                     |
  |                               |                                                 |
  |                               v (Saved Alert / Webhook)                         |
  |                    +----------------------+                                     |
  |                    |   Shuffle SOAR VM    |                                     |
  |                    |   192.168.65.131     |                                     |
  |                    +----------+-----------+                                     |
  |                               |                                                 |
  |                  +------------+------------+                                    |
  |                  |                         |                                    |
  |                  v                         v                                    |
  |       +--------------------+    +--------------------+                          |
  |       | Discord SOC Alert  |    | WinRM (Port 5985)  |                          |
  |       | Interactive Portal |    | Host Isolation     |                          |
  |       +--------------------+    +--------------------+                          |
  +---------------------------------------------------------------------------------+
```
---

## ⚡ Attack Chain Summary

The simulation executed a multi-stage cyber attack mapping to the **MITRE ATT&CK** framework:
1. **Reconnaissance:** Domain discovery queries via `whoami`, `net user`, and `nltest`.
2. **Ingress Tool Transfer:** Payload downloading leveraging LOLBAS utilities (`bitsadmin.exe`).
3. **Privilege Escalation:** Auto-elevating UAC bypass using `fodhelper.exe` registry manipulation.
4. **Defense Evasion / Execution:** Obfuscated PowerShell execution (`IEX`, `FromBase64String`).
5. **Credential Access:** 
   * AS-REP Roasting against pre-authentication disabled user accounts.
   * Kerberoasting targeting service principal names (SPNs).
   * LSASS process memory dumping for credential extraction.
6. **Lateral Movement:** Pass-the-Hash (PtH) NTLM authentication session creation.
7. **Persistence / Admin:** DCSync attack targeting the Domain Controller to extract Active Directory password hashes.

---

## 🤖 Automated SOAR Containment Workflow

1. **Detection:** Splunk SIEM aggregates security telemetry and triggers high-severity custom SPL detection alerts.
2. **Webhook Trigger:** Splunk dispatches an automated JSON webhook payload to **Shuffle SOAR** (`192.168.65.131`).
3. **Remediation Execution:** Shuffle SOAR parses the payload and securely executes a remote WinRM command against the compromised workstation (`192.168.65.151:5985`):
   ```powershell
   New-NetFirewallRule -DisplayName "Shuffle-Isolation" -Direction Outbound -Action Block -Enabled True
   ```
4. **Containment Verification:** Outbound network connections are severed instantly, halting attacker lateral propagation and command-and-control communication.
   ```powershell
   Get-NetFirewallRule -DisplayName "Shuffle-Isolation"
   ```
---

## 📂 Documentation & Resources

📄 Full Incident Response Report: Comprehensive documentation detailing the executive summary, detailed timeline, MITRE ATT&CK matrix, complete custom Splunk SPL detection queries, and containment verification logs.

---

## 🚀 Quick Navigation

Read the Incident Response Report

