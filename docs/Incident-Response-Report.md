# Security Incident Response Report: Active Directory Cyber Attack & Automated SOAR Isolation

**Document Control Reference:** INC-2026-1002  
**Framework:** NIST SP 800-61 Rev. 2 Incident Handling Guide  
**Date of Incident:** October 2, 2026  
**Severity Level:** High / Critical  
**Incident Status:** Closed / Mitigated  
**Lead Investigator:** SOC Engineering & SOAR Response Team  
**Primary Target (DC):** `Windows Server 2022` (`192.168.65.10`) | Domain: `corp.local`  
**Compromised Endpoint:** `win11-workstation` (`192.168.65.151`)  
**Attacker Infrastructure:** Kali Linux (`192.168.65.130`)  

---

## 1. Executive Summary

On October 2, 2026, the Security Operations Center (SOC) detected a high-severity Active Directory compromise campaign targeting the primary Domain Controller (`192.168.65.10`) and workstation endpoint (`192.168.65.151`). Initial access and attack execution originated from an adversarial Linux machine (`192.168.65.130`).

The adversary executed domain reconnaissance, LOLBAS tool downloads, UAC registry hijacking, obfuscated PowerShell script execution, credential harvesting (AS-REP Roasting, Kerberoasting, LSASS memory dumping), Pass-the-Hash lateral movement, and a DCSync attack against the domain controller to replicate Active Directory password hashes.

To mitigate domain compromise, an automated containment workflow was executed via **Shuffle SOAR** (`192.168.65.131`). The SOAR platform issued remote host isolation payloads over **WinRM (Port 5985)** to block all outbound traffic on compromised host `192.168.65.151`, neutralizing attacker persistence and lateral propagation.

---

## 2. Environment Architecture & IP Mapping

| Entity | Role / Hostname | IP Address | OS / Details |
| :--- | :--- | :--- | :--- |
| **Attacker Machine** | `kali-linux` | `192.168.65.130` | Kali Linux (Impacket, Mimikatz, Metasploit) |
| **Domain Controller** | `DC01.corp.local` | `192.168.65.10` | Windows Server 2022 (AD DS, DNS, Kerberos) |
| **Compromised Endpoint**| `win11-workstation` | `192.168.65.151` | Windows 11 Enterprise (Target of Isolation) |
| **SIEM Platform** | `splunk-server` | `192.168.65.10` / Local | Splunk Enterprise (Sysmon & WinEventLog) |
| **SOAR Platform** | `shuffle-vm` | `192.168.65.131` | Shuffle SOAR Container Instance |

---

## 3. Incident Timeline

| Time (UTC) | Phase | Event Description | Affected Systems | Artifact / Event ID |
| :--- | :--- | :--- | :--- | :--- |
| **14:00:12** | Reconnaissance | Execution of domain discovery queries (`whoami`, `net user`, `nltest`) | `192.168.65.130` $\rightarrow$ `192.168.65.151` | Sysmon EventID 1 |
| **14:01:30** | Ingress Tool Transfer | Download of auxiliary payload using LOLBAS utilities (`bitsadmin.exe`) | `192.168.65.151` | Sysmon EventID 1 |
| **14:02:45** | Privilege Escalation | Auto-elevating UAC bypass via `fodhelper.exe` registry key manipulation | `192.168.65.151` | Sysmon EventID 12 / 13 |
| **14:04:00** | Execution / Defense Evasion | Execution of obfuscated PowerShell commands (`IEX`, `FromBase64String`) | `192.168.65.151` | PowerShell EventID 4104 |
| **14:05:10** | Credential Access | AS-REP Roasting against pre-authentication disabled user accounts | `192.168.65.130` $\rightarrow$ `192.168.65.10` | Security EventID 4768 |
| **14:06:33** | Credential Access | Kerberoasting service ticket requests targeting SPNs | `192.168.65.130` $\rightarrow$ `192.168.65.10` | Security EventID 4769 |
| **14:08:15** | Credential Access | LSASS process memory read access (`rundll32.exe`) for hash extraction | `192.168.65.151` | Sysmon EventID 10 |
| **14:10:02** | Lateral Movement | Pass-the-Hash (PtH) NTLM authentication session establishment | `192.168.65.130` $\rightarrow$ `192.168.65.151` | Security EventID 4624 (LogonType 3) |
| **14:11:40** | Persistence / Admin | DCSync Active Directory replication request initiated (`corp\Administrator`) | `192.168.65.130` $\rightarrow$ `192.168.65.10` | Security EventID 4662 |
| **14:12:00** | Detection & Alert | Splunk SIEM triggers aggregated alerts; webhook transmitted to Shuffle | Splunk SIEM Engine | Webhook JSON Payload |
| **14:12:05** | Containment | Shuffle SOAR executes WinRM remote payload; outbound host isolation enforced | `192.168.65.131` $\rightarrow$ `192.168.65.151` | WinRM / NetSecurity Log |

---

## 4. Threat Technical Analysis & MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Target System | Technical Details |
| :--- | :--- | :--- | :--- | :--- |
| **Discovery** | [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner Discovery | `192.168.65.151` | Enumeration of users, groups, and domain trusts via native commands. |
| **Defense Evasion** | [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | Signed Binary Proxy Execution | `192.168.65.151` | Payload retrieval leveraging native LOLBAS tools (`bitsadmin`, `certutil`). |
| **Privilege Escalation** | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | UAC Bypass (`fodhelper`) | `192.168.65.151` | Registry key manipulation for silent elevated execution token generation. |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell Obfuscation | `192.168.65.151` | Execution of encoded script blocks (`EventCode 4104`). |
| **Credential Access** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | `192.168.65.10` (DC) | TGT requests against accounts with pre-auth disabled (`EventCode 4768`). |
| **Credential Access** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | `192.168.65.10` (DC) | RC4/AES TGS ticket requests for service accounts (`EventCode 4769`). |
| **Credential Access** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory Dumping | `192.168.65.151` | Process handle extraction against `lsass.exe` (`Sysmon EventCode 10`). |
| **Lateral Movement** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass-the-Hash (PtH) | `192.168.65.151` | Replayed NTLM hashes for network authentication sessions (`EventCode 4624`). |
| **Credential Access** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | DCSync Attack | `192.168.65.10` (DC) | Directory replication service protocol request (`EventCode 4662`). |

---

## 5. SIEM Detection Queries (Splunk SPL)

### 5.1 Kerberoasting Detection Query (DC Target)
```spl
index="main" EventCode="4769" "0x17"  
| rex "Service Name:\s+(?<ServiceName>\S+)" 
| rex "Client Address:\s+(?<ClientAddress>\S+)" 
| rex "Account Name:\s+(?<TargetUserName>\S+)" 
| stats count values(ServiceName) as Requested_Services by ClientAddress, TargetUserName
```

### 5.2 AS-REP Roasting Detection Query (DC Target)
```spl
index="main" EventCode="4768"
| rex "Pre-Authentication Type:\s+(?<PreAuthType>\S+)"
| rex "Client Address:\s+(?<ClientAddress>\S+)" 
| rex "Account Name:\s+(?<TargetUserName>\S+)" 
| where PreAuthType="0" OR PreAuthType="0x0"
| stats count values(TargetUserName) as Requested_Accounts by ClientAddress
```

### 5.3 Pass-the-Hash Detection Query (DC Target)
```spl
index="main" EventCode="4624" Logon_Type="3" Authentication_Package="NTLM" Account_Name!="*$"
| stats count by ComputerName, Account_Name, Source_Network_Address, Authentication_Package 
| sort - count
```

### 5.4 DCSync Directory Replication Detection Query (DC Target)
```spl
index="main" EventCode="4662" ("1131f6aa" OR "1131f6ad" OR "DS-Replication-Get-Changes")
| rex "Account Name:\s+(?<SubjectUserName>\S+)"
| where NOT match(SubjectUserName, "\$$") AND SubjectUserName!="-"
| stats count by host, SubjectUserName
```

### 5.5 Suspicious Recon Execution Detection Query (Win11 Workstation Target)
```spl
index="main" host="winserver" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 
| spath input=_raw path=Event.System.EventID output=EventID 
| where EventID=1
| rex field=_raw "Name=[\"']Image[\"']>(?<Image>[^<]+)"
| rex field=_raw "Name=[\"']CommandLine[\"']>(?<CommandLine>[^<]+)"
| rex field=_raw "Name=[\"']User[\"']>(?<User>[^<]+)"
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*nltest*"
| table _time, host, User, Image, CommandLine 
| sort - _time
```

### 5.6 LSASS Memory Access Detection Query (Win11 Workstation Target)
```spl
index="main" host="Win11" EventCode=10 TargetImage="*lsass.exe" (GrantedAccess="0x1fffff" OR GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1f0fff")
| table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
```

### 5.7 UAC Bypass via Fodhelper Registry Hijacking Detection Query (Win11 Workstation Target)
```spl
index="main" host="Win11" (EventCode=12 OR EventCode=13) TargetObject="*ms-settings*"
| table _time, Image, TargetObject, Details, EventCode
```

### 5.8 Obfuscated Powershell Script Execution Detection Query (Win11 Workstation Target)
```spl
index="main" host="Win11" EventCode=4104 ("FromBase64String" OR "Invoke-Expression" OR "IEX" OR "DownloadString" OR "AmsiUtils")
| table _time, host, EventCode, Message
```

### 5.9 Ingress tool Transfer via LOLBAS (Bitsadmin/Certutil) Detection Query (Win11 Workstation Target)
```spl
index="main" host="Win11" EventCode=1 (Image="*bitsadmin.exe*" AND (CommandLine="*/transfer*" OR CommandLine="*/addfile*")) OR (Image="*certutil.exe*" AND (CommandLine="*-urlcache*" OR CommandLine="*-split*"))
| table _time, User, Image, CommandLine, ParentCommandLine
```

---

## 6. SOAR Automated Containment & Isolation Verification
```powershell
New-NetFirewallRule -DisplayName "Shuffle-Isolation" -Direction Outbound -Action Block -Enabled True
```

Querying the target endpoint (192.168.65.151) verified the firewall containment rule:
```powershell
Get-NetFirewallRule -DisplayName "Shuffle-Isolation"
```
```text
Name                  : {c8796232-0b95-4ab5-9a7c-2ec8b98c8e73}
DisplayName           : Shuffle-Isolation
Enabled               : True
Direction             : Outbound
Action                : Block
Status                : The rule was parsed successfully from the store.
```
---

## 7. Lessons Learned & Security Recommendations

1. Active Directory Hardening: Disable Kerberos pre-authentication exemptions (DONT_REQ_PREAUTH) across all domain accounts.

2. gMSA Implementation: Migrate domain service accounts to Group Managed Service Accounts (gMSA) with managed 128-character complex passwords.

3. LSASS Protection: Enable Windows Defender Credential Guard to restrict memory-based credential harvesting.

4. DCSync Access Control: Audit and revoke Directory Replication Permissions (DS-Replication-Get-Changes-All) for non-DC domain objects.

---
