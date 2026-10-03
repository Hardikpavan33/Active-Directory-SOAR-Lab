## ============================================================================
## LAB: Active Directory SOAR & Threat Hunting Detection Queries (Splunk SPL)
## ============================================================================

### 5.1 Kerberoasting Detection Query (DC Target)
# Description: Identifies service ticket requests (Event Code 4769) utilizing weak RC4 encryption (0x17), 
# which adversaries abuse to extract service account ticket hashes for offline cracking.
index="main" EventCode="4769" "0x17"  
| rex "Service Name:\s+(?<ServiceName>\S+)" 
| rex "Client Address:\s+(?<ClientAddress>\S+)" 
| rex "Account Name:\s+(?<TargetUserName>\S+)" 
| stats count values(ServiceName) as Requested_Services by ClientAddress, TargetUserName


### 5.2 AS-REP Roasting Detection Query (DC Target)
# Description: Monitors Ticket Granting Ticket (TGT) requests (Event Code 4768) where pre-authentication 
# is disabled (PreAuthType=0), allowing attackers to harvest deployable hashes for user accounts.
index="main" EventCode="4768"
| rex "Pre-Authentication Type:\s+(?<PreAuthType>\S+)"
| rex "Client Address:\s+(?<ClientAddress>\S+)" 
| rex "Account Name:\s+(?<TargetUserName>\S+)" 
| where PreAuthType="0" OR PreAuthType="0x0"
| stats count values(TargetUserName) as Requested_Accounts by ClientAddress


### 5.3 Pass-the-Hash Detection Query (DC Target)
# Description: Tracks network logons (Logon Type 3) authenticated via NTLM from non-computer accounts 
# to detect lateral movement across domain systems using extracted password hashes.
index="main" EventCode="4624" Logon_Type="3" Authentication_Package="NTLM" Account_Name!="*$"
| stats count by ComputerName, Account_Name, Source_Network_Address, Authentication_Package 
| sort - count


### 5.4 DCSync Directory Replication Detection Query (DC Target)
# Description: Detects unauthorized DS-Replication rights being invoked (Event Code 4662) by standard 
# or non-computer accounts, signaling a DCSync attack where an attacker mimics a Domain Controller.
index="main" EventCode="4662" ("1131f6aa" OR "1131f6ad" OR "DS-Replication-Get-Changes")
| rex "Account Name:\s+(?<SubjectUserName>\S+)"
| where NOT match(SubjectUserName, "\$$") AND SubjectUserName!="-"
| stats count by host, SubjectUserName


### 5.5 Suspicious Recon Execution Detection Query (Win11 Workstation Target)
# Description: Filters Sysmon Process Creation telemetry (Event ID 1) to spot internal discovery commands 
# such as user enumeration, network mapping, and environment queries executed during initial staging.
index="main" host="winserver" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 
| spath input=_raw path=Event.System.EventID output=EventID 
| where EventID=1
| rex field=_raw "Name=[\"']Image[\"']>(?<Image>[^<]+)"
| rex field=_raw "Name=[\"']CommandLine[\"']>(?<CommandLine>[^<]+)"
| rex field=_raw "Name=[\"']User[\"']>(?<User>[^<]+)"
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*nltest*"
| table _time, host, User, Image, CommandLine 
| sort - _time


### 5.6 LSASS Memory Access Detection Query (Win11 Workstation Target)
# Description: Leverages Sysmon Event ID 10 to catch suspicious high-privilege access handles targeting 
# the Local Security Authority Subsystem Service (`lsass.exe`) for memory scraping and credential extraction.
index="main" host="Win11" EventCode=10 TargetImage="*lsass.exe" (GrantedAccess="0x1fffff" OR GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1f0fff")
| table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace


### 5.7 UAC Bypass via Fodhelper Registry Hijacking Detection Query (Win11 Workstation Target)
# Description: Flags registry modification events (Sysmon Event ID 12/13) tied to the `ms-settings` handler, 
# exposing attempts to silently elevate privileges via the fodhelper UAC bypass technique.
index="main" host="Win11" (EventCode=12 OR EventCode=13) TargetObject="*ms-settings*"
| table _time, Image, TargetObject, Details, EventCode


### 5.8 Obfuscated Powershell Script Execution Detection Query (Win11 Workstation Target)
# Description: Inspects PowerShell Script Block logs (Event Code 4104) for indicators of obfuscation, 
# string decoding primitives, and memory injection patterns (`FromBase64String`, `IEX`, `AmsiUtils`).
index="main" host="Win11" EventCode=4104 ("FromBase64String" OR "Invoke-Expression" OR "IEX" OR "DownloadString" OR "AmsiUtils")
| table _time, host, EventCode, Message


### 5.9 Ingress tool Transfer via LOLBAS (Bitsadmin/Certutil) Detection Query (Win11 Workstation Target)
# Description: Identifies the misuse of native Living-Off-The-Land Binaries (LOLBAS) like `bitsadmin` 
# and `certutil` via Process Creation (Event ID 1) used by threat actors to download external malicious payloads.
index="main" host="Win11" EventCode=1 (Image="*bitsadmin.exe*" AND (CommandLine="*/transfer*" OR CommandLine="*/addfile*")) OR (Image="*certutil.exe*" AND (CommandLine="*-urlcache*" OR CommandLine="*-split*"))
| table _time, User, Image, CommandLine, ParentCommandLine