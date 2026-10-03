\# 🛡️ Group Policy Object (GPO) \& Security Telemetry Blueprints



This directory defines the Group Policy configurations and endpoint auditing baselines enforced across the `corp.local` Active Directory domain to ensure high-fidelity telemetry collection for Splunk and Shuffle SOAR.



\---



\## 📋 GPO Deployment Architecture



To maintain a centralized and scalable security posture, domain-joined endpoints and domain controllers receive baseline configurations via structured Group Policy Objects (GPOs):

1\. \*\*Sysmon Telemetry Deployment GPO\*\* (Distributes the SwiftOnSecurity configuration).

2\. \*\*Advanced Audit Policy GPO\*\* (Enforces core Windows Security event tracking).

3\. \*\*PowerShell Logging \& Script Block GPO\*\* (Captures execution patterns and obfuscated attack strings).



\---



\## ⚙️ 1. Sysmon Telemetry Distribution (`Sysmon-Logging-Policy.xml`)



Instead of manual installation, enterprise environments utilize GPO scheduled tasks or startup scripts to deploy and update Sysmon configurations cleanly.



\* \*\*Configuration Basis:\*\* Powered by the industry-standard \*\*SwiftOnSecurity Sysmon Configuration\*\* (`Sysmon-Logging-Policy.xml`).

\* \*\*Deployment Mechanism (GPO Scheduled Task):\*\*

&#x20; \* \*\*Target Path:\*\* `C:\\Windows\\Sysmon\\Sysmon64.exe`

&#x20; \* \*\*Configuration Path:\*\* `\\\\corp.local\\sysvol\\corp.local\\Policies\\Sysmon-Logging-Policy.xml`

&#x20; \* \*\*Command Line Action:\*\* 

&#x20;   ```powershell

&#x20;   Sysmon64.exe -i \\\\corp.local\\sysvol\\corp.local\\Policies\\Sysmon-Logging-Policy.xml -accepteula

&#x20;   ```

\* \*\*Core Event Telemetry Captured:\*\*

&#x20; \* \*\*Event ID 1:\*\* Process creation with full command-line arguments and parent process mapping.

&#x20; \* \*\*Event ID 3:\*\* Network connections tracking outbound traffic and beaconing activity.

&#x20; \* \*\*Event ID 10:\*\* Process access targeting sensitive memory spaces (`lsass.exe`).

&#x20; \* \*\*Event ID 12/13:\*\* Registry modifications tracking persistence mechanisms (Run keys, services).



\---



\## 📊 2. Advanced Audit Policy Configuration



Configured under \*\*Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration\*\*:



\* \*\*Account Logon:\*\*

&#x20; \* \*Audit Credential Validation:\* Success and Failure (Captures Kerberos TGS-REQ requests for Kerberoasting detection).

\* \*\*Account Management:\*\*

&#x20; \* \*Audit Security Group Management:\* Success (Tracks changes to high-privilege groups).

\* \*\*Logon/Logoff:\*\*

&#x20; \* \*Audit Logon:\* Success and Failure (Captures Event ID 4624 for Pass-the-Hash and lateral movement sessions).

&#x20; \* \*Audit Special Logon:\* Success (Tracks privileged token elevation).

\* \*\*DS Access:\*\*

&#x20; \* \*Audit Directory Service Access:\* Success and Failure (Captures Event ID 4662 for DCSync replication right abuses).

\* \*\*Object Access:\*\*

&#x20; \* \*Audit Detailed File Share:\* Success and Failure.



\---



\## ⚡ 3. PowerShell Auditing \& Script Block Logging



Configured under \*\*Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell\*\*:



\* \*\*Turn on PowerShell Script Block Logging:\*\* Enabled. Captures full script blocks executed in memory, exposing obfuscated malware payloads, `IEX` calls, and base64-encoded command execution.

\* \*\*Turn on PowerShell Module Logging:\*\* Enabled. Logs pipeline execution details for security analysis modules.

\* \*\*Transcription Logging:\*\* Enabled. Writes a text-based transcript of all user PowerShell session interactions to a secure network share for forensics.

