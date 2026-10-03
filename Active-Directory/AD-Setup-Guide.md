# 🏢 Active Directory (AD) Lab Architecture & Deployment Guide

This document outlines the end-to-end design, prerequisites, and step-by-step configuration of the Active Directory Domain Controller (`DC01`) for the enterprise-grade SOAR and Threat Hunting Lab.

---

## 📋 1. Lab Environment Specifications & Topology

* **Operating System:** Windows Server 2022 Datacenter Evaluation (Desktop Experience)
* **Hostname:** `DC01`
* **Root Forest / Domain Name:** `corp.local`
* **Static IP Address:** `192.168.65.10`
* **Primary Roles:** Active Directory Domain Services (AD DS), DNS Server, High-Fidelity Telemetry Provider
* **Network Isolation:** Configured on an isolated virtual network segment to safely simulate lateral movement, credential extraction, and automated SOAR containment.

---

## ⚙️ 2. Pre-Installation & System Configuration

Before deploying Active Directory, the base operating system must be properly prepared with static network properties and identity configurations.

1. **Rename the Host:** 
   * Navigate to **Settings > System > About**, and rename the machine to `DC01`. Restart the server.
2. **Configure Static IP Addressing:**
   * Open **Network Connections** (`ncpa.cpl`).
   * Assign a static IPv4 address: `192.168.65.10`, Subnet Mask: `255.255.255.0`, Default Gateway: `192.168.65.2`.
   * Set the **Preferred DNS Server** to `127.0.0.1` (loopback) or its own static IP to ensure internal DNS name resolution loops correctly through the domain controller.

---

## 🚀 3. Installing Active Directory Domain Services (AD DS)

1. Launch **Server Manager** on Windows Server 2022.
2. Click on **Manage** in the top-right navigation menu and select **Add Roles and Features**.
3. On the *Installation Type* screen, select **Role-based or feature-based installation**.
4. On the *Server Selection* screen, verify that `DC01` is selected from the server pool.
5. On the *Server Roles* screen, check the box for **Active Directory Domain Services**. 
   * A pop-up window will appear detailing required management tools and features. Click **Add Features**.
6. Proceed through the subsequent feature screens, click **Next**, and then click **Install** on the confirmation screen.

---

## 🌐 4. Promoting the Server to a Domain Controller

Once the binaries are installed, the server must be promoted to establish the new forest structure:

1. Click the yellow warning/notification flag in Server Manager and select **Promote this server to a domain controller**.
2. In the *Deployment Configuration* wizard:
   * Select the **Add a new forest** radio button.
   * Enter the Root Domain Name: `corp.local`
3. In the *Domain Controller Options* screen:
   * Specify a secure **Directory Services Restore Mode (DSRM)** password for emergency recovery.
   * Leave DNS Server and Global Catalog (GC) checked by default.
4. Accept the default warnings regarding DNS delegation, and verify the NetBIOS domain name (`CORP`).
5. Review the path configurations, run through the prerequisite checks (which should pass with green checks), and click **Install**. 
6. The server will automatically reboot to finalize the promotion.

---

## 👥 5. Target Object & Simulation Account Provisioning

To validate SIEM detection and threat hunting rules, specific vulnerable simulation accounts must be provisioned inside Active Directory:

* **Kerberoasting Account (`sql_service`):**
  * Created to test TGS-REQ ticket requests against vulnerable Service Principal Names (SPNs).
  * Configured with a weak password and mapped an SPN via PowerShell:
    ```powershell
    Set-ADUser sql_service -PrincipalsAllowedToDelegateToAccount $null
    setspn -A MSSQLSvc/sqlserver01.corp.local:1433 sql_service
    ```
* **AS-REP Roasting Account (`labuser`):**
  * Created to test pre-authentication abuse.
  * Explicitly configured with the user flag **"Do not require Kerberos pre-authentication"**:
    ```powershell
    Set-ADUser labuser -DoesNotRequirePreAuth $true
    ```

---

## 🛡️ 6. Telemetry Enforcement & Sysmon Integration

To ensure maximum visibility for Splunk ingestion, high-fidelity endpoint tracing is deployed across the DC and workstations:

* **Configuration Policy:** Utilizing the industry-standard **SwiftOnSecurity Sysmon Configuration** (`Sysmon-Logging-Policy.xml` located under `Active-Directory/GPO-Configs/`).
* **Installation Command:**
  ```powershell
  Sysmon64.exe -i C:\Path\To\Active-Directory\GPO-Configs\Sysmon-Logging-Policy.xml

* **Key Event IDs Monitored:**

Event ID 1: Process Creation (capturing command-line parameters and parent process IDs).

Event ID 3: Network Connections (monitoring outbound communication paths).

Event ID 10: Process Access (detecting LSASS memory read operations during credential dumping simulations).

Event ID 4624 / 4688 / 4768 / 4769: Core Windows Security auditing events ingested for Active Directory attack detection.