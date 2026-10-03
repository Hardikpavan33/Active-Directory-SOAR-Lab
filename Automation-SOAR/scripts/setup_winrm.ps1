# ============================================================================
# Script: Enable and Configure WinRM via PowerShell Cmdlets for SOAR
# ============================================================================

# 1. Enable PowerShell Remoting
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# 2. Configure WinRM Service Settings (Allow Basic auth and unencrypted traffic for lab automation)
Set-Item WSMan:\localhost\Service\Auth\Basic $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true

# 3. Configure Client Trusted Hosts (Allow incoming connections from the SOAR engine)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# 4. Ensure Firewall allows WinRM HTTP traffic (Port 5985)
New-NetFirewallRule -Name "WinRM-HTTP-In-TCP" -DisplayName "Windows Remote Management (HTTP-In)" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985 -ErrorAction SilentlyContinue

# 5. Restart the WinRM Service to apply changes
Restart-Service WinRM

Write-Host "[+] WinRM configuration completed successfully."