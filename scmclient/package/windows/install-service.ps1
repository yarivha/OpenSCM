$ServiceName = "SCMClient"
$BinaryPath = "`"$env:ProgramFiles\OpenSCM\scmclient.exe`""

Write-Host "Registering Service: $ServiceName"

# Create the service entry in SCM
# Using sc.exe is often more reliable in installer contexts than New-Service
sc.exe create $ServiceName binPath= $BinaryPath start= auto

# Set description
sc.exe description $ServiceName "OpenSCM Client"

# Start the service immediately
Start-Service -Name $ServiceName
