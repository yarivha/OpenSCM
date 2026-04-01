$ServiceName = "SCMClient"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and deleting $ServiceName..."
    
    # Force stop the service
    Stop-Service -Name $ServiceName -Force
    
    # Remove from Windows Service Control Manager
    sc.exe delete $ServiceName
}
