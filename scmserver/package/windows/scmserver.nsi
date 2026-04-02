!include "MUI2.nsh"
!include "FileFunc.nsh"

!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmserver-installer.exe"
!endif

Name "OpenSCM Server"
InstallDir "$PROGRAMFILES64\OpenSCM\Server"

RequestExecutionLevel admin

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
    # IMPORTANT: This makes $APPDATA point to C:\ProgramData
    SetShellVarContext all
    SetRegView 64
    
    SetOutPath "$INSTDIR"
    
    # --- Files ---
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmserver.exe"
    File "scmserver-service.exe"
    File "scmserver-service.xml" # Fixed typo (was scmsever)
    
    # --- Directories ---
    CreateDirectory "$APPDATA\OpenSCM\Server"
    CreateDirectory "$APPDATA\OpenSCM\Server\keys"

    # --- Registry Settings ---
    # We keep EVERYTHING inside the \Server subkey to avoid client conflicts
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "Port" "8000"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "DB" "$APPDATA\OpenSCM\Server\scm.db"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "KeyPath" "$APPDATA\OpenSCM\Server\keys"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PubKeyFile" "scmserver.pub"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PrivKeyFile" "scmserver.key"

    # --- Service Management ---
    ExecWait '"$INSTDIR\scmserver-service.exe" install'
    ExecWait '"$INSTDIR\scmserver-service.exe" start'

    # --- Uninstaller Registration ---
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # Use a unique key for the Add/Remove programs list
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayName" "OpenSCM Server"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayVersion" "1.0.1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "Publisher" "OpenSCM"
    
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoRepair" 1
SectionEnd

Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and Remove Service
    DetailPrint "Stopping and removing service..."
    ExecWait '"$INSTDIR\scmserver-service.exe" stop'
    ExecWait '"$INSTDIR\scmserver-service.exe" uninstall'

    # 2. Delete Files
    Delete "$INSTDIR\scmserver.exe"
    Delete "$INSTDIR\scmserver-service.exe" # Fixed typo (was scmserverm)
    Delete "$INSTDIR\scmserver-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Cleanup Registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server"
    DeleteRegKey HKLM "Software\OpenSCM\Server"

    # 4. Remove Directory
    RMDir "$INSTDIR" 
    # Optional: If you want to wipe the DB and keys on uninstall:
    # RMDir /r "$APPDATA\OpenSCM\Server"
SectionEnd
