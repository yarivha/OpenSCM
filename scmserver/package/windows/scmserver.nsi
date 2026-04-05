# =========================================================
# OpenSCM Server Windows Installer
# =========================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"

# --- Basic Metadata ---
!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmserver-installer.exe"
!endif

Name "OpenSCM Server"
InstallDir "$PROGRAMFILES64\OpenSCM\Server"
RequestExecutionLevel admin

# --- Interface Settings ---
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

# =========================================================
# INSTALLATION SECTION
# =========================================================
Section "Install"
    # Set context to all users (C:\ProgramData) and 64-bit Registry
    SetShellVarContext all
    SetRegView 64

    # --- 1. PRE-INSTALL: HANDLE UPGRADES & FILE LOCKS ---
    DetailPrint "Checking for existing server instance..."
    
    # Check if the service wrapper exists. If so, stop it.
    IfFileExists "$INSTDIR\scmserver-service.exe" 0 +3
        DetailPrint "Stopping OpenSCM Server service..."
        ExecWait '"$INSTDIR\scmserver-service.exe" stop'

    # The 'Double Tap': Force kill the process to ensure file locks are released.
    # This prevents the "Error opening file for writing" bug.
    DetailPrint "Ensuring process is terminated..."
    ExecWait 'taskkill /F /IM scmserver.exe /T'

    # --- 2. DEPLOY BINARIES ---
    SetOutPath "$INSTDIR"
    
    # Binary artifacts from your build folder
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmserver.exe"
    File "scmserver-service.exe"
    File "scmserver-service.xml"

    # --- 3. DATA PERSISTENCE ---
    # These directories survive upgrades. 
    # NOTE: We do NOT use 'File' for scm.db to ensure your data stays intact.
    CreateDirectory "$APPDATA\OpenSCM\Server"
    CreateDirectory "$APPDATA\OpenSCM\Server\keys"

    # --- 4. REGISTRY CONFIGURATION ---
    # Updates the server environment settings (does not touch the DB content)
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "Port" "8000"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "DB" "$APPDATA\OpenSCM\Server\scm.db"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "KeyPath" "$APPDATA\OpenSCM\Server\keys"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PubKeyFile" "scmserver.pub"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PrivKeyFile" "scmserver.key"

    # --- 5. SERVICE INITIALIZATION ---
    DetailPrint "Registering and starting OpenSCM Server service..."
    ExecWait '"$INSTDIR\scmserver-service.exe" install'
    ExecWait '"$INSTDIR\scmserver-service.exe" start'

    # --- 6. UNINSTALLER REGISTRATION ---
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # Add to Windows Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayName" "OpenSCM Server"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayVersion" "1.1.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "Publisher" "OpenSCM"
    
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoRepair" 1
SectionEnd

# =========================================================
# UNINSTALLATION SECTION
# =========================================================
Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and Wipe the Service
    DetailPrint "Removing OpenSCM Server service..."
    ExecWait '"$INSTDIR\scmserver-service.exe" stop'
    ExecWait '"$INSTDIR\scmserver-service.exe" uninstall'

    # 2. Delete Binary Files
    Delete "$INSTDIR\scmserver.exe"
    Delete "$INSTDIR\scmserver-service.exe"
    Delete "$INSTDIR\scmserver-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Wipe Registry (But leave the data folder alone)
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server"
    DeleteRegKey HKLM "Software\OpenSCM\Server"

    # 4. Cleanup Directory
    RMDir "$INSTDIR" 
    
    # CRITICAL: We do NOT delete $APPDATA\OpenSCM\Server here.
    # This keeps scm.db and your keys safe even if the server is uninstalled.
SectionEnd
