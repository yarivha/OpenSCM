# =========================================================
# OpenSCM Client Windows Installer - Safe Upgrade Version
# =========================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"

# --- Metadata ---
!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmclient-installer.exe"
!endif

Name "OpenSCM Client"
InstallDir "$PROGRAMFILES64\OpenSCM\Client"
RequestExecutionLevel admin

# --- Variables ---
Var ServerURL
Var Dialog
Var Label1
Var Text1
Var ExistingURL

# --- Pages ---
!insertmacro MUI_PAGE_DIRECTORY
Page custom SetCustom GetCustom
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

# =========================================================
# CUSTOM PAGE: Handles New Install vs. Upgrade URL
# =========================================================
Function SetCustom
    # Try to read existing URL from Registry to provide as default
    SetRegView 64
    ReadRegStr $ExistingURL HKLM "SOFTWARE\OpenSCM\Client" "ServerURL"
    
    # If no existing URL, use the demo default
    StrCmp $ExistingURL "" 0 +2
        StrCpy $ExistingURL "https://demo.openscm.io:8000"

    nsDialogs::Create 1018
    Pop $Dialog
    ${NSD_CreateLabel} 0 0u 100% 10u "Enter OpenSCM Server URL (include https:// and port):"
    Pop $Label1
    ${NSD_CreateText} 0 12u 100% 12u "$ExistingURL"
    Pop $Text1
    nsDialogs::Show
FunctionEnd

Function GetCustom
    ${NSD_GetText} $Text1 $ServerURL
FunctionEnd

# =========================================================
# INSTALLATION SECTION
# =========================================================
Section "Install"
    SetShellVarContext all
    SetRegView 64

    # --- 1. PRE-INSTALL: STOP SERVICE & RELEASE LOCKS ---
    DetailPrint "Checking for existing client instance..."
    
    # Stop the service if it exists
    IfFileExists "$INSTDIR\scmclient-service.exe" 0 +3
        DetailPrint "Stopping OpenSCM Client service..."
        ExecWait '"$INSTDIR\scmclient-service.exe" stop'

    # The 'Double Tap': Kill the process to release file locks on scmclient.exe
    DetailPrint "Releasing file locks..."
    ExecWait 'taskkill /F /IM scmclient.exe /T'

    # --- 2. DEPLOY BINARIES (OVERWRITE) ---
    SetOutPath "$INSTDIR"
    
    # Replace these paths with your local build paths
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmclient.exe"
    File "scmclient-service.exe"
    File "scmclient-service.xml"

    # --- 3. PERSISTENCE (KEYS & CONFIG) ---
    # CreateDirectory does nothing if the folders already exist.
    # Your hashed .id and .key files inside \keys will NOT be touched.
    CreateDirectory "$APPDATA\OpenSCM\Client"
    CreateDirectory "$APPDATA\OpenSCM\Client\keys"

    # --- 4. REGISTRY UPDATE ---
    # We update the environment but the agent will still look for 
    # its old hashed ID files based on the URL.
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerURL" "$ServerURL"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "Tenant_id" "default"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "Heartbeat" "300"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "KeyPath" "$APPDATA\OpenSCM\Client\keys"

    # --- 5. SERVICE RESTART ---
    DetailPrint "Restarting OpenSCM Client service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" install'
    ExecWait '"$INSTDIR\scmclient-service.exe" start'

    # --- 6. UNINSTALLER ---
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # Add/Remove Programs Entries
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayName" "OpenSCM Client"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayVersion" "0.0.10"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "Publisher" "OpenSCM"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoRepair" 1
SectionEnd

# =========================================================
# UNINSTALLATION SECTION
# =========================================================
Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and Remove Service
    DetailPrint "Removing OpenSCM Client service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" stop'
    ExecWait '"$INSTDIR\scmclient-service.exe" uninstall'

    # 2. Delete Binary Files
    Delete "$INSTDIR\scmclient.exe"
    Delete "$INSTDIR\scmclient-service.exe"
    Delete "$INSTDIR\scmclient-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Wipe Registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client"
    DeleteRegKey HKLM "Software\OpenSCM\Client"

    # 4. Cleanup Directory
    RMDir "$INSTDIR"
    
    # NOTE: We specifically leave $APPDATA\OpenSCM\Client\keys alone.
    # This ensures that if a user uninstalls and reinstalls later, 
    # the server still recognizes this machine.
SectionEnd
