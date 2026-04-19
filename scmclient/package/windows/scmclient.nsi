# =========================================================
# OpenSCM Client Windows Installer
# =========================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"

# --- Build Parameters ---
!ifndef VERSION
    !define VERSION "0.0.0"
!endif
!ifndef BUILD_DIR
    !define BUILD_DIR "/Apps/OpenSCM/build"
!endif

# --- Metadata ---
!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmclient-installer.exe"
!endif

Name "OpenSCM Agent"
InstallDir "$PROGRAMFILES64\OpenSCM\Client"
RequestExecutionLevel admin

# --- Variables ---
Var ServerURL
Var Dialog
Var Label1
Var Text1
Var ExistingURL

# --- Pages ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page custom SetCustom GetCustom
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

# =========================================================
# CUSTOM PAGE: Server URL
# =========================================================
Function SetCustom
    SetRegView 64
    ReadRegStr $ExistingURL HKLM "SOFTWARE\OpenSCM\Client" "ServerURL"

    # If no existing URL use placeholder
    StrCmp $ExistingURL "" 0 +2
        StrCpy $ExistingURL "https://your-openscm-server.com"

    nsDialogs::Create 1018
    Pop $Dialog
    ${NSD_CreateLabel} 0 0u 100% 10u "Enter OpenSCM Server URL (include https:// and port if not 443):"
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

    IfFileExists "$INSTDIR\scmclient-service.exe" 0 +3
        DetailPrint "Stopping OpenSCM Agent service..."
        ExecWait '"$INSTDIR\scmclient-service.exe" stop'

    DetailPrint "Releasing file locks..."
    ExecWait 'taskkill /F /IM scmclient.exe /T'
    Sleep 2000

    # --- 2. DEPLOY BINARIES ---
    SetOutPath "$INSTDIR"

    File "${BUILD_DIR}\target\x86_64-pc-windows-gnu\release\scmclient.exe"
    File "scmclient-service.exe"
    File "scmclient-service.xml"

    # --- 3. PERSISTENCE (KEYS & CONFIG) ---
    # Use COMMONAPPDATA (C:\ProgramData) — accessible by SYSTEM service account
    CreateDirectory "$COMMONAPPDATA\OpenSCM\Client"
    CreateDirectory "$COMMONAPPDATA\OpenSCM\Client\keys"

    # --- 4. REGISTRY UPDATE ---
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerURL" "$ServerURL"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "TenantId" "default"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "Heartbeat" "300"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "KeyPath" "$COMMONAPPDATA\OpenSCM\Client\keys"

    # --- 5. SERVICE RESTART ---
    DetailPrint "Registering and starting OpenSCM Agent service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" install'
    ExecWait '"$INSTDIR\scmclient-service.exe" start'

    # --- 6. UNINSTALLER ---
    WriteUninstaller "$INSTDIR\uninstall.exe"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayName" "OpenSCM Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "Publisher" "OpenSCM"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "URLInfoAbout" "https://openscm.io"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "HelpLink" "https://openscm.io/docs"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoRepair" 1

SectionEnd

# =========================================================
# UNINSTALLATION SECTION
# =========================================================
Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and remove service
    DetailPrint "Removing OpenSCM Agent service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" stop'
    ExecWait '"$INSTDIR\scmclient-service.exe" uninstall'

    # 2. Delete binaries
    Delete "$INSTDIR\scmclient.exe"
    Delete "$INSTDIR\scmclient-service.exe"
    Delete "$INSTDIR\scmclient-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client"
    DeleteRegKey HKLM "Software\OpenSCM\Client"

    # 4. Remove install directory
    RMDir "$INSTDIR"

    # NOTE: $COMMONAPPDATA\OpenSCM\Client\keys is intentionally preserved
    # Keys survive uninstall so reinstall doesn't require re-registration

SectionEnd
