# =========================================================
# OpenSCM Server Windows Installer
# =========================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"

# --- Build Parameters ---
!ifndef VERSION
    !define VERSION "0.0.0"
!endif
!ifndef BUILD_DIR
    !define BUILD_DIR "/Apps/OpenSCM/build"
!endif

# --- Basic Metadata ---
!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmserver-installer.exe"
!endif

Name "OpenSCM Server"
InstallDir "$PROGRAMFILES64\OpenSCM\Server"
RequestExecutionLevel admin

# --- Variables ---
Var ProgramData


# --- Interface Settings ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

# =========================================================
# INSTALLATION SECTION
# =========================================================
Section "Install"
    ReadEnvStr $ProgramData "PROGRAMDATA"
    SetShellVarContext all
    SetRegView 64


    # --- 1. PRE-INSTALL: STOP SERVICE & RELEASE LOCKS ---
    DetailPrint "Checking for existing server instance..."

    # Graceful stop via Windows service manager first
    DetailPrint "Stopping OpenSCM Server service..."
    ExecWait 'sc stop OpenSCMServer'
    Sleep 2000

    # Stop via service wrapper if exists
    IfFileExists "$INSTDIR\scmserver-service.exe" 0 +3
       DetailPrint "Stopping service wrapper..."
       ExecWait '"$INSTDIR\scmserver-service.exe" stop'

    # Force kill any remaining process and wait for OS to release file locks
    DetailPrint "Releasing file locks..."
    ExecWait 'taskkill /F /IM scmserver.exe /T'
    Sleep 3000



    # --- 1. PRE-INSTALL: HANDLE UPGRADES & FILE LOCKS ---
    DetailPrint "Checking for existing server instance..."

    IfFileExists "$INSTDIR\scmserver-service.exe" 0 +3
        DetailPrint "Stopping OpenSCM Server service..."
        ExecWait '"$INSTDIR\scmserver-service.exe" stop'

    DetailPrint "Ensuring process is terminated..."
    ExecWait 'taskkill /F /IM scmserver.exe /T'
    Sleep 2000

    # --- 2. DEPLOY BINARIES ---
    SetOutPath "$INSTDIR"

    File "${BUILD_DIR}\target\x86_64-pc-windows-gnu\release\scmserver.exe"
    File "scmserver-service.exe"
    File "scmserver-service.xml"

    # --- 3. DATA PERSISTENCE ---
    # Use COMMONAPPDATA (C:\ProgramData) — accessible by SYSTEM service account
    CreateDirectory "$ProgramData\OpenSCM\Server"
    CreateDirectory "$ProgramData\OpenSCM\Server\keys"

    # --- 4. REGISTRY CONFIGURATION ---
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "Port" "8000"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "DB" "$ProgramData\OpenSCM\Server\scm.db"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "KeyPath" "$ProgramData\OpenSCM\Server\keys"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PubKeyFile" "scmserver.pub"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Server" "PrivKeyFile" "scmserver.key"

    # --- 5. SERVICE INITIALIZATION ---
    DetailPrint "Registering and starting OpenSCM Server service..."
    ExecWait '"$INSTDIR\scmserver-service.exe" install'
    ExecWait '"$INSTDIR\scmserver-service.exe" start'

    # --- 6. UNINSTALLER REGISTRATION ---
    WriteUninstaller "$INSTDIR\uninstall.exe"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayName" "OpenSCM Server"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "Publisher" "OpenSCM"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "URLInfoAbout" "https://openscm.io"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "HelpLink" "https://openscm.io/docs"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server" "NoRepair" 1

SectionEnd

# =========================================================
# UNINSTALLATION SECTION
# =========================================================
Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and remove service
    DetailPrint "Removing OpenSCM Server service..."
    ExecWait '"$INSTDIR\scmserver-service.exe" stop'
    ExecWait '"$INSTDIR\scmserver-service.exe" uninstall'

    # 2. Delete binaries
    Delete "$INSTDIR\scmserver.exe"
    Delete "$INSTDIR\scmserver-service.exe"
    Delete "$INSTDIR\scmserver-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Server"
    DeleteRegKey HKLM "Software\OpenSCM\Server"

    # 4. Remove install directory
    RMDir "$INSTDIR"

    # NOTE: $COMMONAPPDATA\OpenSCM\Server is intentionally preserved
    # Database and keys survive uninstall for safe reinstallation

SectionEnd
