!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"

!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmclient-installer.exe"
!endif

Name "OpenSCM Client"
InstallDir "$PROGRAMFILES64\OpenSCM\Client"

RequestExecutionLevel admin

; --- Variables ---
Var ServerURL
Var Dialog
Var Label1
Var Text1

; --- Pages ---
!insertmacro MUI_PAGE_DIRECTORY

; Custom Page for Server URL
Page custom SetCustom GetCustom

!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function SetCustom
    nsDialogs::Create 1018
    Pop $Dialog
    ${NSD_CreateLabel} 0 0u 100% 10u "Enter OpenSCM Server URL (include https:// and port):"
    Pop $Label1
    ${NSD_CreateText} 0 12u 100% 12u "https://demo.openscm.io:8000"
    Pop $Text1
    nsDialogs::Show
FunctionEnd

Function GetCustom
    ${NSD_GetText} $Text1 $ServerURL
FunctionEnd

Section "Install"
    # --- 1. DETECT AND UNINSTALL PREVIOUS VERSION ---
    # This prevents the "Error opening file for writing" bug
    SetRegView 64
    ReadRegStr $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "UninstallString"
    
    StrCmp $R0 "" +3
        DetailPrint "Removing previous version..."
        # Run the uninstaller silently and wait for it to finish
        # _?=$INSTDIR is vital: it tells the uninstaller not to copy itself to a temp folder
        ExecWait '"$INSTDIR\uninstall.exe" /S _?=$INSTDIR'

    # --- 2. START FRESH INSTALLATION ---
    SetShellVarContext all
    
    SetOutPath "$INSTDIR"
    # Update this path to your actual build artifact location
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmclient.exe"
    File "scmclient-service.exe"
    File "scmclient-service.xml"
    
    # Create private data areas
    CreateDirectory "$APPDATA\OpenSCM\Client"
    CreateDirectory "$APPDATA\OpenSCM\Client\keys"

    # Save to Registry
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerURL" "$ServerURL"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "Heartbeat" "300"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "KeyPath" "$APPDATA\OpenSCM\Client\keys"

    # Register and Start Service
    DetailPrint "Installing OpenSCM Windows Service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" install'
    ExecWait '"$INSTDIR\scmclient-service.exe" start'

    # Create the Uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # Register in Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayName" "OpenSCM Client"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayVersion" "1.1.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "Publisher" "OpenSCM"
    
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoRepair" 1
SectionEnd

Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # Stop and Remove the Windows Service
    DetailPrint "Stopping and removing service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" stop'
    ExecWait '"$INSTDIR\scmclient-service.exe" uninstall'

    # Delete files
    Delete "$INSTDIR\scmclient.exe"
    Delete "$INSTDIR\scmclient-service.exe"
    Delete "$INSTDIR\scmclient-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # Remove Registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client"
    DeleteRegKey HKLM "Software\OpenSCM\Client"

    RMDir "$INSTDIR"
SectionEnd
