!include "MUI2.nsh"
!include "FileFunc.nsh"

!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmclient-installer.exe"
!endif

Name "OpenSCM Client"
InstallDir "$PROGRAMFILES64\OpenSCM\Client"

RequestExecutionLevel admin

; --- Pages ---
!insertmacro MUI_PAGE_DIRECTORY

; Custom Page for Server/Port
Page custom SetCustom GetCustom

!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Var ServerName
Var ServerPort
Var Dialog
Var Label1
Var Label2
Var Text1
Var Text2

Function SetCustom
    nsDialogs::Create 1018
    Pop $Dialog
    ${NSD_CreateLabel} 0 0u 100% 10u "Enter Server Name:"
    Pop $Label1
    ${NSD_CreateText} 0 12u 100% 12u "localhost"
    Pop $Text1
    ${NSD_CreateLabel} 0 30u 100% 10u "Enter Port Number:"
    Pop $Label2
    ${NSD_CreateText} 0 42u 50u 12u "8000"
    Pop $Text2
    nsDialogs::Show
FunctionEnd

Function GetCustom
    ${NSD_GetText} $Text1 $ServerName
    ${NSD_GetText} $Text2 $ServerPort
FunctionEnd

Section "Install"
    # IMPORTANT: Makes $APPDATA point to C:\ProgramData
    SetShellVarContext all
    SetRegView 64
    
    SetOutPath "$INSTDIR"
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmclient.exe"
    
    # Using unique names for the service wrapper to avoid conflicts
    File "scmclient-service.exe"
    File "scmclient-service.xml"
    
    # Create private data areas for the client
    CreateDirectory "$APPDATA\OpenSCM\Client"
    CreateDirectory "$APPDATA\OpenSCM\Client\keys"

    # --- Save to Registry (New Model: Nested under \Client) ---
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerName" "$ServerName"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerPort" "$ServerPort"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ClientID" "0"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "Heartbeat" "300"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "LogLevel" "info"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "KeyPath" "$APPDATA\OpenSCM\Client\keys"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "PubKeyFile" "scmclient.pub"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "PrivKeyFile" "scmclient.key"
    WriteRegStr HKLM "SOFTWARE\OpenSCM\Client" "ServerKeyFile" "scmserver.pub"

    # Register and Start Service using the unique name
    ExecWait '"$INSTDIR\scmclient-service.exe" install'
    ExecWait '"$INSTDIR\scmclient-service.exe" start'

    # Create the Uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # Register in Add/Remove Programs (Unique ID: OpenSCM-Client)
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayName" "OpenSCM Client"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "DisplayVersion" "1.0.1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "Publisher" "OpenSCM"
    
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client" "NoRepair" 1

SectionEnd

# --- The Uninstaller Logic ---
Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    # 1. Stop and Remove the Windows Service
    DetailPrint "Stopping and removing service..."
    ExecWait '"$INSTDIR\scmclient-service.exe" stop'
    ExecWait '"$INSTDIR\scmclient-service.exe" uninstall'

    # 2. Delete the specific client files
    Delete "$INSTDIR\scmclient.exe"
    Delete "$INSTDIR\scmclient-service.exe"
    Delete "$INSTDIR\scmclient-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Remove the Registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM-Client"
    DeleteRegKey HKLM "Software\OpenSCM\Client"

    # 4. Remove the installation directory (only the \Client subfolder)
    RMDir "$INSTDIR"
    # Optional: Wipe client data
    # RMDir /r "$APPDATA\OpenSCM\Client"
SectionEnd
