!include "MUI2.nsh"
!include "FileFunc.nsh"

!ifdef INSTALLER_NAME
    OutFile "${INSTALLER_NAME}"
!else
    OutFile "scmclient-installer.exe"
!endif

Name "OpenSCM Client"
InstallDir "$PROGRAMFILES64\OpenSCM"

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
    SetOutPath "$INSTDIR"
    File "/Apps/OpenSCM/build/target/x86_64-pc-windows-gnu/release/scmclient.exe"
    File "scm-service.exe"
    File "scm-service.xml"
    
    ; Save to Registry
    WriteRegStr HKLM "SOFTWARE\OpenSCM" "ServerName" "$ServerName"
    WriteRegStr HKLM "SOFTWARE\OpenSCM" "ServerPort" "$ServerPort"
    WriteRegStr HKLM "SOFTWARE\OpenSCM" "Heartbeat" "300"
    WriteRegStr HKLM "SOFTWARE\OpenSCM" "LogLevel" "info"

    ; Register and Start Service
    ExecWait '"$INSTDIR\scm-service.exe" install'
    ExecWait '"$INSTDIR\scm-service.exe" start'


    # 1. Create the Uninstaller executable
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # 2. Register the app in Windows "Add/Remove Programs"
    # The ID "OpenSCM" should be unique
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "DisplayName" "OpenSCM Client"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "DisplayVersion" "1.0.1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "Publisher" "OpenSCM"
    
    # Optional: Add an icon (if you have one)
    # WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "DisplayIcon" "$INSTDIR\scmclient.exe"
    
    # These let Windows calculate the size
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM" "NoRepair" 1

SectionEnd

# --- The Uninstaller Logic ---
Section "Uninstall"
    # 1. Stop and Remove the Windows Service
    # We do this first so the files aren't "in use" when we try to delete them
    DetailPrint "Stopping and removing service..."
    ExecWait '"$INSTDIR\scm-service.exe" stop'
    ExecWait '"$INSTDIR\scm-service.exe" uninstall'

    # 2. Delete the files
    Delete "$INSTDIR\scmclient.exe"
    Delete "$INSTDIR\scm-service.exe"
    Delete "$INSTDIR\scm-service.xml"
    Delete "$INSTDIR\uninstall.exe"

    # 3. Remove the Registry keys (Add/Remove Programs & App Settings)
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSCM"
    DeleteRegKey HKLM "Software\OpenSCM"

    # 4. Remove the installation directory
    RMDir "$INSTDIR"
SectionEnd
