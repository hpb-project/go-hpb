CRCCheck on

!define GROUPNAME "Hpb"
!define APPNAME "Ghpb"
!define DESCRIPTION "Official Go implementation of the HPB protocol"
!addplugindir .\

# Require admin rights on NT6+ (When UAC is turned on)
RequestExecutionLevel admin

# Use LZMA compression
SetCompressor /SOLID lzma

!include LogicLib.nsh
!include PathUpdate.nsh
!include EnvVarUpdate.nsh

!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin" # Require admin rights on NT4+
  messageBox mb_iconstop "Administrator rights required!"
  setErrorLevel 740 # ERROR_ELEVATION_REQUIRED
  quit
${EndIf}
!macroend

function .onInit
  # make vars are global for all users since ghpb is installed global
  setShellVarContext all
  !insertmacro VerifyUserIsAdmin

  ${If} ${ARCH} == "amd64"
    StrCpy $InstDir "$PROGRAMFILES64\${APPNAME}"
  ${Else}
    StrCpy $InstDir "$PROGRAMFILES32\${APPNAME}"
  ${Endif}
functionEnd

!include install.nsh
!include uninstall.nsh
