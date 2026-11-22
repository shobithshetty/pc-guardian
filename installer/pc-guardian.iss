; Inno Setup script for pc-guardian.
; Build:  dotnet publish app/PcGuardian.App -c Release --self-contained false -o publish
;         ISCC.exe installer\pc-guardian.iss /DAppVersion=0.1.0
; Output: installer\Output\pc-guardian-setup-<version>.exe

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{8F3B6C1E-5A2D-4E7B-9C41-2D6A0B7E5F13}
AppName=pc-guardian
AppVersion={#AppVersion}
AppPublisher=pc-guardian contributors
DefaultDirName={autopf}\pc-guardian
DefaultGroupName=pc-guardian
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=Output
OutputBaseFilename=pc-guardian-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Admin is needed once to register the daily scheduled scan.
PrivilegesRequired=admin
UninstallDisplayIcon={app}\PcGuardian.exe
UninstallDisplayName=pc-guardian

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "dailyscan"; Description: "Run a full scan every day at 2:00 AM (read-only)"; GroupDescription: "Protection:"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "Install.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\pc-guardian"; Filename: "{app}\PcGuardian.exe"
Name: "{autodesktop}\pc-guardian"; Filename: "{app}\PcGuardian.exe"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -ModulePath ""{app}\module\PcGuardian\PcGuardian.psd1"""; \
  Flags: runhidden waituntilterminated; Tasks: dailyscan; StatusMsg: "Scheduling the daily scan..."
Filename: "{app}\PcGuardian.exe"; Description: "Open pc-guardian"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -Remove"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveDailyScan"

[Code]
// The app needs the .NET 8 Desktop Runtime. Look for any 8.x version in the registry.
function HasDotNet8Desktop(): Boolean;
var
  Names: TArrayOfString;
  I: Integer;
begin
  Result := False;
  if RegGetValueNames(HKLM64, 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App', Names) then
    for I := 0 to GetArrayLength(Names) - 1 do
      if Pos('8.', Names[I]) = 1 then
      begin
        Result := True;
        Exit;
      end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not HasDotNet8Desktop() then
    Result := MsgBox('pc-guardian needs the Microsoft .NET 8 Desktop Runtime, which was not found.' + #13#10 + #13#10 +
      'Install it from https://dotnet.microsoft.com/download/dotnet/8.0 (".NET Desktop Runtime") and run this setup again.' + #13#10 + #13#10 +
      'Continue installing anyway?', mbConfirmation, MB_YESNO) = IDYES;
end;
