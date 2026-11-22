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
SetupIconFile=..\app\PcGuardian.App\Assets\pc-guardian.ico
UninstallDisplayIcon={app}\PcGuardian.exe
UninstallDisplayName=pc-guardian

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "installclamav"; Description: "Install ClamAV, the open-source second virus scanner (from the official winget package)"; GroupDescription: "Protection:"
Name: "downloaddata"; Description: "Download protection data now (virus signatures and rules, about 110 MB)"; GroupDescription: "Protection:"
Name: "dailyscan"; Description: "Run a full scan every day at 2:00 AM (read-only) and refresh the virus database first"; GroupDescription: "Protection:"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "Install.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\pc-guardian"; Filename: "{app}\PcGuardian.exe"
Name: "{autodesktop}\pc-guardian"; Filename: "{app}\PcGuardian.exe"; Tasks: desktopicon

[Run]
; 1. ClamAV program (needs administrator, which this installer already has). A failure here is not fatal.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""winget install --id Cisco.ClamAV --exact --silent --accept-package-agreements --accept-source-agreements"""; \
  Flags: runhidden waituntilterminated; Tasks: installclamav; StatusMsg: "Installing ClamAV..."
; 2. Protection data, written to the profile of the person who started setup (not an elevated account).
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Import-Module '{app}\module\PcGuardian\PcGuardian.psd1' -Force; Install-GuardianScanner"""; \
  Flags: runhidden waituntilterminated runasoriginaluser; Tasks: downloaddata; StatusMsg: "Downloading protection data (this can take a few minutes)..."
; 3. Daily scan task.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -ModulePath ""{app}\module\PcGuardian\PcGuardian.psd1"""; \
  Flags: runhidden waituntilterminated; Tasks: dailyscan; StatusMsg: "Scheduling the daily scan..."
Filename: "{app}\PcGuardian.exe"; Description: "Open pc-guardian"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -Remove"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveDailyScan"

[Code]
// The app needs the .NET 8 Desktop Runtime. Some installs do not write the registry key, so the
// runtime folder is the main check and the registry is a fallback.
function HasDotNet8DesktopFolder(): Boolean;
var
  FindRec: TFindRec;
begin
  Result := False;
  if FindFirst(ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App\8.*'), FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
          Result := True;
      until Result or not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function HasDotNet8DesktopRegistry(): Boolean;
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

function HasDotNet8Desktop(): Boolean;
begin
  Result := HasDotNet8DesktopFolder() or HasDotNet8DesktopRegistry();
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not HasDotNet8Desktop() then
    Result := MsgBox('pc-guardian needs the Microsoft .NET 8 Desktop Runtime, which was not found.' + #13#10 + #13#10 +
      'Install it from https://dotnet.microsoft.com/download/dotnet/8.0 (".NET Desktop Runtime") and run this setup again.' + #13#10 + #13#10 +
      'Continue installing anyway?', mbConfirmation, MB_YESNO) = IDYES;
end;
