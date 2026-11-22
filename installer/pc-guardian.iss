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
Name: "firstrunsetup"; Description: "Set up virus scanning when pc-guardian first opens (installs ClamAV if needed and downloads about 110 MB, with a progress bar)"; GroupDescription: "Protection:"
Name: "dailyscan"; Description: "Run a full scan every day at 2:00 AM (read-only) and refresh the virus database first"; GroupDescription: "Protection:"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "Install.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\pc-guardian"; Filename: "{app}\PcGuardian.exe"
Name: "{autodesktop}\pc-guardian"; Filename: "{app}\PcGuardian.exe"; Tasks: desktopicon

[Run]
; 0. The data folder is the standard Windows location unless another one is chosen on the "Data folder" page.
;    A custom choice is remembered for the person who started setup (not an elevated account) as the user
;    environment variable PCGUARDIAN_DATA, which the app, the engine and the daily task all read.
;    Choosing the standard location again clears it.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""[Environment]::SetEnvironmentVariable('PCGUARDIAN_DATA', '{code:GetDataDir}', 'User')"""; \
  Flags: runhidden waituntilterminated runasoriginaluser; Check: DataDirIsCustom
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""[Environment]::SetEnvironmentVariable('PCGUARDIAN_DATA', $null, 'User')"""; \
  Flags: runhidden waituntilterminated runasoriginaluser; Check: not DataDirIsCustom
; 1. The big downloads happen inside the app, which shows a real progress bar. Here we only leave a note
;    (in the data folder, as the person who started setup, not an elevated account) saying they agreed to it.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$d = '{code:GetDataDir}'; New-Item -ItemType Directory -Force $d | Out-Null; Set-Content -Path (Join-Path $d 'auto-setup.flag') -Value 'yes'"""; \
  Flags: runhidden waituntilterminated runasoriginaluser; Tasks: firstrunsetup
; 2. Daily scan task.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -ModulePath ""{app}\module\PcGuardian\PcGuardian.psd1"""; \
  Flags: runhidden waituntilterminated; Tasks: dailyscan; StatusMsg: "Scheduling the daily scan..."
; The app is started through cmd so it sees the chosen data folder right away (a running installer does not
; see the environment change it just made).
Filename: "cmd.exe"; \
  Parameters: "/c set ""PCGUARDIAN_DATA={code:GetDataDir}"" && start """" ""{app}\PcGuardian.exe"""; \
  Description: "Open pc-guardian"; Flags: runhidden nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install.ps1"" -Remove"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveDailyScan"

[Code]
var
  DataDirPage: TInputDirWizardPage;

// A page that asks where pc-guardian should keep its data. The default is the standard Windows location.
procedure InitializeWizard();
begin
  DataDirPage := CreateInputDirPage(wpSelectDir, 'Data folder', 'Where should pc-guardian keep its data?',
    'Virus signatures, rules, settings and your safe list are stored here (about 110 MB). ' +
    'The default is the standard Windows location. To keep everything on another drive, choose a folder there.',
    False, '');
  DataDirPage.Add('');
  DataDirPage.Values[0] := ExpandConstant('{localappdata}\PcGuardian');
end;

function GetDataDir(Param: String): String;
begin
  Result := RemoveBackslashUnlessRoot(DataDirPage.Values[0]);
end;

function DataDirIsCustom(): Boolean;
begin
  Result := CompareText(GetDataDir(''), ExpandConstant('{localappdata}\PcGuardian')) <> 0;
end;

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
