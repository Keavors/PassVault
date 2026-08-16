; -----------------------------------------------------------------------------
; Установщик PassVault (Inno Setup 6)
;
; Собирается из build.py, вручную запускать не нужно:
;
;     python build.py
;
; ПОЧЕМУ ОТДЕЛЬНЫЙ УСТАНОВЩИК, А НЕ САМОУСТАНОВКА
;
; Версии 2.x–3.2 install-ились сами: один и тот же exe под именем
; PassVault-Setup.exe копировал себя в выбранную папку, писал ключ в
; CurrentVersion\Uninstall, создавал ярлыки и запускал записанный файл.
; Windows Defender метил эту последовательность как Behavior:Win32/
; DefenseEvasion.A!ml и удалял файл: неподписанная программа с нулевой
; репутацией, раскладывающая по диску исполняемые файлы, — это портрет
; дроппера, а не установщика.
;
; Разница не в том, ЧТО делается, а в том, КТО делает. Здесь установку ведёт
; загрузчик Inno Setup — тот самый, которым собраны установщики Git for
; Windows, VS Code и тысяч других программ. Он стоит на сотнях миллионов
; машин, и поведенческие модели антивирусов на нём откалиброваны: копирование
; файлов и запись ключа удаления для него — ожидаемое поведение, а не аномалия.
;
; Само приложение при этом остаётся чистым: PassVault.exe не копирует себя,
; не пишет в реестр, не создаёт ярлыков, не запускает внешних программ и не
; удаляет себя. За этим следят тесты в tests/test_setup.py.
;
; ХРАНИЛИЩЕ ПРИ УДАЛЕНИИ НЕ ТРОГАЕТСЯ
;
; Inno удаляет только те файлы, которые сам установил, и сносит папку, только
; если она опустела. Файл vault.pmv установщик не клал — значит, и не удалит.
; Это устройство, а не обещание: обещание было в версии 3.0 и оказалось
; ложным, там удаление выполняло rmdir /s /q по папке программы вместе с
; хранилищем. Ниже к этому добавлено явное предупреждение перед удалением.
; -----------------------------------------------------------------------------

#define AppName        "PassVault"
#define AppExeName     "PassVault.exe"
#define AppPublisher   "PassVault"

; Версию передаёт build.py: /DAppVersion=3.3
#ifndef AppVersion
  #define AppVersion "0.0"
#endif

; Папку со сборкой тоже передаёт build.py: /DSourceDir=...\dist\PassVault
#ifndef SourceDir
  #define SourceDir "..\dist\PassVault"
#endif

#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
; AppId менять нельзя никогда: по нему Windows понимает, что новая версия —
; это обновление прежней, а не вторая программа рядом.
AppId={{8A2F6C41-9D3B-4E7A-B15C-2F0E8D4A6B93}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=PassVault - офлайн-хранилище и генератор паролей
VersionInfoProductName={#AppName}

; Ставим под текущего пользователя. Права администратора не запрашиваются:
; менеджеру паролей нечего делать в системных папках, а лишний запрос UAC от
; неподписанной программы — ещё один повод для подозрений.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

DefaultDirName={code:GetDefaultDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
AllowNoIcons=yes

OutputDir={#OutputDir}
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
SetupIconFile=..\assets\passvault.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}

WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Ставим только на Windows 10 и новее: собранный exe всё равно не запустится
; на более старых, и честнее сказать об этом сразу.
MinVersion=10.0

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Ярлык на рабочем столе"; \
    GroupDescription: "Дополнительно:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Comment: "Офлайн-хранилище и генератор паролей"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Comment: "Офлайн-хранилище и генератор паролей"; Tasks: desktopicon

[Registry]
; Уборка за версиями 2.x–3.2: они писали собственный ключ удаления вручную.
; Если его не снять, в «Установленных программах» останется вторая запись,
; ведущая в никуда. Свой ключ Inno создаёт и удаляет сам.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\PassVault"; \
    Flags: deletekey

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Запустить {#AppName}"; \
    Flags: nowait postinstall skipifsilent

; Никакого [UninstallDelete] здесь нет и быть не должно. Inno удалит ровно то,
; что установил; всё остальное в папке — файлы пользователя.

[Code]

function IsSystemDrive(const Drive: String): Boolean;
begin
  Result := CompareText(Drive, ExpandConstant('{sd}') + '\') = 0;
end;

function LargestNonSystemDrive(): String;
var
  I: Integer;
  Drive: String;
  FreeSpace, TotalSpace: Int64;
  BestFree: Int64;
begin
  Result := '';
  BestFree := 0;
  for I := Ord('D') to Ord('Z') do
  begin
    Drive := Chr(I) + ':\';
    if DirExists(Drive) and not IsSystemDrive(Drive) then
    begin
      if GetSpaceOnDisk64(Drive, FreeSpace, TotalSpace) then
      begin
        if FreeSpace > BestFree then
        begin
          BestFree := FreeSpace;
          Result := Drive;
        end;
      end;
    end;
  end;
end;

function GetDefaultDir(Param: String): String;
var
  Drive: String;
begin
  { Хранилище ложится рядом с программой, поэтому по умолчанию предлагаем
    самый просторный несистемный диск: человек, который держит данные не на
    C:, не должен править путь руками при каждой переустановке. Поле в мастере
    в любом случае можно изменить, а при обновлении Inno подставит прежний
    путь сам (UsePreviousAppDir включён по умолчанию). }
  Drive := LargestNonSystemDrive();
  if Drive <> '' then
    Result := Drive + '{#AppName}'
  else
    Result := ExpandConstant('{autopf}\{#AppName}');
end;

function VaultFilesPresent(const Dir: String): String;
var
  Rec: TFindRec;
  Found: String;
begin
  Found := '';
  if FindFirst(AddBackslash(Dir) + '*.pmv*', Rec) then
  begin
    try
      repeat
        if Rec.Attributes and FILE_ATTRIBUTE_DIRECTORY = 0 then
          Found := Found + '    ' + Rec.Name + #13#10;
      until not FindNext(Rec);
    finally
      FindClose(Rec);
    end;
  end;
  if DirExists(AddBackslash(Dir) + 'vault_backups') then
    Found := Found + '    vault_backups\' + #13#10;
  Result := Found;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Vaults: String;
begin
  { Единственный вопрос, который здесь важен, — что будет с паролями.
    Переносимый режим кладёт vault.pmv рядом с exe, поэтому папка программы и
    папка с данными — часто одна и та же. Удаляются только файлы, которые
    установщик клал; хранилище остаётся. Человек должен знать об этом до
    того, как начнёт искать свои пароли. }
  if CurUninstallStep = usUninstall then
  begin
    Vaults := VaultFilesPresent(ExpandConstant('{app}'));
    if Vaults <> '' then
      MsgBox('В папке программы лежит твоё хранилище:' + #13#10#13#10 +
             Vaults + #13#10 +
             'Оно НЕ будет удалено. Удаляются только файлы программы,' + #13#10 +
             'папка останется вместе с данными.' + #13#10#13#10 +
             ExpandConstant('{app}'),
             mbInformation, MB_OK);
  end;
end;
