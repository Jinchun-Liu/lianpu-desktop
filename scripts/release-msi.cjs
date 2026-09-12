'use strict';
// Independently authored from Microsoft Windows Installer table documentation.
// Windows' own makecab and COM API are development tools, never bundled runtimes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { walk, sha } = require('./licenses.cjs');
const UPGRADE_CODE = '{9B0F315E-5660-4A1A-81E9-47E22F57C2B1}';
const guid = () => '{' + crypto.randomUUID().toUpperCase() + '}';
function stableGuid(value) {
  const bytes = crypto.createHash('sha256').update('lianpu-msi-component-v1:' + value).digest().subarray(0,16);
  bytes[6] = (bytes[6] & 15) | 80; bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString('hex').toUpperCase();
  return `{${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}}`;
}
function table(name, columns, keys, rows) {
  return [name, columns.map(([col,type]) => '`' + col + '` ' + type).join(', ') + ' PRIMARY KEY ' + keys.map(k => '`' + k + '`').join(', '), columns.map(c => c[0]), rows];
}
const id = 'CHAR(72) NOT NULL'; const text = 'CHAR(255)'; const localized = 'CHAR(255) LOCALIZABLE';
function database({ stage, outfile, version, build, productName = '联铺', installFolder = 'Lianpu', upgradeCode = UPGRADE_CODE, launchFile = 'Lianpu.exe', uninstallCleanup = launchFile === 'Lianpu.exe', startupItemName = 'Lianpu' }) {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,5}$/.test(version)) throw new Error('MSI 需要三段数字版本');
  const productCode = guid(), packageCode = guid();
  const dirs = [['TARGETDIR',null,'SourceDir'],['LocalAppDataFolder','TARGETDIR','.'],['Programs','LocalAppDataFolder','Programs'],['INSTALLDIR','Programs',installFolder],['ProgramMenuFolder','TARGETDIR','.'],['AppMenu','ProgramMenuFolder',installFolder],['DesktopFolder','TARGETDIR','.']];
  const dirIds = new Map([['','INSTALLDIR']]);
  function directory(rel) {
    if (dirIds.has(rel)) return dirIds.get(rel);
    const parent = path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel);
    const parentId = directory(parent); const key = 'D' + sha(Buffer.from(rel)).slice(0,24);
    dirs.push([key,parentId,`D${String(dirs.length).padStart(7,'0')}|${path.posix.basename(rel)}`]); dirIds.set(rel,key); return key;
  }
  const registry = [], files = [], components = [], featureComponents = [];
  const payload = walk(stage).sort().map((source,index) => {
    const rel = path.relative(stage,source).replaceAll('\\','/'); const fileId = `F${String(index+1).padStart(7,'0')}`;
    const component = 'C' + fileId; const registryId = 'R' + fileId; const parent = path.posix.dirname(rel);
    const dir = directory(parent === '.' ? '' : parent);
    // HKCU registry key paths make per-user components explicit. No business data is an MSI component.
    components.push([component,stableGuid(upgradeCode + ':' + rel),dir,260,null,registryId]);
    registry.push([registryId,1,`Software\\${installFolder}\\InstallerFiles`,sha(Buffer.from(rel)).slice(0,24),build,component]);
    featureComponents.push(['Application',component]);
    files.push([fileId,component,`${fileId}|${path.basename(source)}`,fs.statSync(source).size,null,null,16896,index+1]);
    return {source,rel,fileId,component};
  });
  const launch = payload.find(f => f.rel === launchFile); if (!launch) throw new Error('MSI 主程序缺失：' + launchFile);
  components.push(['Menu',stableGuid(upgradeCode + ':menu'),'AppMenu',260,null,'MenuKey']);
  components.push(['Desktop',stableGuid(upgradeCode + ':desktop'),'DesktopFolder',260,'CREATE_DESKTOP = 1','DesktopKey']);
  featureComponents.push(['Application','Menu'],['Application','Desktop']);
  registry.push(['MenuKey',1,`Software\\${installFolder}\\Installer`,'StartMenu','#1','Menu'],['DesktopKey',1,`Software\\${installFolder}\\Installer`,'Desktop','#1','Desktop']);
  // Directory properties are not automatically restored during maintenance.
  // Persist only the program location; never add user data as an MSI component.
  registry.push(['InstallLocation',1,`Software\\${installFolder}\\Installer`,'InstallLocation','[INSTALLDIR]','Menu']);
  const sequences = [
    ['FindRelatedProducts',null,25],['ClearSavedInstallDirectory',null,39],['ClearExistingStartupValue',null,40],['AppSearch',null,50],['RestoreInstallLocation','SavedInstallDirectory AND (Installed OR NOT INSTALLDIR)',60],['LaunchConditions',null,100],['CostInitialize',null,800],['FileCost',null,900],['CostFinalize',null,1000],['MigrateFeatureStates',null,1200],['SetInstallLocation',null,1300],
    ['InstallValidate',null,1400],['InstallInitialize',null,1500],['ProcessComponents',null,1600],['UnpublishFeatures',null,1800],
    ['RemoveShortcuts',null,3200],['RemoveRegistryValues',null,3300],['RemoveFiles',null,3500],['RemoveFolders',null,3600],['CreateFolders',null,3700],['InstallFiles',null,4000],
    ['CreateShortcuts',null,4500],['WriteRegistryValues',null,5000],['RegisterUser',null,6000],['RegisterProduct',null,6100],['PublishFeatures',null,6300],['PublishProduct',null,6400],
    // Keep old registration until new files are installed, within one rollback
    // transaction. Component GUIDs remain stable by product family + relative path.
    ['InstallExecute',null,6500],['RemoveExistingProducts','OLDPRODUCTS',6501],['InstallFinalize',null,6600]
  ];
  const customActions = [['SetInstallLocation',51,'ARPINSTALLLOCATION','[INSTALLDIR]'],['ClearSavedInstallDirectory',51,'SavedInstallDirectory',''],['ClearExistingStartupValue',51,'ExistingStartupValue',''],['RestoreInstallLocation',51,'INSTALLDIR','[SavedInstallDirectory]']];
  // Immediate actions set session properties only; native registry removal is
  // transacted by Windows Installer. Exact quoted executable equality excludes
  // extra arguments and different targets. Mixed-case properties are private.
  if (uninstallCleanup) {
    const own = 'Installed AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE AND SavedInstallDirectory AND ExistingStartupValue ~= ExpectedStartupValue';
    const privateKey = `Software\\${installFolder}\\Installer\\StartupCleanup`;
    const privateApprovalKey = `Software\\${installFolder}\\Installer\\StartupApprovalCleanup`;
    registry.push(['StartupCleanup',1,'[StartupCleanupKey]',startupItemName,'cleanup-marker','Menu'],['StartupApprovalCleanup',1,'[StartupApprovalCleanupKey]',startupItemName,'cleanup-marker','Menu'],['PrivateStartupMarker',1,privateKey,startupItemName,'cleanup-marker','Menu'],['PrivateStartupApprovalMarker',1,privateApprovalKey,startupItemName,'cleanup-marker','Menu']);
    customActions.push(['ResetStartupCleanupKey',51,'StartupCleanupKey',privateKey],['ResetStartupApprovalCleanupKey',51,'StartupApprovalCleanupKey',privateApprovalKey],['SetExpectedStartupValue',51,'ExpectedStartupValue',`"[#${launch.fileId}]"`],['SelectOwnStartupRemoval',51,'StartupCleanupKey','Software\\Microsoft\\Windows\\CurrentVersion\\Run'],['SelectOwnStartupApprovalRemoval',51,'StartupApprovalCleanupKey','Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run']);
    sequences.push(['ResetStartupCleanupKey',null,3240],['ResetStartupApprovalCleanupKey',null,3241],['SetExpectedStartupValue',null,3250],['SelectOwnStartupRemoval',own,3260],['SelectOwnStartupApprovalRemoval',own,3261]);
  }
  const tables = [
    table('Property',[['Property',id],['Value','CHAR(0) LOCALIZABLE']],['Property'],[
      ['ProductCode',productCode],['ProductName',productName],['ProductVersion',version],['Manufacturer','Lianpu Development'],['ProductLanguage','2052'],['UpgradeCode',upgradeCode],
      // Every packaged file is application-owned. Replace the complete matched
      // executable/ASAR set, including same-version repair or replacement builds.
      ['ALLUSERS','2'],['MSIINSTALLPERUSER','1'],['INSTALLLEVEL','1'],['REINSTALLMODE','amus'],['ARPNOMODIFY','1'],['ARPNOREPAIR','1'],['CREATE_DESKTOP','1'],
      ['SecureCustomProperties','OLDPRODUCTS;NEWERPRODUCTS;INSTALLDIR;CREATE_DESKTOP'],['DefaultUIFont','Body'],['MsiLogging','voicewarmupx'],['MSIRESTARTMANAGERCONTROL','DisableShutdown'],
      ['ARPCOMMENTS','仅为当前用户安装。升级及卸载保留个人业务资料。开发验证包，尚未代码签名。']
    ]),
    table('Directory',[['Directory',id],['Directory_Parent','CHAR(72)'],['DefaultDir',localized.replace(' LOCALIZABLE',' NOT NULL LOCALIZABLE')]],['Directory'],dirs),
    table('Component',[['Component',id],['ComponentId','CHAR(38)'],['Directory_',id],['Attributes','SHORT NOT NULL'],['Condition',text],['KeyPath','CHAR(72)']],['Component'],components),
    table('Feature',[['Feature','CHAR(38) NOT NULL'],['Feature_Parent','CHAR(38)'],['Title','CHAR(64) LOCALIZABLE'],['Description',localized],['Display','SHORT'],['Level','SHORT NOT NULL'],['Directory_','CHAR(72)'],['Attributes','SHORT NOT NULL']],['Feature'],[['Application',null,productName,'应用程序与随包运行组件',1,1,'INSTALLDIR',0]]),
    table('FeatureComponents',[['Feature_',id],['Component_',id]],['Feature_','Component_'],featureComponents),
    table('File',[['File',id],['Component_',id],['FileName','CHAR(255) NOT NULL LOCALIZABLE'],['FileSize','LONG NOT NULL'],['Version','CHAR(72)'],['Language','CHAR(20)'],['Attributes','SHORT'],['Sequence','LONG NOT NULL']],['File'],files),
    table('Media',[['DiskId','SHORT NOT NULL'],['LastSequence','LONG NOT NULL'],['DiskPrompt','CHAR(64) LOCALIZABLE'],['Cabinet',text],['VolumeLabel','CHAR(32)'],['Source','CHAR(72)']],['DiskId'],[[1,files.length,null,'#payload.cab',null,null]]),
    table('Registry',[['Registry',id],['Root','SHORT NOT NULL'],['Key','CHAR(255) NOT NULL LOCALIZABLE'],['Name',localized],['Value','CHAR(0) LOCALIZABLE'],['Component_',id]],['Registry'],registry),
    table('Shortcut',[['Shortcut',id],['Directory_',id],['Name','CHAR(128) NOT NULL LOCALIZABLE'],['Component_',id],['Target','CHAR(255) NOT NULL'],['Arguments',text],['Description',localized],['Hotkey','SHORT'],['Icon_','CHAR(72)'],['IconIndex','SHORT'],['ShowCmd','SHORT'],['WkDir','CHAR(72)']],['Shortcut'],[
      ['StartMenu','AppMenu',`Lianpu|${productName}`,'Menu',`[#${launch.fileId}]`,null,productName,null,null,null,1,'INSTALLDIR'],
      ['DesktopShortcut','DesktopFolder',`Lianpu|${productName}`,'Desktop',`[#${launch.fileId}]`,null,productName,null,null,null,1,'INSTALLDIR']
    ]),
    table('RemoveFile',[['FileKey',id],['Component_',id],['FileName',localized],['DirProperty',id],['InstallMode','SHORT NOT NULL']],['FileKey'],[['RemoveMenuDir','Menu',null,'AppMenu',2]]),
    table('CreateFolder',[['Directory_',id],['Component_',id]],['Directory_','Component_'],[['AppMenu','Menu']]),
    table('Upgrade',[['UpgradeCode','CHAR(38) NOT NULL'],['VersionMin','CHAR(20)'],['VersionMax','CHAR(20)'],['Language',text],['Attributes','SHORT NOT NULL'],['Remove',text],['ActionProperty',id]],['UpgradeCode','VersionMin','VersionMax','Language','Attributes'],[
      [upgradeCode,null,version,null,513,null,'OLDPRODUCTS'],[upgradeCode,version,null,null,2,null,'NEWERPRODUCTS']
    ]),
    table('LaunchCondition',[['Condition','CHAR(255) NOT NULL'],['Description','CHAR(255) NOT NULL LOCALIZABLE']],['Condition'],[
      ['VersionNT64 AND OSBUILD >= 10240','此版本需要 Windows 10 或更新的 x64 系统。已测试版本请见发布说明。'],['NOT NEWERPRODUCTS','已安装较新的版本，请使用较新的安装程序。'],
      ['(ALLUSERS = 2 AND MSIINSTALLPERUSER = 1) OR NOT ALLUSERS','此程序仅支持当前用户安装。']
    ]),
    table('RegLocator',[['Signature_',id],['Root','SHORT NOT NULL'],['Key','CHAR(255) NOT NULL'],['Name',text],['Type','SHORT']],['Signature_'],[['WindowsBuild',2,'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion','CurrentBuildNumber',18],['ProgramLocation',1,`Software\\${installFolder}\\Installer`,'InstallLocation',18],...(uninstallCleanup?[['ExistingStartup',1,'Software\\Microsoft\\Windows\\CurrentVersion\\Run',startupItemName,18]]:[])]),
    table('Signature',[['Signature',id],['FileName','CHAR(255) NOT NULL'],['MinVersion','CHAR(20)'],['MaxVersion','CHAR(20)'],['MinSize','LONG'],['MaxSize','LONG'],['MinDate','LONG'],['MaxDate','LONG'],['Languages',text]],['Signature'],[]),
    table('AppSearch',[['Property',id],['Signature_',id]],['Property','Signature_'],[['OSBUILD','WindowsBuild'],['SavedInstallDirectory','ProgramLocation'],...(uninstallCleanup?[['ExistingStartupValue','ExistingStartup']]:[])]),
    table('CustomAction',[['Action',id],['Type','SHORT NOT NULL'],['Source','CHAR(72)'],['Target','CHAR(255)']],['Action'],customActions),
    table('InstallExecuteSequence',[['Action',id],['Condition',text],['Sequence','SHORT']],['Action'],sequences),
    table('InstallUISequence',[['Action',id],['Condition',text],['Sequence','SHORT']],['Action'],[
      ['FindRelatedProducts',null,25],['ClearSavedInstallDirectory',null,39],['ClearExistingStartupValue',null,40],['AppSearch',null,50],['RestoreInstallLocation','SavedInstallDirectory AND (Installed OR NOT INSTALLDIR)',60],['LaunchConditions',null,100],['CostInitialize',null,800],['FileCost',null,900],['CostFinalize',null,1000],['MigrateFeatureStates',null,1200],
      ['Welcome','NOT Installed',1230],['Maintenance','Installed',1240],['Progress',null,1280],['ExecuteAction',null,1300],
      ['Complete',null,-1],['Cancelled',null,-2],['Failed',null,-3]
    ])
  ];
  const dialogs = [], controls = [], events = [];
  function dialog(name,title,body,button='继续',end='Return',attrs=3) {
    dialogs.push([name,50,50,380,250,attrs,title,'Next','Next','Cancel']);
    controls.push([name,'Title','Text',20,18,340,25,3,null,'{\\Heading}' + title,null,null]);
    controls.push([name,'Body','Text',20,55,340,115,3,null,body,null,null]);
    controls.push([name,'Next','PushButton',218,217,72,20,3,null,button,'Cancel',null]);
    controls.push([name,'Cancel','PushButton',296,217,64,20,3,null,'取消','Next',null]);
    events.push([name,'Next','EndDialog',end,'1',10],[name,'Cancel','EndDialog','Exit','1',10]);
  }
  dialog('Welcome',`安装 ${productName}`,`所需运行组件已随包提供。\r\n\r\n只为当前用户安装，升级及卸载保留本机资料和授权。\r\n安装前请先完全退出 ${productName}。\r\n\r\n本版本为开发验证包，尚未代码签名。\r\n实际设备、云端和平台验证范围见随附报告。`,'安装');
  controls.push(['Welcome','DesktopOption','CheckBox',20,178,335,18,3,'CREATE_DESKTOP','创建桌面快捷方式',null,null]);
  controls.find(c=>c[0]==='Welcome'&&c[1]==='Cancel')[10]='DesktopOption';
  controls.find(c=>c[0]==='Welcome'&&c[1]==='DesktopOption')[10]='Next';
  dialog('Maintenance',`维护 ${productName}`,`此版本已经安装。\r\n\r\n“修复”重新安装原始程序文件，保留资料和设备授权。\r\n“卸载”移除程序，保留资料和设备授权。\r\n\r\n请先完全退出 ${productName}。`,'卸载');
  events.push(['Maintenance','Next','[REMOVE]','ALL','1',1]);
  controls.push(['Maintenance','Repair','PushButton',138,217,72,20,3,null,'修复','Next',null]);
  controls.find(c=>c[0]==='Maintenance'&&c[1]==='Cancel')[10]='Repair';
  events.push(['Maintenance','Repair','[REINSTALL]','ALL','1',1],['Maintenance','Repair','[REINSTALLMODE]','amus','1',2],['Maintenance','Repair','EndDialog','Return','1',10]);
  dialog('RemoveConfirm',`卸载 ${productName}`,`卸载程序和快捷方式。\r\n\r\n本机资料与设备授权会保留。\r\n卸载后程序不会继续处理任务。\r\n\r\n请先完全退出 ${productName}，再继续。`,'卸载');
  dialog('Progress',`正在处理 ${productName}`,'请稍候，Windows 正在处理程序文件。\r\n你的业务资料不会被删除。','处理中','Return',1);
  const progressNext = controls.find(c => c[0]==='Progress'&&c[1]==='Next'); progressNext[7]=0;
  const progressDialog=dialogs.find(d=>d[0]==='Progress'); progressDialog[8]='Cancel'; progressDialog[9]='Cancel';
  controls.push(['Progress','Bar','ProgressBar',20,160,340,14,65537,null,null,null,null]);
  controls.push(['Progress','Action','Text',20,185,340,20,3,null,'准备处理文件',null,null]);
  for (const [name,title,body] of [['Complete','已完成',`Windows 已完成本次操作。\r\n可从开始菜单打开 ${productName}。\r\n若刚刚卸载，本机资料与设备授权仍保留。`],['Cancelled','已取消','你已取消本次操作。\r\n本机资料与设备授权会保留。'],['Failed','未能完成','安装或卸载未能完成。\r\n请保留 Windows 安装日志并查看发布说明。\r\n不要关闭系统保护来继续。\r\n\r\n业务资料不属于本安装包的删除范围。']]) {
    dialog(name,title,body,'关闭');
    controls.find(c => c[0]===name&&c[1]==='Cancel')[7]=0;
    events.find(e=>e[0]===name&&e[1]==='Cancel')[3]='Return';
  }
  tables.push(
    table('Dialog',[['Dialog',id],['HCentering','SHORT NOT NULL'],['VCentering','SHORT NOT NULL'],['Width','SHORT NOT NULL'],['Height','SHORT NOT NULL'],['Attributes','LONG'],['Title','CHAR(128) LOCALIZABLE'],['Control_First',id],['Control_Default','CHAR(72)'],['Control_Cancel','CHAR(72)']],['Dialog'],dialogs),
    table('Control',[['Dialog_',id],['Control',id],['Type',id],['X','SHORT NOT NULL'],['Y','SHORT NOT NULL'],['Width','SHORT NOT NULL'],['Height','SHORT NOT NULL'],['Attributes','LONG'],['Property','CHAR(72)'],['Text','CHAR(0) LOCALIZABLE'],['Control_Next','CHAR(72)'],['Help','CHAR(50) LOCALIZABLE']],['Dialog_','Control'],controls),
    table('ControlEvent',[['Dialog_',id],['Control_',id],['Event','CHAR(50) NOT NULL'],['Argument','CHAR(255) NOT NULL'],['Condition',text],['Ordering','SHORT']],['Dialog_','Control_','Event','Argument','Condition'],events),
    table('CheckBox',[['Property',id],['Value','CHAR(64)']],['Property'],[['CREATE_DESKTOP','1']]),
    table('EventMapping',[['Dialog_',id],['Control_',id],['Event',id],['Attribute',id]],['Dialog_','Control_','Event'],[['Progress','Bar','SetProgress','Progress'],['Progress','Action','ActionText','Text']]),
    table('TextStyle',[['TextStyle',id],['FaceName','CHAR(32) NOT NULL'],['Size','SHORT NOT NULL'],['Color','LONG'],['StyleBits','SHORT']],['TextStyle'],[['Body','Microsoft YaHei UI',10,0,0],['Heading','Microsoft YaHei UI',16,0,1]])
  );
  return { msi:outfile, productCode, packageCode, upgradeCode, version, productName, installFolder, launchFileId:launch.fileId, definitions:tables, payload };
}
const AUTHOR_PS = `param([string]$Configuration)
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath $Configuration -Raw -Encoding UTF8 | ConvertFrom-Json
$installer = New-Object -ComObject WindowsInstaller.Installer
# Use the actual PE version, and bind unversioned application resources to the
# versioned launcher. The MSI must not treat a changed ASAR as user-edited data.
$fileDefinition = @($cfg.definitions | Where-Object { $_[0] -eq 'File' })[0]
$launcher = @($cfg.payload | Where-Object { $_.fileId -eq $cfg.launchFileId })[0]
$launcherVersion = $installer.FileVersion($launcher.source, $false)
foreach ($row in $fileDefinition[3]) {
  $sourceFile = @($cfg.payload | Where-Object { $_.fileId -eq $row[0] })[0]
  $actualVersion = $installer.FileVersion($sourceFile.source, $false)
  if ($actualVersion) { $row[4] = $actualVersion; $row[5] = $installer.FileVersion($sourceFile.source, $true) }
  elseif ($launcherVersion -and $row[0] -ne $cfg.launchFileId) { $row[4] = $cfg.launchFileId }
}
$database = $installer.OpenDatabase($cfg.msi, 3)
$database.Import((Split-Path -Parent $Configuration), 'codepage.idt')
foreach ($def in $cfg.definitions) {
  $view = $database.OpenView('CREATE TABLE ' + [char]96 + $def[0] + [char]96 + ' (' + $def[1] + ')')
  $view.Execute(); $view.Close()
  $cols = ($def[2] | ForEach-Object { [char]96 + $_ + [char]96 }) -join ', '
  $values = ($def[2] | ForEach-Object { '?' }) -join ', '
  foreach ($row in $def[3]) {
    $record = $installer.CreateRecord($def[2].Count)
    for ($i=0; $i -lt $def[2].Count; $i++) {
      if ($null -eq $row[$i]) { continue }
      $property = if ($row[$i] -is [long] -or $row[$i] -is [int]) { 'IntegerData' } else { 'StringData' }
      $value = if ($property -eq 'IntegerData') { [int]$row[$i] } else { [string]$row[$i] }
      $record.GetType().InvokeMember($property,[Reflection.BindingFlags]::SetProperty,$null,$record,@([int]($i+1),$value)) | Out-Null
    }
    $view = $database.OpenView('INSERT INTO ' + [char]96 + $def[0] + [char]96 + ' (' + $cols + ') VALUES (' + $values + ')')
    $view.Execute($record); $view.Close()
  }
}
$record = $installer.CreateRecord(2)
$record.GetType().InvokeMember('StringData',[Reflection.BindingFlags]::SetProperty,$null,$record,@(1,'payload.cab')) | Out-Null
$record.SetStream(2,$cfg.cabinet)
$view = $database.OpenView('INSERT INTO ' + [char]96 + '_Streams' + [char]96 + ' (' + [char]96 + 'Name' + [char]96 + ',' + [char]96 + 'Data' + [char]96 + ') VALUES (?, ?)')
$view.Execute($record); $view.Close()
$summary = $database.SummaryInformation(20)
$properties = @{1=936;2='Installation Database';3=$cfg.productName;4='Lianpu Development';7='x64;2052';9=$cfg.packageCode;14=500;15=10;18='Lianpu independent Windows Installer authoring'}
foreach($key in $properties.Keys) { $summary.GetType().InvokeMember('Property',[Reflection.BindingFlags]::SetProperty,$null,$summary,@([int]$key,$properties[$key])) | Out-Null }
$summary.Persist(); $database.Commit()
`;
function buildMsi(options) {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('MSI 构建需要开发方 Windows x64');
  const config = database(options); const work = options.work;
  fs.mkdirSync(work,{recursive:true});
  if (fs.existsSync(options.outfile)) throw new Error('MSI 输出文件已经存在；使用独立构建路径');
  const cabinet = path.join(work,'payload.cab'); config.cabinet = cabinet;
  const ddf = ['.OPTION EXPLICIT','.Set Cabinet=on','.Set Compress=on','.Set CompressionType=MSZIP','.Set CabinetNameTemplate=payload.cab',`.Set DiskDirectoryTemplate="${work}"`,'.Set MaxDiskSize=0','.Set MaxCabinetSize=0','.Set MaxDiskFileCount=0','.Set FolderSizeThreshold=0', ...config.payload.map(f => `"${f.source}" ${f.fileId}`)].join('\r\n');
  const ddfPath = path.join(work,'payload.ddf'); fs.writeFileSync(ddfPath,ddf,'utf8');
  const makecab = path.join(process.env.SystemRoot,'System32','makecab.exe');
  const compressed = spawnSync(makecab,['/F',ddfPath],{cwd:work,encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(work,'makecab.log'),(compressed.stdout||'')+'\n'+(compressed.stderr||''));
  if (compressed.status!==0 || !fs.existsSync(cabinet)) throw new Error('Windows CAB 构建失败，见 '+path.join(work,'makecab.log'));
  fs.writeFileSync(path.join(work,'codepage.idt'),'\r\n\r\n936\t_ForceCodepage\r\n','ascii');
  fs.writeFileSync(path.join(work,'database.json'),JSON.stringify(config));
  fs.writeFileSync(path.join(work,'author.ps1'),AUTHOR_PS,'utf8');
  const ps = path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
  const authored = spawnSync(ps,['-NoProfile','-File',path.join(work,'author.ps1'),'-Configuration',path.join(work,'database.json')],{encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(work,'author.log'),(authored.stdout||'')+'\n'+(authored.stderr||''));
  if(authored.status!==0 || !fs.existsSync(options.outfile)) throw new Error('MSI 数据库构建失败，见 '+path.join(work,'author.log'));
  return {format:'msi',productCode:config.productCode,upgradeCode:config.upgradeCode,packageCode:config.packageCode,packageLanguage:2052,architecture:'x64',installContext:'per-user',installerEngine:'Windows Installer',cabinetSha256:sha(fs.readFileSync(cabinet)),makecabSha256:sha(fs.readFileSync(makecab)),authoredTables:config.definitions.length,fullIceValidation:'not-performed-no-Windows-SDK-validation-tool',dataDeletion:'no-business-data-or-session-files-in-installer-tables'};
}
module.exports = { buildMsi, database, UPGRADE_CODE };
