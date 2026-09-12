param([Parameter(Mandatory=$true)][string]$MsiPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$installer = $null
$database = $null
try {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  # MSIDBOPEN_READONLY (0). Never call InstallProduct, ConfigureProduct or msiexec.
  $database = $installer.OpenDatabase($MsiPath, 0)
  function ReadProperty([string]$name) {
    # Names are constants in this file. No path or MSI content enters SQL.
    $view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''' + $name + '''')
    try {
      $view.Execute() | Out-Null
      $record = $view.Fetch()
      if ($null -eq $record) { return '' }
      $value = [string]$record.StringData(1)
      if ($value.Length -gt 255) { throw 'Metadata length is invalid' }
      return $value
    } finally { $view.Close() | Out-Null }
  }
  $summary = $database.SummaryInformation(0)
  [ordered]@{
    productName = ReadProperty 'ProductName'
    productVersion = ReadProperty 'ProductVersion'
    upgradeCode = ReadProperty 'UpgradeCode'
    productCode = ReadProperty 'ProductCode'
    manufacturer = ReadProperty 'Manufacturer'
    allUsers = ReadProperty 'ALLUSERS'
    msiInstallPerUser = ReadProperty 'MSIINSTALLPERUSER'
    template = [string]$summary.Property(7)
    wordCount = [int]$summary.Property(15)
  } | ConvertTo-Json -Compress
} catch {
  # Do not expose Windows exception text, MSI contents or user paths.
  [Console]::Error.Write('MSI_METADATA_READ_FAILED')
  exit 1
} finally {
  if ($null -ne $database) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null }
  if ($null -ne $installer) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null }
}
