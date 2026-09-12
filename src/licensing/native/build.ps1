[CmdletBinding()]
param([switch]$IsolatedTest)
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Windows x64 .NET Framework 4.x compiler was not found.' }
$source = Join-Path $PSScriptRoot 'LianpuTpm.cs'
$outputDirectory = if ($IsolatedTest) { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\tests\work\licensing-client-tpm')) } else { Join-Path $PSScriptRoot 'bin' }
$output = Join-Path $outputDirectory $(if ($IsolatedTest) { 'Lianpu.Device.Test.exe' } else { 'Lianpu.Device.exe' })
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$compilerArguments = @('/nologo', '/target:exe', '/platform:x64', '/optimize+', '/warnaserror+', '/utf8output', '/reference:System.Web.Extensions.dll', "/out:$output", $source)
if ($IsolatedTest) { $compilerArguments = @('/define:LIANPU_ISOLATED_TEST') + $compilerArguments }
& $compiler @compilerArguments
if ($LASTEXITCODE -ne 0) { throw "Native helper build failed with exit code $LASTEXITCODE." }
$hashAlgorithm = [Security.Cryptography.SHA256]::Create()
try { $outputHash = [BitConverter]::ToString($hashAlgorithm.ComputeHash([IO.File]::ReadAllBytes($output))).Replace('-', '').ToLowerInvariant() } finally { $hashAlgorithm.Dispose() }
[pscustomobject]@{ path = $output; isolatedTest = [bool]$IsolatedTest; sha256 = $outputHash; compiler = $compiler } | ConvertTo-Json -Compress
