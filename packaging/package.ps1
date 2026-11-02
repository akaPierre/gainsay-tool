<#
.SYNOPSIS
  Builds a standalone Gainsay for Windows: dist\gainsay\gainsay.exe with its own Java runtime (no Java install
  needed), a zip of it, and optionally an MSI installer (needs the WiX Toolset on PATH).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\package.ps1
  powershell -ExecutionPolicy Bypass -File packaging\package.ps1 -Installer
#>
param([switch]$Installer)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = '0.1.0'
$jar = "gainsay-$version.jar"
# Modules from: jdeps --print-module-deps --ignore-missing-deps target\gainsay-$version.jar (+ java.logging for slf4j)
$modules = 'java.base,java.desktop,java.sql,java.logging'

$jpackage = Get-Command jpackage -ErrorAction SilentlyContinue
if (-not $jpackage -and $env:JAVA_HOME) { $jpackage = Get-Command (Join-Path $env:JAVA_HOME 'bin\jpackage.exe') -ErrorAction SilentlyContinue }
if (-not $jpackage) { throw 'jpackage not found: install a JDK 21+ and put its bin folder on PATH (or set JAVA_HOME).' }

Write-Host '1/3 Building and testing the jar...'
mvn -q -B package
if ($LASTEXITCODE -ne 0) { throw 'Maven build failed.' }

$staging = Join-Path $root 'target\jpackage-input'
$dist = Join-Path $root 'dist'
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
if (Test-Path (Join-Path $dist 'gainsay')) { Remove-Item (Join-Path $dist 'gainsay') -Recurse -Force }
New-Item -ItemType Directory -Force $staging, $dist | Out-Null
Copy-Item "target\$jar" $staging

$common = @(
  '--name', 'gainsay', '--app-version', $version, '--vendor', 'Gainsay',
  '--description', 'Cross-examines security settings against observed network traffic (read-only, passive).',
  '--input', $staging, '--main-jar', $jar, '--main-class', 'dev.gainsay.cli.Main',
  '--add-modules', $modules, '--jlink-options', '--strip-debug --no-header-files --no-man-pages',
  '--java-options', '--enable-native-access=ALL-UNNAMED', '--win-console', '--dest', $dist
)

Write-Host '2/3 Creating the app image (bundled Java runtime)...'
& $jpackage.Source --type app-image @common
if ($LASTEXITCODE -ne 0) { throw 'jpackage app-image failed.' }

Copy-Item LICENSE, NOTICE, README.md, SECURITY.md (Join-Path $dist 'gainsay')

# Sign gainsay.exe before zipping it, when a signing command is provided (CI sets one; see .github/workflows/release.yml).
# It receives the path of the file to sign as its only argument.
if ($env:GAINSAY_SIGN_SCRIPT) {
  Write-Host "Signing gainsay.exe with $env:GAINSAY_SIGN_SCRIPT..."
  & $env:GAINSAY_SIGN_SCRIPT (Join-Path $dist 'gainsay\gainsay.exe')
  if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
}

$zip = Join-Path $dist "gainsay-$version-windows-x64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $dist 'gainsay') -DestinationPath $zip

if ($Installer) {
  Write-Host '3/3 Creating the MSI installer (needs WiX Toolset)...'
  & $jpackage.Source --type msi @common --win-dir-chooser --win-menu --win-menu-group Gainsay --win-shortcut-prompt
  if ($LASTEXITCODE -ne 0) { throw 'jpackage msi failed (is the WiX Toolset installed and on PATH?).' }
} else {
  Write-Host '3/3 Skipping the MSI (pass -Installer; needs the WiX Toolset).'
}

# Checksums for every published file, in the format of sha256sum (verify with: certutil -hashfile FILE SHA256).
$sums = Get-ChildItem $dist -File | Where-Object { $_.Extension -in '.zip', '.msi' } | Sort-Object Name | ForEach-Object {
  '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
}
[IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS-windows.txt'), [string[]]$sums)

Write-Host ''
Write-Host "Done. Run:  dist\gainsay\gainsay.exe audit"
Write-Host "Portable zip: $zip  (checksums in dist\SHA256SUMS-windows.txt)"
Write-Host 'Tip: add dist\gainsay to your PATH to type just "gainsay audit".'
