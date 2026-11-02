# Provenza endpoint agent: install on Windows in one command, in PowerShell
# run as administrator:
#
#   $s='https://provenza.example.com'; & ([scriptblock]::Create((irm "$s/api/v1/egress-sensor/download/install-agent.ps1"))) -Server $s
#
# It downloads the agent for this machine from your Provenza, checks it
# against SHA256SUMS next to it, asks for the Ingestion Source key (input
# hidden) and runs "provenza-agent install": the Windows service
# ProvenzaAgent, started automatically as LocalSystem. Run it again to
# upgrade; the key is then not needed.
#
# Unattended (Intune, GPO startup script, SCCM - they run as SYSTEM):
# -Key KEY or the PROVENZA_KEY environment variable.
#
# Parameters:
#   -Server URL     your Provenza (required)
#   -Key KEY        the Ingestion Source key (prompted for when missing)
#   -AgentId ID     the name this machine is listed under (default: the computer name)
#   -Discovery      also discover network services (DNS, gateway, mDNS, LLMNR)
#   -Uninstall      remove the agent (with -Purge also its configuration)
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$Key = $env:PROVENZA_KEY,
    [string]$AgentId = '',
    [switch]$Discovery,
    [switch]$Uninstall,
    [switch]$Purge
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is many times slower with the progress bar

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as administrator.'
}

$installed = Join-Path $env:ProgramFiles 'Provenza\provenza-agent.exe'
if ($Uninstall) {
    if (-not (Test-Path $installed)) { throw 'The agent is not installed.' }
    if ($Purge) { & $installed uninstall --purge } else { & $installed uninstall }
    return   # not exit: run as a script block, exit would close the PowerShell window
}

$Server = $Server.TrimEnd('/')
$config = Join-Path $env:ProgramData 'Provenza\Agent\config.json'
if (-not $Key -and -not (Test-Path $config)) {
    $secure = Read-Host -AsSecureString 'Ingestion Source key (Settings -> Ingestion Sources, type Endpoint agent)'
    $Key = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if (-not $Key) { throw 'No key given.' }
}

# Windows PowerShell 5.1 may still default to TLS 1.0
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$arch = 'amd64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $arch = 'arm64' }
$name = "provenza-agent-windows-$arch.exe"
$base = "$Server/api/v1/egress-sensor/download"
$tmp = Join-Path $env:TEMP ('provenza-agent-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "-> downloading $name from $Server"
    $exe = Join-Path $tmp $name
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $exe
    $sums = Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS"
    $text = $sums.Content
    if ($text -is [byte[]]) { $text = [Text.Encoding]::UTF8.GetString($text) }
    $expected = $null
    foreach ($line in ($text -split "`n")) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $name) { $expected = $parts[0].ToLower() }
    }
    if (-not $expected) { throw "$name is not in SHA256SUMS: is your Provenza up to date?" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLower()
    if ($actual -ne $expected) { throw "Checksum mismatch for ${name}: not installed." }
    Write-Host '   checksum ok'

    Write-Host '-> installing'
    if ($Key) {
        $argv = @('install', '--server', $Server, '--key', '-')
        if ($AgentId) { $argv += @('--agent-id', $AgentId) }
        if ($Discovery) { $argv += '--discovery' }
        $Key | & $exe @argv
    } else {
        & $exe install   # an upgrade: the configuration and the key stay
    }
    if ($LASTEXITCODE -ne 0) { throw "provenza-agent install failed (exit $LASTEXITCODE)." }
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
