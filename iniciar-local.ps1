param(
  [string]$NodeExe = "node",
  [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:HOST = "127.0.0.1"
$env:PORT = [string]$Port

Push-Location $root
try {
  & $NodeExe "server.mjs"
} finally {
  Pop-Location
}
