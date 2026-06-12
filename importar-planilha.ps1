param(
  [Parameter(Mandatory = $true)]
  [string]$Planilha,

  [string]$NodeExe = "node",
  [string]$AdminLogin = "ADM",
  [Parameter(Mandatory = $true)]
  [string]$AdminPassword
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$authDb = Join-Path $root "data\auth.db"
$secret = Join-Path $root "data\app-secret.key"
$provision = Join-Path $root "provision.mjs"

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

try {
  $workbook = $excel.Workbooks.Open($Planilha, 0, $true)
  $sheet = $workbook.Worksheets.Item(1)
  $used = $sheet.UsedRange

  $headers = @(
    [string]$used.Cells.Item(1, 1).Text,
    [string]$used.Cells.Item(1, 2).Text
  )

  if ($headers[0] -notmatch "USP" -or $headers[1] -notmatch "CPF") {
    throw "A primeira planilha deve ter as colunas Nº USP e CPF nessa ordem."
  }

  $records = @()
  for ($row = 2; $row -le $used.Rows.Count; $row++) {
    $usp = ([string]$used.Cells.Item($row, 1).Text) -replace "\D", ""
    $cpf = ([string]$used.Cells.Item($row, 2).Text) -replace "\D", ""
    if ($cpf -and $cpf.Length -lt 11) {
      $cpf = $cpf.PadLeft(11, "0")
    }
    if ($usp -or $cpf) {
      $records += [pscustomobject]@{ usp = $usp; cpf = $cpf }
    }
  }

  $payload = [pscustomobject]@{
    records = $records
    adminLogin = $AdminLogin
    adminPassword = $AdminPassword
  }
  $json = $payload | ConvertTo-Json -Depth 4 -Compress
  $json | & $NodeExe $provision $authDb $secret
  if ($LASTEXITCODE -ne 0) {
    throw "Falha ao provisionar o banco de autenticação."
  }
} finally {
  if ($workbook) {
    $workbook.Close($false)
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) | Out-Null
  }
  $excel.Quit()
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
}
