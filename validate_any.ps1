param(
  [Parameter(Position=0,Mandatory=$true)][string]$Name,
  [switch]$Diag, [switch]$Why
)

function Resolve-PathOrAttachment([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $s = $s.Trim('"').Trim()
  if (Test-Path -LiteralPath $s) {
    $fi = Get-Item -LiteralPath $s -ErrorAction SilentlyContinue
    if ($fi -and $fi.Length -gt 0) { return $fi.FullName }
  }
  $dir = $env:ATTACHMENTS_DIR
  if ($dir -and (Test-Path -LiteralPath $dir)) {
    $file = Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -ieq $s } | Select-Object -First 1
    if (-not $file) {
      $file = Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -like "*$s*" } |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($file -and $file.Length -gt 0) { return $file.FullName }
  }
  return $null
}

$Path = Resolve-PathOrAttachment $Name
if ($Diag) { "ATTACHMENTS_DIR: $env:ATTACHMENTS_DIR"; "INPUT: '$Name'"; "RESOLVED: '$Path'" }
if (-not $Path) { "SIN-ANÁLISIS"; exit 3 }

$ext  = [IO.Path]::GetExtension($Path).ToLowerInvariant()
$head = Get-Content -LiteralPath $Path -Raw
$probe = $head.Substring(0,[Math]::Min($head.Length,4000))
function Is-Oracle { param($t) return ($t -match '(?is)\b(CREATE|ALTER|INSERT|UPDATE|DELETE|MERGE|DECLARE|BEGIN|SELECT)\b') }
function Is-IPC    { param($t) return ($t -match '(?i)\b(Workflow|Mapping|Session|IPC|TRUNCATE\s+TARGET\s+TABLE|PRM_VERSION|PARAM=)\b') }

$type = switch ($ext) {
  '.ps1' { 'ps' }
  { $_ -in @('.sql','.pkb','.pks','.pls','.ddl','.pkg') } { 'oracle' }
  { $_ -in @('.prm','.txt','.xml') } {
    if (Is-Oracle $probe) { 'oracle' } elseif (Is-IPC $probe) { 'ipc' } else { 'ipc' }
  }
  default {
    if (Is-Oracle $probe) { 'oracle' } elseif (Is-IPC $probe) { 'ipc' } else { 'ps' }
  }
}

$polRoot = Join-Path $PSScriptRoot 'policies'
$policy = switch ($type) {
  'oracle' { Join-Path $polRoot 'policy_oracle.json' }
  'ipc'    { Join-Path $polRoot 'policy_ipc.json' }
  'ps'     { Join-Path $polRoot 'policy_powershell.json' }
}
if ($Diag) { "TYPE: $type"; "POLICY: $policy" }
if (-not (Test-Path $policy)) { "SIN-ANÁLISIS"; exit 4 }

# Precheck duro (errores → NO CUMPLE) con la política elegida
$rules = Get-Content -Raw -LiteralPath $policy | ConvertFrom-Json
$hitIds = @()
foreach ($r in $rules) {
  if ($r.level -eq 'error' -and [regex]::IsMatch($head, $r.regex)) { $hitIds += $r.id }
}
if ($hitIds.Count -gt 0) {
  if ($Why) { $hitIds | ForEach-Object { "[rule] $_" | Out-Host } }
  "NO CUMPLE"; exit 2
}

# Respaldo: motor Python con la policy seleccionada
$env:POLICY_PATH = $policy
$engine = Join-Path $PSScriptRoot 'validator_integration.py'
if (-not (Test-Path $engine)) { $engine = '.\validator_integration.py' }
$out = & python -u $engine $Path 2>&1

if ($Why) {
  ($out -split "`r?`n") | Where-Object { $_ -match '^\[(error|warn)\]\s*[A-Z0-9_\-:]+' } | ForEach-Object { $_ }
}
if ($out -match '(?i)\bNO\s*CUMPLE\b') { "NO CUMPLE"; exit 2 }
elseif ($out -match '(?i)\bCUMPLE\b')  { "CUMPLE"; exit 0 }
else                                   { "SIN-ANÁLISIS"; exit 3 }
