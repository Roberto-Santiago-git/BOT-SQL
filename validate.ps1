param(
  [Parameter(Position=0)][string]$Name,  # << antes era $Input
  [switch]$Diag,
  [switch]$Why
)

# 0) Fuente: ruta, nombre en chat o SQL inline
if ([string]::IsNullOrWhiteSpace($Name)) { $Name = $env:CHAT_MESSAGE }

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

  $U = $s.ToUpperInvariant()
  if ($U -match '\b(CREATE|ALTER|INSERT|UPDATE|DELETE|MERGE|DECLARE|BEGIN|SELECT)\b' -and $U.Length -gt 40) {
    $tmp = Join-Path $env:TEMP ("inline_{0:yyyyMMdd_HHmmssfff}.sql" -f (Get-Date))
    $s | Set-Content -Encoding UTF8 $tmp
    return $tmp
  }
  return $null
}

$Path = Resolve-PathOrAttachment $Name

if ($Diag) {
  "ATTACHMENTS_DIR: $env:ATTACHMENTS_DIR"
  if ($env:ATTACHMENTS_DIR -and (Test-Path $env:ATTACHMENTS_DIR)) {
    Get-ChildItem $env:ATTACHMENTS_DIR -File |
      Select Name,Length,LastWriteTime |
      Sort LastWriteTime -Desc | Select -First 10 | Format-Table | Out-String | Write-Host
  }
  "INPUT:    '$Name'"
  "RESOLVED: '$Path'"
}

if (-not $Path) { "SIN-ANÁLISIS"; exit 3 }

# 1) Precheck corporativo
$rulesJson = @"
[
  {"id":"ORA-INSERT-NOCOLS-SELECT","regex":"(?is)\\binsert\\s+into\\s+[^\\(\\s;]+\\s+(?=select\\b)"},
  {"id":"ORA-INSERT-NOCOLS-VALUES","regex":"(?is)\\binsert\\s+into\\s+[^\\(\\s;]+\\s*values\\s*\\("},
  {"id":"ORA-SCHEMA-NOT-QUALIFIED","regex":"(?im)^\\s*insert\\s+into\\s+(?!\"?[A-Z0-9_]+\"?\\.)\"?[A-Z0-9_]+\"?"},
  {"id":"ORA-SEQ-MAXPLUSONE","regex":"(?is)max\\s*\\(\\s*[A-Z0-9_\"\\.]+\\s*\\)\\s*\\+\\s*1"},
  {"id":"ORA-WHEN-OTHERS-NO-RAISE","regex":"(?is)when\\s+others\\s+then(?:(?!raise_application_error).)*?end\\s*;"},
  {"id":"IPC-TRUNCATE-TARGET","regex":"(?i)truncate\\s+target\\s+table"},
  {"id":"PS-CLEAR-HOST-FIRST","regex":"(?s)\\A(?!\\s*Clear-Host)"}
]
"@
$txt   = Get-Content -LiteralPath $Path -Raw
$rules = $rulesJson | ConvertFrom-Json
foreach ($r in $rules) {
  if ([regex]::IsMatch($txt, $r.regex)) {
    if ($Why) { "[rule] $($r.id)" | Out-Host }
    "NO CUMPLE"; exit 2
  }
}

# 2) Motor existente
$engine = Join-Path $PSScriptRoot 'validator_integration.py'
if (-not (Test-Path $engine)) { $engine = '.\validator_integration.py' }
$out = & python -u $engine $Path 2>&1

if ($out -match '(?i)Veredicto\s*:\s*([A-ZÁÉÍÓÚÑ \-]+)') { $matches[1].Trim().ToUpper(); exit 0 }
if ($out -match '(?i)\b(NO\s*CUMPLE|CUMPLE)\b')       { $matches[1].Trim().ToUpper(); exit 0 }
"SIN-ANÁLISIS"
