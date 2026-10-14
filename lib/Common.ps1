# 공통 헬퍼. 진입점에서 dot-source 되며, checks\*.ps1 은 같은 스코프의 $script:Findings 에 결과를 쌓는다.

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:SigCache = @{}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'WARN', 'INFO', 'SKIP', 'N/A', 'ERROR')][string]$Status,
        [ValidateSet('CAT I', 'CAT II', 'CAT III', '')][string]$Severity = '',
        [string]$Evidence = '',
        [string]$Remediation = '',
        [string]$STIG = '',
        [string[]]$NIST = @(),
        [string]$Note = ''
    )
    $script:Findings.Add([pscustomobject][ordered]@{
            Id = $Id; Category = $Category; Title = $Title; Status = $Status; Severity = $Severity
            Evidence = $Evidence; Remediation = $Remediation; STIG = $STIG; NIST = ($NIST -join ', '); Note = $Note
        })
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-AdminSkip([string]$Id, [string]$Category, [string]$Title, [string]$STIG = '', [string[]]$NIST = @()) {
    Add-Finding -Id $Id -Category $Category -Title $Title -Status SKIP -Evidence '관리자 권한 필요 - 관리자 PowerShell 에서 다시 실행' -STIG $STIG -NIST $NIST
}

# 비밀값 마스킹: 원문은 어디에도 남기지 않는다.
function Get-MaskedSecret([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return '' }
    if ($s.Length -le 12) { return $s.Substring(0, [Math]::Min(2, $s.Length)) + '***' + " (len=$($s.Length))" }
    if ($s.Length -le 24) { return $s.Substring(0, 2) + '...' + $s.Substring($s.Length - 2) + " (len=$($s.Length))" }
    return $s.Substring(0, 4) + '...' + $s.Substring($s.Length - 4) + " (len=$($s.Length))"
}

function Get-ShannonEntropy([string]$s) {
    if (-not $s) { return 0 }
    $h = 0.0
    $s.ToCharArray() | Group-Object | ForEach-Object { $p = $_.Count / $s.Length; $h -= $p * [Math]::Log($p, 2) }
    [Math]::Round($h, 2)
}

# Authenticode 서명 (경로별 캐시)
function Get-SignatureInfo([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Status = 'NoPath'; Signer = '' } }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { [pscustomobject]@{ Status = 'NotFound'; Signer = '' } }
        else {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
            [pscustomobject]@{ Status = [string]$s.Status; Signer = $signer }
        }
    } catch { [pscustomobject]@{ Status = 'Error'; Signer = '' } }
    $script:SigCache[$Path] = $r
    $r
}

# 서비스 ImagePath / 명령줄에서 실행 파일 경로만 뽑기
function Resolve-ExecutablePath([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^system32\\', "$env:SystemRoot\System32\"
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js))(\s|,|$)') { return $Matches[1] }
    ($c -split '\s+')[0]
}

# 일반 사용자가 쓸 수 있는 위치인지: 프로필·Temp 는 무조건, 그 외는 상위 폴더 ACL 로 판정 (폴더별 캐시)
$script:WritableCache = @{}
function Test-UserWritablePath([string]$Path) {
    if (-not $Path) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($root in @($env:USERPROFILE, $env:TEMP, $env:PUBLIC, "$env:SystemRoot\Temp")) {
        if ($root -and $p.StartsWith($root.ToLowerInvariant() + '\')) { return $true }
    }
    $dir = Split-Path $Path -Parent
    if (-not $dir) { return $false }
    if ($script:WritableCache.ContainsKey($dir)) { return $script:WritableCache[$dir] }
    $w = $false
    try {
        $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
        $broad = 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11'
        # 파일 생성(0x2)·추가(0x4)·GENERIC_WRITE·GENERIC_ALL 만 본다 (FullControl 등 복합값은 Synchronize 비트까지 포함해 오탐)
        $mask = 0x2 -bor 0x4 -bor 0x40000000 -bor 0x10000000
        foreach ($a in $acl.Access) {
            if ($a.AccessControlType -ne 'Allow' -or ($a.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($sid -in $broad -and ([int64][int]$a.FileSystemRights -band $mask)) { $w = $true; break }
        }
    } catch { }
    $script:WritableCache[$dir] = $w
    $w
}
function Get-RegValue([string]$Hive, [string]$Path, [string]$Name) {
    $full = "Registry::$(if ($Hive -eq 'HKCU') { 'HKEY_CURRENT_USER' } else { 'HKEY_LOCAL_MACHINE' })\$Path"
    try {
        $k = Get-Item -LiteralPath $full -ErrorAction Stop
        $v = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        if ($null -eq $v) { return [pscustomobject]@{ Exists = $false; Value = $null } }
        [pscustomobject]@{ Exists = $true; Value = $v }
    } catch { [pscustomobject]@{ Exists = $false; Value = $null } }
}

function Test-Expectation($Actual, [string]$Op, $Expected) {
    switch ($Op) {
        'eq'    { if ($Expected -is [string] -and $Actual -is [array]) { return (($Actual -join ' ') -eq $Expected) }
                  return ("$Actual" -eq "$Expected") }
        'ge'    { return ([int64]$Actual -ge [int64]$Expected) }
        'le'    { return ([int64]$Actual -le [int64]$Expected) }
        'le_nz' { return ([int64]$Actual -le [int64]$Expected -and [int64]$Actual -ne 0) }
        'in'    { return (@($Expected | ForEach-Object { "$_" }) -contains "$Actual") }
        default { return $false }
    }
}

function Format-Expectation([string]$Op, $Expected) {
    switch ($Op) {
        'eq' { "= $Expected" } 'ge' { ">= $Expected" } 'le' { "<= $Expected" }
        'le_nz' { "1..$Expected (0 제외)" } 'in' { "in {$($Expected -join ', ')}" } default { "$Op $Expected" }
    }
}

# 외부 명령 실행 (출력 문자열, 실패 시 $null)
function Invoke-Native([string]$File, [string[]]$Arguments) {
    try {
        $out = & $File @Arguments 2>$null
        if ($LASTEXITCODE -ne 0 -and -not $out) { return $null }
        $out
    } catch { $null }
}

function Get-IsPrivateIp([string]$ip) {
    if ($ip -match '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)' -or $ip -in '::', '::1' -or $ip -match '^(fe80|fc|fd)') { return $true }
    $false
}

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
