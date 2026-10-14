<#
.SYNOPSIS
  Windows 11 개인 PC 하드닝 점검 (읽기 전용). DISA Windows 11 STIG + NIST SP 800-53 Rev.5 기준.

.DESCRIPTION
  설정을 바꾸지 않는다. 결과는 reports\<시각>\report.html + results.json 에 저장하고, 보고서 폴더는 현재 사용자만 읽도록 ACL 을 제한한다.
  관리자 PowerShell 에서 실행하면 secedit·auditpol·SMB 세션·WMI 구독·선택 기능 점검까지 수행한다(아니면 해당 항목 SKIP).

  점검 영역
    1   API Key 계류        (checks\10-Secrets.ps1)
    2-a 세션·연결          (checks\20-Network.ps1)
    2-b 무결성·의심 파일    (checks\30-Integrity.ps1)
    3   기초보안설정 STIG   (checks\40-Baseline.ps1, data\controls.json)
    4   원격 접속          (checks\50-RemoteAccess.ps1)
    5   공급망·기타        (checks\60-SupplyChain.ps1)

.PARAMETER ScanPath      API Key 스캔 루트 (기본: 사용자 프로필)
.PARAMETER AuditProfile  Personal(기본: Home·비도메인 적용성 반영) | Strict(STIG 원문 그대로)
.PARAMETER NewBaseline   핵심 시스템 바이너리 해시 기준선을 새로 저장
.PARAMETER Deep          sfc /verifyonly, DISM /CheckHealth 추가 (관리자, 10분 내외)
.PARAMETER CompareTo     비교할 이전 results.json (기본: 가장 최근 보고서 자동 선택)
.PARAMETER Skip          건너뛸 영역: Secrets, Network, Integrity, Baseline, RemoteAccess, SupplyChain

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Invoke-HardeningAudit.ps1
.EXAMPLE
  # 관리자 PowerShell, 전체 + 시스템 파일 검사
  .\Invoke-HardeningAudit.ps1 -Deep
#>
[CmdletBinding()]
param(
    [string]$ScanPath = $env:USERPROFILE,
    [string]$OutDir,   # 기본값은 본문에서 (PS 5.1 -File 실행 시 param 기본값의 $PSScriptRoot 가 비어 있음)
    [ValidateSet('Personal', 'Strict')][string]$AuditProfile = 'Personal',
    [switch]$NewBaseline,
    [switch]$Deep,
    [string]$CompareTo,
    [ValidateSet('Secrets', 'Network', 'Integrity', 'Baseline', 'RemoteAccess', 'SupplyChain')][string[]]$Skip = @(),
    [switch]$NoOpen,
    [switch]$Elevate,      # Run-Audit.cmd 용: 관리자 권한 요청 후 그 창에서 실행
    [switch]$Pause,        # 끝나고 창을 바로 닫지 않음
    [string]$GrantSid      # 보고서 폴더를 읽을 수 있게 할 원래 사용자 (다른 관리자 계정으로 승격된 경우)
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot 'reports' }

# --- 더블클릭 실행: 관리자 권한 요청 -------------------------------------------
if ($Elevate -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -NoOpen -ScanPath "{1}" -GrantSid {2} -AuditProfile {3}' -f $PSCommandPath, $ScanPath, $me, $AuditProfile
    Write-Host '관리자 권한을 요청합니다. 화면에 뜨는 창에서 [예]를 눌러 주세요.' -ForegroundColor Cyan
    $child = $null; $launched = Get-Date
    try { $child = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -PassThru -ErrorAction Stop } catch { }
    if ($child) {
        Write-Host '관리자 창에서 점검이 진행됩니다 (10~20분). 끝나면 보고서가 열립니다.' -ForegroundColor Green
        $child.WaitForExit()
        # 브라우저는 관리자 권한이 아닌 이 창에서 연다
        $latest = Get-ChildItem $OutDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        $html = if ($latest) { Join-Path $latest.FullName 'report.html' }
        if ($html -and (Test-Path $html) -and (Get-Item $html).LastWriteTime -gt $launched) {
            Write-Host "보고서를 엽니다: $html" -ForegroundColor Green
            Start-Process $html
        } else {
            Write-Host '관리자 창이 보고서를 만들지 못하고 끝났습니다. Run-Audit.cmd 를 다시 실행하거나, 관리자 PowerShell 에서 Invoke-HardeningAudit.ps1 을 직접 실행해 오류 메시지를 확인하세요.' -ForegroundColor Red
            if ($Pause) { Read-Host "`n엔터를 누르면 창이 닫힙니다" | Out-Null }
        }
        exit
    }
    Write-Host '관리자 권한 없이 진행합니다. 일부 항목(약 90개)은 SKIP 으로 표시됩니다.' -ForegroundColor Yellow
}
$started = Get-Date

. (Join-Path $PSScriptRoot 'lib\Common.ps1')
Get-ChildItem (Join-Path $PSScriptRoot 'checks') -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }
. (Join-Path $PSScriptRoot 'lib\Report.ps1')

$dataDir = Join-Path $PSScriptRoot 'data'
$isAdmin = Test-IsAdmin
Write-Host "Windows 하드닝 점검 (읽기 전용) - 관리자 권한: $isAdmin, 프로필: $AuditProfile" -ForegroundColor Green
if (-not $isAdmin) { Write-Host '    관리자 PowerShell 에서 실행하면 STIG 계정·감사 정책 등 약 70개 항목을 추가로 점검합니다.' -ForegroundColor Yellow }

# 이전 회차 (비교·VS Code 신규 확장 판정용)
if (-not $CompareTo) {
    $prev = Get-ChildItem $OutDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'results.json' } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($prev) { $CompareTo = $prev }
}

$steps = [ordered]@{
    Secrets      = { Invoke-CheckSecrets -ScanPath $ScanPath -DataDir $dataDir -ExcludeRoot $PSScriptRoot }
    Network      = { Invoke-CheckNetwork -IsAdmin $isAdmin }
    Integrity    = { Invoke-CheckIntegrity -IsAdmin $isAdmin -BaselineDir (Join-Path $PSScriptRoot 'baseline') -NewBaseline:$NewBaseline -Deep:$Deep }
    Baseline     = { Invoke-CheckBaseline -IsAdmin $isAdmin -DataDir $dataDir -AuditProfile $AuditProfile }
    RemoteAccess = { Invoke-CheckRemoteAccess -IsAdmin $isAdmin }
    SupplyChain  = { Invoke-CheckSupplyChain -IsAdmin $isAdmin -PrevJson $CompareTo }
}
foreach ($name in $steps.Keys) {
    if ($name -in $Skip) { continue }
    $t0 = Get-Date
    try { & $steps[$name] }
    catch { Add-Finding -Id "ERR-$name" -Category '오류' -Title "$name 점검 중 오류" -Status ERROR -Evidence "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)" }
    Write-Host ("    {0} 완료 ({1:N0}초)" -f $name, ((Get-Date) - $t0).TotalSeconds) -ForegroundColor DarkGray
}

# --- 저장 --------------------------------------------------------------------
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$dir = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Force $dir | Out-Null
Protect-ReportDirectory $dir $GrantSid

$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$meta = [ordered]@{
    Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"; IsAdmin = $isAdmin; Profile = $AuditProfile
    OS = "$($os.ProductName) $($os.DisplayVersion) (build $($os.CurrentBuild).$($os.UBR))"
    Started = $started.ToString('s'); DurationSec = [int]((Get-Date) - $started).TotalSeconds
    Standard = $(if ($script:StigSource) { $script:StigSource } else { 'DISA Windows 11 STIG' }) + ' / NIST SP 800-53 Rev.5'
    ScanPath = $ScanPath; Skipped = $Skip; ComparedTo = $CompareTo
}
$diff = Get-FindingDiff -Current $script:Findings -PrevJson $CompareTo
$result = [ordered]@{ Meta = $meta; Actions = (Get-TopActions $script:Findings); Diff = $diff; Inventory = $script:Inventory; Findings = $script:Findings }
$jsonPath = Join-Path $dir 'results.json'
[IO.File]::WriteAllText($jsonPath, ($result | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
$htmlPath = Join-Path $dir 'report.html'
[IO.File]::WriteAllText($htmlPath, (New-HtmlReport -Result $result), (New-Object Text.UTF8Encoding $false))

# --- 콘솔 요약 ------------------------------------------------------------------
$g = $script:Findings | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host "`n결과: $($g -join '  ')" -ForegroundColor Green
$top = $script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'CAT I' } | Select-Object -First 10
if ($top) { Write-Host 'CAT I FAIL:' -ForegroundColor Red; $top | ForEach-Object { Write-Host "  - [$($_.Id)] $($_.Title)" -ForegroundColor Red } }
if ($diff) { Write-Host "이전 회차 대비: 신규 문제 $(@($diff.New).Count)건, 해소 $(@($diff.Resolved).Count)건" -ForegroundColor Cyan }
Write-Host "보고서: $htmlPath"
if (-not $NoOpen) { Start-Process $htmlPath }
if ($Pause) { Read-Host "`n엔터를 누르면 창이 닫힙니다" | Out-Null }
