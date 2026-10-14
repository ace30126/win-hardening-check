<#
.SYNOPSIS
  DISA Windows 11 STIG XCCDF + DISA CCI List -> data\controls.json

.DESCRIPTION
  STIG 원문에서 레지스트리 점검(Hive/Path/ValueName/Type/Value)과 감사 정책(Category >> Subcategory - Success|Failure)을
  기계적으로 추출하고, CCI 를 NIST SP 800-53 Rev.5 통제로 변환해 controls.json 을 만든다.
  사용자 권한(UR)·계정 정책(AC)·기타 항목은 아래 $Manual 표로 기대값을 정의한다(STIG 제목·점검문 기준).
  개인 PC(Home, 비도메인)에 맞춘 적용성은 data\stig-overrides.json 에서 관리한다.

  원문 출처
    - STIG : DISA "Microsoft Windows 11 STIG" XCCDF (Microsoft PowerStig 저장소 보관본
             https://github.com/microsoft/PowerStig/tree/dev/source/StigData/Archive/Windows.Client)
    - CCI  : DISA U_CCI_List.xml (https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip)

.EXAMPLE
  .\tools\Build-Controls.ps1 -StigXml .\src\U_MS_Windows_11_STIG_V2R7_Manual-xccdf.xml -CciXml .\src\U_CCI_List.xml
#>
param(
    [Parameter(Mandatory)][string]$StigXml,
    [Parameter(Mandatory)][string]$CciXml,
    [string]$OutFile = (Join-Path $PSScriptRoot '..\data\controls.json')
)
$ErrorActionPreference = 'Stop'

# --- CCI -> NIST 800-53 Rev.5 ---------------------------------------------------
[xml]$cci = Get-Content $CciXml -Raw -Encoding UTF8
$cciMap = @{}
foreach ($item in $cci.cci_list.cci_items.cci_item) {
    $rev5 = $item.references.reference | Where-Object { $_.title -eq 'NIST SP 800-53 Revision 5' } | Select-Object -First 1
    if ($rev5) { $cciMap[$item.id] = ($rev5.index -replace '\s.*$', '') }   # "CM-6 b" -> "CM-6"
}

# --- STIG ---------------------------------------------------------------------
[xml]$x = Get-Content $StigXml -Raw -Encoding UTF8
$ns = @{ x = 'http://checklists.nist.gov/xccdf/1.1' }
$release = ($x.Benchmark.'plain-text' | Where-Object { $_.id -eq 'release-info' }).'#text'
$version = $x.Benchmark.version
$rules = Select-Xml -Xml $x -XPath '//x:Rule' -Namespace $ns | ForEach-Object Node

$sevMap = @{ high = 'CAT I'; medium = 'CAT II'; low = 'CAT III' }
$regRx = 'Registry Hive:\s*(HKEY_\w+)\s*Registry Path:\s*([^\r\n]+?)\s*[\r\n]+\s*Value Name:\s*([^\r\n]+?)\s*[\r\n]+\s*(?:Value )?Type:\s*(REG_\w+)\s*Value(?: data)?:\s*([^\r\n]*)'

# 감사 하위 범주 이름 -> GUID (MS-GPAC 2.2.1.2; auditpol 출력은 지역화되므로 GUID 로 비교)
$auditGuid = @{
    'Credential Validation' = '0CCE923F'; 'Kerberos Authentication Service' = '0CCE9242'; 'Kerberos Service Ticket Operations' = '0CCE9240'; 'Other Account Logon Events' = '0CCE9241'
    'Application Group Management' = '0CCE9239'; 'Computer Account Management' = '0CCE9236'; 'Distribution Group Management' = '0CCE9238'; 'Other Account Management Events' = '0CCE923A'
    'Security Group Management' = '0CCE9237'; 'User Account Management' = '0CCE9235'
    'DPAPI Activity' = '0CCE922D'; 'Plug and Play Events' = '0CCE9248'; 'Process Creation' = '0CCE922B'; 'Process Termination' = '0CCE922C'; 'RPC Events' = '0CCE922E'; 'Token Right Adjusted Events' = '0CCE924A'
    'Account Lockout' = '0CCE9217'; 'Group Membership' = '0CCE9249'; 'Logoff' = '0CCE9216'; 'Logon' = '0CCE9215'; 'Other Logon/Logoff Events' = '0CCE921C'; 'Special Logon' = '0CCE921B'
    'IPsec Main Mode' = '0CCE9218'; 'IPsec Quick Mode' = '0CCE9219'; 'IPsec Extended Mode' = '0CCE921A'; 'Network Policy Server' = '0CCE9243'; 'User / Device Claims' = '0CCE9247'
    'Application Generated' = '0CCE9222'; 'Certification Services' = '0CCE9221'; 'Detailed File Share' = '0CCE9244'; 'File Share' = '0CCE9224'; 'File System' = '0CCE921D'
    'Filtering Platform Connection' = '0CCE9226'; 'Filtering Platform Packet Drop' = '0CCE9225'; 'Handle Manipulation' = '0CCE9223'; 'Kernel Object' = '0CCE921F'
    'Other Object Access Events' = '0CCE9227'; 'Registry' = '0CCE921E'; 'Removable Storage' = '0CCE9245'; 'SAM' = '0CCE9220'; 'Central Policy Staging' = '0CCE9246'
    'Audit Policy Change' = '0CCE922F'; 'Authentication Policy Change' = '0CCE9230'; 'Authorization Policy Change' = '0CCE9231'; 'Filtering Platform Policy Change' = '0CCE9233'
    'MPSSVC Rule-Level Policy Change' = '0CCE9232'; 'Other Policy Change Events' = '0CCE9234'
    'Non Sensitive Privilege Use' = '0CCE9229'; 'Other Privilege Use Events' = '0CCE922A'; 'Sensitive Privilege Use' = '0CCE9228'
    'IPsec Driver' = '0CCE9213'; 'Other System Events' = '0CCE9214'; 'Security State Change' = '0CCE9210'; 'Security System Extension' = '0CCE9211'; 'System Integrity' = '0CCE9212'
}

# 사용자 권한: STIG 제목 기준 허용(Allow) 또는 필수 포함(MustInclude) SID
$S = @{ Adm = 'S-1-5-32-544'; Users = 'S-1-5-32-545'; Guests = 'S-1-5-32-546'; RDU = 'S-1-5-32-555'; Svc = 'S-1-5-6'; LS = 'S-1-5-19'; NS = 'S-1-5-20' }
$Manual = @{
    'WN11-UR-000005' = @{ Type = 'userright'; Right = 'SeTrustedCredManAccessPrivilege'; Allow = @() }
    'WN11-UR-000010' = @{ Type = 'userright'; Right = 'SeNetworkLogonRight'; Allow = @($S.Adm, $S.RDU) }
    'WN11-UR-000015' = @{ Type = 'userright'; Right = 'SeTcbPrivilege'; Allow = @() }
    'WN11-UR-000025' = @{ Type = 'userright'; Right = 'SeInteractiveLogonRight'; Allow = @($S.Adm, $S.Users) }
    'WN11-UR-000030' = @{ Type = 'userright'; Right = 'SeBackupPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000035' = @{ Type = 'userright'; Right = 'SeSystemtimePrivilege'; Allow = @($S.Adm, $S.LS) }
    'WN11-UR-000040' = @{ Type = 'userright'; Right = 'SeCreatePagefilePrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000045' = @{ Type = 'userright'; Right = 'SeCreateTokenPrivilege'; Allow = @() }
    'WN11-UR-000050' = @{ Type = 'userright'; Right = 'SeCreateGlobalPrivilege'; Allow = @($S.Adm, $S.Svc, $S.LS, $S.NS) }
    'WN11-UR-000055' = @{ Type = 'userright'; Right = 'SeCreatePermanentPrivilege'; Allow = @() }
    'WN11-UR-000060' = @{ Type = 'userright'; Right = 'SeCreateSymbolicLinkPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000065' = @{ Type = 'userright'; Right = 'SeDebugPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000070' = @{ Type = 'userright'; Right = 'SeDenyNetworkLogonRight'; MustInclude = @($S.Guests) }
    'WN11-UR-000085' = @{ Type = 'userright'; Right = 'SeDenyInteractiveLogonRight'; MustInclude = @($S.Guests) }
    'WN11-UR-000090' = @{ Type = 'userright'; Right = 'SeDenyRemoteInteractiveLogonRight'; MustInclude = @($S.Guests) }
    'WN11-UR-000095' = @{ Type = 'userright'; Right = 'SeEnableDelegationPrivilege'; Allow = @() }
    'WN11-UR-000100' = @{ Type = 'userright'; Right = 'SeRemoteShutdownPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000110' = @{ Type = 'userright'; Right = 'SeImpersonatePrivilege'; Allow = @($S.Adm, $S.Svc, $S.LS, $S.NS) }
    'WN11-UR-000120' = @{ Type = 'userright'; Right = 'SeLoadDriverPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000125' = @{ Type = 'userright'; Right = 'SeLockMemoryPrivilege'; Allow = @() }
    'WN11-UR-000130' = @{ Type = 'userright'; Right = 'SeSecurityPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000140' = @{ Type = 'userright'; Right = 'SeSystemEnvironmentPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000145' = @{ Type = 'userright'; Right = 'SeManageVolumePrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000150' = @{ Type = 'userright'; Right = 'SeProfileSingleProcessPrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000160' = @{ Type = 'userright'; Right = 'SeRestorePrivilege'; Allow = @($S.Adm) }
    'WN11-UR-000165' = @{ Type = 'userright'; Right = 'SeTakeOwnershipPrivilege'; Allow = @($S.Adm) }
    # 계정 정책 (secedit [System Access])
    'WN11-AC-000005' = @{ Type = 'secedit'; Key = 'LockoutDuration'; Op = 'ge'; Expected = 15 }
    'WN11-AC-000010' = @{ Type = 'secedit'; Key = 'LockoutBadCount'; Op = 'le_nz'; Expected = 3 }
    'WN11-AC-000015' = @{ Type = 'secedit'; Key = 'ResetLockoutCount'; Op = 'ge'; Expected = 15 }
    'WN11-AC-000020' = @{ Type = 'secedit'; Key = 'PasswordHistorySize'; Op = 'ge'; Expected = 24 }
    'WN11-AC-000025' = @{ Type = 'secedit'; Key = 'MaximumPasswordAge'; Op = 'le_nz'; Expected = 60 }
    'WN11-AC-000030' = @{ Type = 'secedit'; Key = 'MinimumPasswordAge'; Op = 'ge'; Expected = 1 }
    'WN11-AC-000035' = @{ Type = 'secedit'; Key = 'MinimumPasswordLength'; Op = 'ge'; Expected = 14 }
    'WN11-AC-000040' = @{ Type = 'secedit'; Key = 'PasswordComplexity'; Op = 'eq'; Expected = 1 }
    'WN11-AC-000045' = @{ Type = 'secedit'; Key = 'ClearTextPassword'; Op = 'eq'; Expected = 0 }
    'WN11-SO-000010' = @{ Type = 'secedit'; Key = 'EnableGuestAccount'; Op = 'eq'; Expected = 0 }
    'WN11-SO-000005' = @{ Type = 'secedit'; Key = 'EnableAdminAccount'; Op = 'eq'; Expected = 0 }
    'WN11-SO-000140' = @{ Type = 'secedit'; Key = 'LSAAnonymousNameLookup'; Op = 'eq'; Expected = 0 }
}

function ConvertTo-Expectation([string]$type, [string]$raw) {
    $missingOk = $raw -match 'does not exist'
    if ($type -in 'REG_DWORD', 'REG_QWORD') {
        $nums = [regex]::Matches($raw, '\((\d+)\)') | ForEach-Object { [int64]$_.Groups[1].Value }
        if (-not $nums) { $nums = [regex]::Matches($raw, '(?<![x\w])(\d+)(?!\w)') | ForEach-Object { [int64]$_.Groups[1].Value } }
        $nums = @($nums)
        if ($raw -match 'or greater')               { return @{ Op = 'ge'; Expected = $nums[0]; MissingOk = $missingOk } }
        if ($raw -match 'or less, excluding')       { return @{ Op = 'le_nz'; Expected = $nums[0]; MissingOk = $missingOk } }
        if ($raw -match 'or less')                  { return @{ Op = 'le'; Expected = $nums[0]; MissingOk = $missingOk } }
        if ($nums.Count -gt 1 -and $raw -match '\bor\b') { return @{ Op = 'in'; Expected = $nums; MissingOk = $missingOk } }
        return @{ Op = 'eq'; Expected = $nums[0]; MissingOk = $missingOk }
    }
    if ($raw -match '^(\d+) \(or less\)') { return @{ Op = 'le'; Expected = [int64]$Matches[1]; MissingOk = $missingOk; Numeric = $true } }
    return @{ Op = 'eq'; Expected = $raw.Trim(); MissingOk = $missingOk }
}

$controls = foreach ($r in $rules) {
    $cc   = [string]$r.check.'check-content'
    $ccis = @($r.ident | Where-Object { $_.system -match 'cci' } | ForEach-Object '#text')
    $nist = @($ccis | ForEach-Object { $cciMap[$_] } | Where-Object { $_ } | Sort-Object -Unique)
    $fix  = ([string]$r.fixtext.'#text').Trim()
    $base = [ordered]@{
        Id = $r.version; Severity = $sevMap[[string]$r.severity]; Title = [string]$r.title
        CCI = $ccis; NIST = $nist; Fix = $fix
    }
    if ($Manual.ContainsKey($r.version)) {
        foreach ($k in $Manual[$r.version].Keys) { $base[$k] = $Manual[$r.version][$k] }
    }
    elseif (($m = [regex]::Match($cc, $regRx)).Success) {
        $e = ConvertTo-Expectation $m.Groups[4].Value $m.Groups[5].Value
        $base.Type = 'registry'
        $base.Hive = if ($m.Groups[1].Value -eq 'HKEY_CURRENT_USER') { 'HKCU' } else { 'HKLM' }
        $base.Path = $m.Groups[2].Value.Trim().Trim('\')
        $base.Name = $m.Groups[3].Value.Trim()
        $base.ValueType = $m.Groups[4].Value
        foreach ($k in $e.Keys) { $base[$k] = $e[$k] }
    }
    elseif ($cc -match '>>\s*[^\r\n]+?\s*-\s*(Success|Failure)') {
        $req = foreach ($a in [regex]::Matches($cc, '>>\s*([^\r\n>]+?)\s*-\s*(Success|Failure)')) {
            $name = $a.Groups[1].Value.Trim()
            if ($auditGuid.ContainsKey($name)) { [ordered]@{ Subcategory = $name; Guid = $auditGuid[$name]; Flag = $a.Groups[2].Value } }
            else { Write-Warning "$($r.version): 감사 하위 범주 GUID 미정의 '$name'" }
        }
        $base.Type = 'audit'; $base.Requires = @($req)
    }
    elseif (($m = [regex]::Match($cc, 'If "Audit ([^"]+)" is not set to "(Success|Failure)"')).Success -and $auditGuid.ContainsKey($m.Groups[1].Value)) {
        $base.Type = 'audit'
        $base.Requires = @([ordered]@{ Subcategory = $m.Groups[1].Value; Guid = $auditGuid[$m.Groups[1].Value]; Flag = $m.Groups[2].Value })
    }
    else { $base.Type = 'custom' }    # checks\40-Baseline.ps1 의 전용 함수가 처리하거나 수동 확인
    [pscustomobject]$base
}

$doc = [ordered]@{
    Source = [ordered]@{ Stig = $x.Benchmark.title; Version = "V$($version)"; Release = $release; Cci = "U_CCI_List $($cci.cci_list.metadata.version)" }
    Generated = (Get-Date).ToString('s')
    Controls = @($controls)
}
$json = $doc | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Resolve-Path (Split-Path $OutFile)).Path + '\' + (Split-Path $OutFile -Leaf), $json, (New-Object Text.UTF8Encoding $false))
$controls | Group-Object Type | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "-> $OutFile ($($controls.Count) rules, $release)"
