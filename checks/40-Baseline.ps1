# 3. 기초보안설정 - DISA Windows 11 STIG (data\controls.json) + 플랫폼 보안
# registry / secedit / userright / audit 형식은 데이터 기반, custom 은 아래 전용 스크립트블록이 처리한다.

function Get-SeceditExport {
    $tmp = Join-Path $env:TEMP "secedit-$PID.inf"
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet 2>$null
        if (-not (Test-Path $tmp)) { return $null }
        $sec = @{}; $cur = ''
        foreach ($line in (Get-Content $tmp -Encoding Unicode)) {
            if ($line -match '^\[(.+)\]$') { $cur = $Matches[1]; $sec[$cur] = @{}; continue }
            if ($line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $sec[$cur][$Matches[1]] = $Matches[2].Trim() }
        }
        $sec
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-AuditPolicy {
    $csv = & auditpol.exe /get /category:* /r 2>$null
    if (-not $csv -or $LASTEXITCODE -ne 0) { return $null }
    $map = @{}
    # 열 순서: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting, Setting Value
    foreach ($row in ($csv | Where-Object { $_ } | ConvertFrom-Csv -Header 'M', 'T', 'Sub', 'Guid', 'Inc', 'Exc', 'Val' | Select-Object -Skip 1)) {
        $g = ($row.Guid -replace '[{}]', '').Split('-')[0].ToUpperInvariant()
        $map[$g] = [pscustomobject]@{ Name = $row.Sub; Value = [int]$row.Val }   # 0 없음, 1 성공, 2 실패, 3 둘 다
    }
    $map
}

function Resolve-SidName([string]$sid) {
    if ($sid -notmatch '^S-1-') { return $sid }   # secedit 가 이름으로 내보낸 항목
    try { (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $sid }
}

# secedit 항목(*SID 또는 계정 이름) -> SID. 허용 목록이 SID 라 이름 그대로 비교하면 오판
function ConvertTo-Sid([string]$entry) {
    $e = $entry.Trim().TrimStart('*')
    if (-not $e -or $e -match '^S-1-') { return $e }
    try { (New-Object Security.Principal.NTAccount($e)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $e }
}

# splat 기본값 위에 상태별 값을 덮어써 기록 (splat 과 같은 이름 인자를 함께 주면 바인딩 오류)
function Send-StigFinding([hashtable]$Base, [hashtable]$Over) {
    $o = $Base.Clone(); foreach ($k in $Over.Keys) { $o[$k] = $Over[$k] }
    Add-Finding @o
}

function Invoke-CheckBaseline {
    param([bool]$IsAdmin, [string]$DataDir, [ValidateSet('Personal', 'Strict')][string]$AuditProfile = 'Personal')
    $cat = '3. 기초보안설정 (STIG)'
    Write-Step "STIG 기초보안설정 점검 (프로필: $AuditProfile)"

    $doc = Get-Content (Join-Path $DataDir 'controls.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $ov = Get-Content (Join-Path $DataDir 'stig-overrides.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $na = @{}; $adv = @{}
    if ($AuditProfile -eq 'Personal') {
        $ov.NA.PSObject.Properties | ForEach-Object { $na[$_.Name] = $_.Value }
        $ov.Advisory.PSObject.Properties | ForEach-Object { $adv[$_.Name] = $_.Value }
    }
    $secDef = @{}
    if ($AuditProfile -eq 'Personal' -and $ov.PSObject.Properties['SecureDefaults']) {
        $ov.SecureDefaults.PSObject.Properties | Where-Object Name -ne '_comment' | ForEach-Object { $secDef[$_.Name] = $_.Value }
    }
    # SMBv1 클라이언트 드라이버(mrxsmb10) 서비스 키 자체가 없으면 SMBv1 기능이 제거된 상태
    $smb1Removed = -not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10')
    # Device Guard 실제 실행 상태 (정책 키 없이 UI 로 켠 경우를 인정 - Personal 한정)
    $dgRun = @()
    $dgObj = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dgObj) { $dgRun = @($dgObj.SecurityServicesRunning); if ([int]$dgObj.VirtualizationBasedSecurityStatus -eq 2) { $dgRun += 'VBS' } }
    $effective = @{ 'WN11-CC-000070' = @('VBS', 'VBS 실행 중'); 'WN11-CC-000075' = @(1, 'Credential Guard 실행 중'); 'WN11-CC-000080' = @(2, 'HVCI(메모리 무결성) 실행 중') }
    $script:StigSource = "$($doc.Source.Stig) $($doc.Source.Version) ($($doc.Source.Release)), $($doc.Source.Cci)"

    $sec = if ($IsAdmin) { Get-SeceditExport } else { $null }
    $aud = if ($IsAdmin) { Get-AuditPolicy } else { $null }
    $custom = Get-CustomStigChecks -IsAdmin $IsAdmin

    foreach ($c in $doc.Controls) {
        $short = $c.Title
        $fa = @{ Id = $c.Id; Category = $cat; Title = $short; Severity = $c.Severity; STIG = $c.Id; NIST = @($c.NIST); Remediation = $c.Fix }
        if ($na.ContainsKey($c.Id)) { Send-StigFinding $fa @{ Status = 'N/A'; Severity = ''; Evidence = $na[$c.Id]; Remediation = '' }; continue }

        $res = $null   # @{ Pass = $true/$false/$null(SKIP); Evidence = '' }
        switch ($c.Type) {
            'registry' {
                $v = Get-RegValue $c.Hive $c.Path $c.Name
                $exp = Format-Expectation $c.Op $c.Expected
                if (-not $v.Exists) {
                    $missing = "$($c.Hive)\$($c.Path)\$($c.Name) 없음 (기대 $exp$(if ($c.MissingOk) { ', 없어도 됨' }))"
                    $res = @{ Pass = [bool]$c.MissingOk; Evidence = $missing }
                    if ($secDef.ContainsKey($c.Id) -and ($c.Id -notin 'WN11-00-000165', 'WN11-00-000170' -or $smb1Removed)) {
                        $res = @{ Pass = $true; Evidence = "$missing -> OS 기본값으로 충족: $($secDef[$c.Id])" }
                    }
                    elseif ($AuditProfile -eq 'Personal' -and $effective.ContainsKey($c.Id) -and $dgRun -contains $effective[$c.Id][0]) {
                        $res = @{ Pass = $true; Evidence = "$missing -> 정책 키는 없지만 $($effective[$c.Id][1]) (Win32_DeviceGuard)" }
                    }
                } else {
                    $actual = $v.Value
                    if ($c.ValueType -eq 'REG_SZ' -and $c.Op -ne 'eq') { $actual = [int64]"$actual" }
                    $ok = try { Test-Expectation $actual $c.Op $c.Expected } catch { $false }
                    $shown = if ($actual -is [array]) { $actual -join ' ' } else { "$actual" }
                    if ($shown.Length -gt 120) { $shown = $shown.Substring(0, 120) + '...' }
                    $res = @{ Pass = $ok; Evidence = "$($c.Name) = $shown (기대 $exp)" }
                }
            }
            'secedit' {
                if (-not $sec) { $res = @{ Pass = $null; Evidence = '관리자 권한 필요 (secedit /export)' }; break }
                $raw = $sec['System Access'][$c.Key]
                if ($null -eq $raw) { $res = @{ Pass = $false; Evidence = "$($c.Key) 미정의" }; break }
                $res = @{ Pass = (Test-Expectation ([int64]$raw) $c.Op $c.Expected); Evidence = "$($c.Key) = $raw (기대 $(Format-Expectation $c.Op $c.Expected))" }
            }
            'userright' {
                if (-not $sec) { $res = @{ Pass = $null; Evidence = '관리자 권한 필요 (secedit /export)' }; break }
                $raw = $sec['Privilege Rights'][$c.Right]
                $sids = @(if ($raw) { $raw.Split(',') | ForEach-Object { ConvertTo-Sid $_ } })
                $names = ($sids | ForEach-Object { Resolve-SidName $_ }) -join ', '
                if ($c.PSObject.Properties['MustInclude'] -and $c.MustInclude) {
                    $missing = @($c.MustInclude | Where-Object { $_ -notin $sids })
                    $res = @{ Pass = (-not $missing); Evidence = "$($c.Right) = [$names]$(if ($missing) { "; 누락: $(($missing | ForEach-Object { Resolve-SidName $_ }) -join ', ')" })" }
                } else {
                    $extra = @($sids | Where-Object { $_ -and $_ -notin @($c.Allow) })
                    $res = @{ Pass = (-not $extra); Evidence = "$($c.Right) = [$(if ($names) { $names } else { '없음' })]$(if ($extra) { "; 허용 외: $(($extra | ForEach-Object { Resolve-SidName $_ }) -join ', ')" })" }
                }
            }
            'audit' {
                if (-not $aud) { $res = @{ Pass = $null; Evidence = '관리자 권한 필요 (auditpol)' }; break }
                $fails = @(); $ev = @()
                foreach ($r in $c.Requires) {
                    $cur = $aud[$r.Guid]
                    $bit = if ($r.Flag -eq 'Success') { 1 } else { 2 }
                    $val = if ($cur) { $cur.Value } else { 0 }
                    $ev += "$($r.Subcategory) [$($r.Flag)] 현재=$(@('없음','성공','실패','성공및실패')[$val])"
                    if (-not ($val -band $bit)) { $fails += $r.Subcategory }
                }
                $res = @{ Pass = (-not $fails); Evidence = ($ev -join '; ') }
                $fa.Remediation = "auditpol /set /subcategory:`"{$($c.Requires[0].Guid)-69AE-11D9-BED3-505054503030}`" /$($c.Requires[0].Flag.ToLower()):enable  (관리자)"
            }
            'custom' {
                if ($custom.ContainsKey($c.Id)) {
                    $res = try { & $custom[$c.Id] } catch { @{ Pass = $null; Evidence = $(if ($_.Exception.Message -match 'elevation|권한') { '관리자 권한 필요' } else { "점검 실패: $($_.Exception.Message)" }) } }
                }
                else { $res = @{ Pass = $null; Evidence = '자동 점검 미구현 - STIG 점검문에 따라 수동 확인'; Manual = $true } }
            }
        }

        if ($null -eq $res.Pass) {
            $st = if ($res.Manual) { 'INFO' } else { 'SKIP' }
            Send-StigFinding $fa @{ Status = $st; Evidence = $res.Evidence }
            continue
        }
        if ($res.Pass) { Send-StigFinding $fa @{ Status = 'PASS'; Severity = ''; Evidence = $res.Evidence }; continue }
        if ($adv.ContainsKey($c.Id)) { Send-StigFinding $fa @{ Status = 'WARN'; Severity = 'CAT III'; Evidence = $res.Evidence; Note = "개인 PC 권고: $($adv[$c.Id])" }; continue }
        Send-StigFinding $fa @{ Status = 'FAIL'; Evidence = $res.Evidence }
    }

    # --- STIG 외 플랫폼 보안 (Microsoft Security Baseline / NIST) ----------------
    $pcat = '3. 기초보안설정 (플랫폼)'
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        $vbs = @('꺼짐', '활성(미실행)', '실행 중')[[int]$dg.VirtualizationBasedSecurityStatus]
        $hvci = @($dg.SecurityServicesRunning) -contains 2
        $cg = @($dg.SecurityServicesRunning) -contains 1
        Add-Finding -Id 'PLT-HVCI' -Category $pcat -Title '메모리 무결성(HVCI)·VBS 실행' -Status $(if ($hvci) { 'PASS' } else { 'FAIL' }) -Severity $(if ($hvci) { '' } else { 'CAT II' }) `
            -STIG 'WN11-CC-000080' -NIST @('SI-16', 'SC-39') -Evidence "VBS=$vbs, HVCI 실행=$hvci, Credential Guard 실행=$cg" `
            -Remediation '설정 > 개인 정보 및 보안 > Windows 보안 > 장치 보안 > 코어 격리 > 메모리 무결성 켜기 (재부팅)'
    }
    $lsaPpl = Get-RegValue HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    Add-Finding -Id 'PLT-LSAPPL' -Category $pcat -Title 'LSA 보호(RunAsPPL) - lsass 메모리 덤프 차단' -Status $(if ($lsaPpl.Value -in 1, 2) { 'PASS' } else { 'FAIL' }) -Severity $(if ($lsaPpl.Value -in 1, 2) { '' } else { 'CAT II' }) `
        -NIST @('IA-5', 'SC-39', 'AC-6') -Evidence "RunAsPPL = $(if ($lsaPpl.Exists) { $lsaPpl.Value } else { '없음' })" `
        -Remediation 'Windows 보안 > 장치 보안 > 코어 격리 > 로컬 보안 기관 보호 켜기, 또는 reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 2 /f (재부팅)'

    $smb1 = Get-RegValue HKLM 'SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
    $ps2 = Get-RegValue HKLM 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion'
    Add-Finding -Id 'PLT-LEGACY' -Category $pcat -Title '레거시 구성요소 (SMBv1 클라이언트·PowerShell 2.0 엔진)' -Status $(if (($smb1.Exists -and $smb1.Value -ne 4) -or $ps2.Value -eq '2.0') { 'FAIL' } else { 'PASS' }) `
        -STIG 'WN11-00-000155' -NIST @('CM-7') -Evidence "mrxsmb10 Start=$(if ($smb1.Exists) { $smb1.Value } else { '없음(미설치)' }), PS 2.0 엔진=$(if ($ps2.Value -eq '2.0') { '설치' } else { '없음' })" `
        -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol,MicrosoftWindowsPowerShellV2Root (관리자)'

    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hl = @(Get-Content $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' })
    $hsus = @($hl | Where-Object { $_ -match '(?i)(microsoft|windowsupdate|google|github|anthropic|openai|bank|naver|kakao|defender|virustotal)' -and $_ -notmatch '^\s*(0\.0\.0\.0|127\.0\.0\.1)\s' })
    Add-Finding -Id 'PLT-HOSTS' -Category $pcat -Title "hosts 파일 항목 ($($hl.Count)개)" -Status $(if ($hsus) { 'FAIL' } elseif ($hl) { 'INFO' } else { 'PASS' }) -Severity $(if ($hsus) { 'CAT I' } else { '' }) `
        -NIST @('SI-7', 'SC-20') -Evidence $(if ($hl) { ($hl | Select-Object -First 30) -join "`n" } else { '주석 외 항목 없음' }) -Remediation '주요 도메인을 다른 IP 로 돌리는 항목은 피싱·업데이트 차단형 악성코드 흔적. 모르면 삭제'

    $osv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $lastHf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $age = if ($lastHf) { [int]((Get-Date) - $lastHf.InstalledOn).TotalDays } else { 999 }
    Add-Finding -Id 'PLT-UPDATE' -Category $pcat -Title '최근 업데이트 설치' -Status $(if ($age -le 35) { 'PASS' } elseif ($age -le 60) { 'WARN' } else { 'FAIL' }) -Severity $(if ($age -le 35) { '' } else { 'CAT II' }) `
        -STIG 'WN11-00-000040' -NIST @('SI-2') -Evidence "$($osv.DisplayVersion) build $($osv.CurrentBuild).$($osv.UBR), 마지막 핫픽스 $($lastHf.HotFixID) $($lastHf.InstalledOn) ($age 일 전)" `
        -Remediation '설정 > Windows 업데이트 > 업데이트 확인. 월간 보안 업데이트(둘째 주 화요일) 후 2주 안에 적용'
}

# STIG custom 항목 전용 점검 (반환: @{ Pass; Evidence })
function Get-CustomStigChecks([bool]$IsAdmin) {
    $feat = $null
    if ($IsAdmin) { $feat = @{}; Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | ForEach-Object { $feat[$_.FeatureName] = [string]$_.State } }
    $featCheck = {
        param([string[]]$names, [string]$label)
        if ($null -eq $feat) { return @{ Pass = $null; Evidence = "관리자 권한 필요 (Get-WindowsOptionalFeature: $label)" } }
        $on = @($names | Where-Object { $feat[$_] -eq 'Enabled' })
        @{ Pass = (-not $on); Evidence = $(if ($on) { "활성: $($on -join ', ')" } else { "$label 미설치/비활성" }) }
    }.GetNewClosure()
    $script:FeatState = $feat; $script:FeatCheck = $featCheck

    @{
        'WN11-00-000010' = { $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
            if (-not $t) { if (-not (Test-IsAdmin)) { return @{ Pass = $null; Evidence = '관리자 권한 필요 (Win32_Tpm)' } }; return @{ Pass = $false; Evidence = 'TPM 없음' } }
            @{ Pass = ($t.IsEnabled_InitialValue -and $t.IsActivated_InitialValue); Evidence = "TPM $($t.SpecVersion.Split(',')[0]) Enabled=$($t.IsEnabled_InitialValue) Activated=$($t.IsActivated_InitialValue)" } }
        'WN11-00-000015' = { @{ Pass = ($env:firmware_type -eq 'UEFI'); Evidence = "펌웨어 = $env:firmware_type" } }
        'WN11-00-000020' = { $sb = Get-RegValue HKLM 'SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
            @{ Pass = ($sb.Value -eq 1); Evidence = "UEFISecureBootEnabled = $($sb.Value)" } }
        'WN11-00-000030' = {
            # Home: BitLocker 관리 도구가 없으므로 장치 암호화(Device Encryption) 상태로 확인
            $vol = Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue | Where-Object DriveLetter -eq $env:SystemDrive
            if ($vol) { $ps = (Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus).ProtectionStatus
                return @{ Pass = ($ps -eq 1); Evidence = "$env:SystemDrive 보호 상태 = $(@('꺼짐','켜짐','알 수 없음')[[int]$ps]) (BitLocker/장치 암호화)" } }
            $mbde = (& manage-bde.exe -status $env:SystemDrive 2>$null) -join ' '
            if ($mbde -match '(Protection On|보호 켜짐)') { return @{ Pass = $true; Evidence = 'manage-bde: 보호 켜짐' } }
            if ($mbde -match '(Protection Off|보호 꺼짐)') { return @{ Pass = $false; Evidence = 'manage-bde: 보호 꺼짐' } }
            @{ Pass = $null; Evidence = '관리자 권한 필요 - 설정 > 개인 정보 및 보안 > 장치 암호화 에서 수동 확인' } }
        'WN11-00-000040' = { $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            # 23H2(22631) 이상을 지원 버전으로 본다 (Home/Pro 기준 22H2 는 2024-10 지원 종료)
            @{ Pass = ([int]$v.CurrentBuild -ge 22631); Evidence = "$($v.DisplayVersion) build $($v.CurrentBuild).$($v.UBR)" } }
        'WN11-00-000045' = { $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object displayName)
            @{ Pass = [bool]($mp.AntivirusEnabled -or $av); Evidence = "등록 백신: $($av -join ', '); Defender 실시간=$($mp.RealTimeProtectionEnabled)" } }
        'WN11-00-000050' = { $bad = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -notin 'NTFS', 'ReFS' })
            @{ Pass = (-not $bad); Evidence = $(if ($bad) { ($bad | ForEach-Object { "$($_.DriveLetter): $($_.FileSystem)" }) -join ', ' } else { '고정 디스크 모두 NTFS/ReFS' }) } }
        'WN11-00-000065' = { $u = @(Get-LocalUser | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-35) })
            @{ Pass = (-not $u); Evidence = $(if ($u) { ($u | ForEach-Object { "$($_.Name) 마지막 로그온 $($_.LastLogon)" }) -join ', ' } else { '35일 이상 미사용 활성 계정 없음' }) } }
        'WN11-00-000070' = { $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)
            @{ Pass = ($m.Count -le 2); Evidence = "Administrators: $(($m | ForEach-Object Name) -join ', ')" } }
        'WN11-00-000075' = { $m = @(Get-LocalGroupMember -SID 'S-1-5-32-551' -ErrorAction SilentlyContinue)
            @{ Pass = (-not $m); Evidence = "Backup Operators: $(if ($m) { ($m | ForEach-Object Name) -join ', ' } else { '없음' })" } }
        'WN11-00-000090' = { $u = @(Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordExpires -and $_.PrincipalSource -eq 'Local' })
            @{ Pass = (-not $u); Evidence = $(if ($u) { "만료 없음: $(($u | ForEach-Object Name) -join ', ')" } else { '로컬 활성 계정 모두 암호 만료 설정' }) } }
        'WN11-00-000100' = { & $script:FeatCheck @('IIS-WebServerRole', 'IIS-WebServer', 'IIS-HostableWebCore') 'IIS' }
        'WN11-00-000105' = { $c = Get-WindowsCapability -Online -Name 'SNMP.Client*' -ErrorAction SilentlyContinue
            if ($null -eq $c) { if (-not $IsAdmin) { return @{ Pass = $null; Evidence = '관리자 권한 필요 (Get-WindowsCapability)' } } }
            $on = @($c | Where-Object State -eq 'Installed'); @{ Pass = (-not $on); Evidence = $(if ($on) { 'SNMP 설치됨' } else { 'SNMP 미설치' }) } }
        'WN11-00-000110' = { & $script:FeatCheck @('SimpleTCP') 'Simple TCP/IP Services' }
        'WN11-00-000115' = { & $script:FeatCheck @('TelnetClient') 'Telnet Client' }
        'WN11-00-000120' = { & $script:FeatCheck @('TFTP') 'TFTP Client' }
        'WN11-00-000135' = { $fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue); @{ Pass = ($fw -and -not ($fw | Where-Object { -not $_.Enabled })); Evidence = ($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ' } }
        'WN11-00-000155' = { & $script:FeatCheck @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root') 'PowerShell 2.0' }
        'WN11-00-000160' = { & $script:FeatCheck @('SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server') 'SMBv1' }
        'WN11-00-000175' = { $s = Get-Service seclogon -ErrorAction SilentlyContinue; @{ Pass = ($s.StartType -eq 'Disabled'); Evidence = "seclogon StartType=$($s.StartType) Status=$($s.Status)" } }
        'WN11-00-000190' = { if (-not $IsAdmin) { return @{ Pass = $null; Evidence = '관리자 권한 필요' } }
            $sec = Get-SeceditExport; $orph = foreach ($kv in $sec['Privilege Rights'].GetEnumerator()) { foreach ($s in $kv.Value.Split(',')) { $s = $s.Trim().TrimStart('*'); if ($s -match '^S-1-5-21-' -and (Resolve-SidName $s) -eq $s) { "$($kv.Key): $s" } } }
            @{ Pass = (-not $orph); Evidence = $(if ($orph) { $orph -join '; ' } else { '고아 SID 없음' }) } }
        'WN11-00-000230' = { @{ Pass = $null; Evidence = '블루투스 연결 알림 - 설정 > Bluetooth 및 장치에서 수동 확인'; Manual = $true } }
        'WN11-00-000395' = { $k = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'; @{ Pass = (-not $k); Evidence = $(if ($k) { 'PortProxy\v4tov4\tcp 키 존재' } else { 'PortProxy 설정 없음' }) } }
        'WN11-00-000125' = { $a = @(Get-AppxPackage -Name '*Copilot*' -ErrorAction SilentlyContinue); @{ Pass = (-not $a); Evidence = $(if ($a) { ($a | ForEach-Object Name) -join ', ' } else { 'Copilot 앱 없음' }) } }
        'WN11-AU-000515' = { @{ Pass = $null; Evidence = '이벤트 로그 파일 권한 - icacls %SystemRoot%\System32\winevt\Logs\Application.evtx 로 수동 확인'; Manual = $true } }
        'WN11-AU-000520' = { @{ Pass = $null; Evidence = 'icacls %SystemRoot%\System32\winevt\Logs\Security.evtx 로 수동 확인'; Manual = $true } }
        'WN11-AU-000525' = { @{ Pass = $null; Evidence = 'icacls %SystemRoot%\System32\winevt\Logs\System.evtx 로 수동 확인'; Manual = $true } }
        'WN11-CC-000007' = { $cam = @(Get-PnpDevice -Class Camera, Image -PresentOnly -ErrorAction SilentlyContinue | Where-Object Status -eq 'OK'); @{ Pass = (-not $cam); Evidence = $(if ($cam) { "활성 카메라: $(($cam | ForEach-Object FriendlyName) -join ', ') - 물리 덮개 사용 시 무시" } else { '활성 카메라 없음' }) } }
        'WN11-CC-000039' = { $keys = 'batfile', 'cmdfile', 'exefile', 'mscfile' | ForEach-Object { (Get-RegValue HKLM "SOFTWARE\Classes\$_\shell\runasuser" 'SuppressionPolicy').Value }
            $ok = -not ($keys | Where-Object { $_ -ne 4096 }); @{ Pass = $ok; Evidence = "runasuser SuppressionPolicy = $($keys -join ',') (기대 4096)" } }
        'WN11-CC-000391' = { $ie = Test-Path "$env:ProgramFiles\Internet Explorer\iexplore.exe"; $f = if ($script:FeatState) { $script:FeatState['Internet-Explorer-Optional-amd64'] } else { $null }
            @{ Pass = ($f -ne 'Enabled'); Evidence = "IE 기능 상태=$(if ($f) { $f } else { '확인불가/없음' }), iexplore.exe 존재=$ie (Win11 은 기본 비활성)" } }
        'WN11-SO-000020' = { $a = Get-LocalUser | Where-Object { $_.SID -like '*-500' }; @{ Pass = ($a.Name -ne 'Administrator'); Evidence = "기본 관리자 이름 = $($a.Name), 활성=$($a.Enabled)" } }
        'WN11-SO-000025' = { $g = Get-LocalUser | Where-Object { $_.SID -like '*-501' }; @{ Pass = ($g.Name -ne 'Guest'); Evidence = "기본 게스트 이름 = $($g.Name), 활성=$($g.Enabled)" } }
        'WN11-EP-000310' = { $d = Get-RegValue HKLM 'SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' 'DeviceEnumerationPolicy'
            @{ Pass = ($d.Exists -and $d.Value -eq 0); Evidence = "DeviceEnumerationPolicy = $(if ($d.Exists) { $d.Value } else { '없음' }) (기대 0) - msinfo32 '커널 DMA 보호' 항목도 확인" } }
    }
}
