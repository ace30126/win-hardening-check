# 4. 원격 접속 - Chrome 원격 데스크톱 + 기타 원격 도구 (NIST AC-17, AC-12, AC-2, CM-7)
# 정책 근거: Chrome Enterprise 정책 목록 RemoteAccessHost* (https://chromeenterprise.google/policies/#RemoteAccess)

function Invoke-CheckRemoteAccess {
    param([bool]$IsAdmin)
    $cat = '4. 원격 접속'
    Write-Step '원격 접속 도구 점검'

    # --- Chrome 원격 데스크톱 호스트 ------------------------------------------
    $svc = Get-CimInstance Win32_Service -Filter "Name='chromoting'" -ErrorAction SilentlyContinue
    if ($svc) {
        $exe = Resolve-ExecutablePath $svc.PathName
        $sig = Get-SignatureInfo $exe
        $ver = if ($exe -and (Test-Path $exe)) { (Get-Item $exe).VersionInfo.ProductVersion } else { '' }
        Add-Finding -Id 'RA-CRD-SVC' -Category $cat -Title 'Chrome 원격 데스크톱 호스트 서비스' -Status $(if ($sig.Status -eq 'Valid' -and $sig.Signer -match 'Google') { 'INFO' } else { 'FAIL' }) `
            -Severity $(if ($sig.Status -eq 'Valid') { '' } else { 'CAT I' }) -NIST @('AC-17', 'SI-7') `
            -Evidence "상태=$($svc.State) 시작=$($svc.StartMode) 계정=$($svc.StartName) 버전=$ver 서명=$($sig.Status): $($sig.Signer)`n$exe" `
            -Remediation '원격을 쓰지 않는 기간에는 서비스 중지: Stop-Service chromoting; Set-Service chromoting -StartupType Manual (관리자). 버전은 Chrome 이 자동 업데이트'

        $dir = Join-Path $env:ProgramData 'Google\Chrome Remote Desktop'
        $hostJson = Join-Path $dir 'host.json'
        if (Test-Path $hostJson) {
            # host.json 에는 호스트 개인키·PIN 해시가 있다. 일반 사용자 권한으로 읽히면 안 된다.
            $readable = $false
            if (-not $IsAdmin) { try { $null = [IO.File]::ReadAllBytes($hostJson); $readable = $true } catch { } }
            $broad = @(Get-BroadReadAce $hostJson)
            $st = if ($readable -or $broad) { 'FAIL' } else { 'PASS' }
            Add-Finding -Id 'RA-CRD-HOSTCFG' -Category $cat -Title 'CRD 호스트 설정(host.json: 호스트 개인키·PIN 해시) 접근 제한' -Status $st -Severity $(if ($st -eq 'FAIL') { 'CAT I' } else { '' }) `
                -NIST @('AC-3', 'IA-5', 'SC-28') -Evidence $(if ($st -eq 'PASS') { "일반 사용자 읽기 거부됨 ($((Get-Item $hostJson).LastWriteTime) 등록)" } else { "일반 사용자 읽기 가능: $($broad -join ', ')" }) `
                -Remediation 'icacls 로 SYSTEM·Administrators 만 남기고, 의심되면 원격 호스트를 삭제 후 재등록(PIN 변경)'
        }
        $unpriv = Join-Path $dir 'host_unprivileged.json'
        if (Test-Path $unpriv) {
            try {
                $u = Get-Content $unpriv -Raw | ConvertFrom-Json
                $owner = [string]$u.xmpp_login
                $maskedOwner = if ($owner -match '^(.{2}).*(@.+)$') { "$($Matches[1])***$($Matches[2])" } else { $owner }
                Add-Finding -Id 'RA-CRD-OWNER' -Category $cat -Title 'CRD 호스트 소유 계정' -Status INFO -NIST @('AC-2', 'AC-17') `
                    -Evidence "소유 계정=$maskedOwner, host_id=$(Get-MaskedSecret ([string]$u.host_id))" `
                    -Remediation '본인 계정이 아니면 즉시 remotedesktop.google.com/access 에서 기기 삭제. 이 Google 계정은 2단계 인증(보안 키·패스키 권장) 필수'
            } catch { }
        }

        # 정책 (HKLM\SOFTWARE\Policies\Google\Chrome)
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue
        $want = [ordered]@{
            'RemoteAccessHostAllowRemoteSupportConnections' = @{ Want = 0; Why = '일회성 지원 코드 접속 차단 - "원격 지원" 사칭 사기의 주 경로' }
            'RemoteAccessHostAllowClientPairing'           = @{ Want = 0; Why = '접속 기기에 PIN 기억(페어링) 금지 - 매번 PIN 요구' }
            'RemoteAccessHostAllowFileTransfer'            = @{ Want = 0; Why = '파일 전송이 필요 없으면 차단 (유출·악성 파일 반입 경로)' }
            'RemoteAccessHostMaximumSessionDurationMinutes' = @{ Want = 'le480'; Why = '세션 최대 시간 제한 (AC-12 세션 종료)' }
            'RemoteAccessHostClipboardSizeBytes'           = @{ Want = 'set'; Why = '클립보드 동기화 크기 제한 (0 이면 차단) - 키·암호가 클립보드로 넘어감' }
            'RemoteAccessHostRequireCurtain'               = @{ Want = 1; Why = '커튼 모드 - 원격 중 실제 화면을 가림(옆 사람이 못 봄). Windows 는 RDP 구성 필요해 선택' }
        }
        foreach ($k in $want.Keys) {
            $w = $want[$k]
            $v = if ($pol -and $pol.PSObject.Properties[$k]) { $pol.$k } else { $null }
            $ok = switch -Regex ([string]$w.Want) {
                '^le(\d+)$' { $null -ne $v -and [int]$v -gt 0 -and [int]$v -le [int]$Matches[1] }
                '^set$'     { $null -ne $v }
                default     { $null -ne $v -and [int]$v -eq [int]$w.Want }
            }
            $wantShown = switch -Regex ([string]$w.Want) { '^le(\d+)$' { "1..$($Matches[1])" } '^set$' { '설정(예: 0 또는 1024)' } default { $w.Want } }
            $regType = 'REG_DWORD'
            $setVal = switch -Regex ([string]$w.Want) { '^le(\d+)$' { $Matches[1] } '^set$' { '0' } default { $w.Want } }
            $sev = if ($k -match 'RemoteSupport|ClientPairing') { 'CAT II' } else { 'CAT III' }
            Add-Finding -Id "RA-CRD-$($k -replace 'RemoteAccessHost', '')" -Category $cat -Title "CRD 정책 $k" -Status $(if ($ok) { 'PASS' } elseif ($k -notmatch 'RemoteSupport|ClientPairing') { 'WARN' } else { 'FAIL' }) `
                -Severity $(if ($ok) { '' } else { $sev }) -NIST @('AC-17', 'AC-12', 'SC-7') `
                -Evidence "현재=$(if ($null -eq $v) { '미설정(기본: 허용)' } else { $v }), 권장=$wantShown`n$($w.Why)" `
                -Remediation "reg add `"HKLM\SOFTWARE\Policies\Google\Chrome`" /v $k /t $regType /d $setVal /f  (관리자, 호스트 재시작: Restart-Service chromoting)"
        }

        # 최근 접속 기록 (Application 로그, 원본 chromoting)
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'chromoting'; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 200 -ErrorAction SilentlyContinue)
        $conn = @($ev | Where-Object { $_.Message -match '(?i)connect|access|인증|연결' })
        $lines = $conn | Select-Object -First 25 | ForEach-Object { "$($_.TimeCreated.ToString('MM-dd HH:mm')) [$($_.Id)] $(($_.Message -split "`n")[0].Trim())" }
        Add-Finding -Id 'RA-CRD-LOG' -Category $cat -Title "CRD 최근 30일 이벤트 ($($ev.Count)건, 연결 관련 $($conn.Count)건)" -Status INFO -NIST @('AU-6', 'AC-17') `
            -Evidence $(if ($lines) { ($lines -join "`n") -replace '([A-Za-z0-9._%+-]{2})[A-Za-z0-9._%+-]*@', '$1***@' } else { '이벤트 없음' }) `
            -Remediation '본인이 접속하지 않은 시간대의 연결이 있으면 PIN 변경, Google 계정 세션 로그아웃, 호스트 재등록'
    } else {
        Add-Finding -Id 'RA-CRD-SVC' -Category $cat -Title 'Chrome 원격 데스크톱 호스트 서비스' -Status INFO -NIST @('AC-17') -Evidence 'chromoting 서비스 없음'
    }

    # 수동 확인 항목
    Add-Finding -Id 'RA-CRD-MANUAL' -Category $cat -Title 'CRD 수동 확인: Google 계정 2단계 인증·PIN' -Status INFO -NIST @('IA-2(1)', 'IA-5') `
        -Evidence '스크립트로 확인 불가: (1) Google 계정 2단계 인증(보안 키/패스키) (2) PIN 6자리 이상·다른 곳과 다른 값 (3) remotedesktop.google.com/access 에 모르는 기기 없음' `
        -Remediation 'myaccount.google.com/security 에서 2단계 인증·로그인된 기기 확인'

    # --- RDP / 원격 지원 / OpenSSH 서버 ---------------------------------------
    $rdp = Get-RegValue HKLM 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $ts = Get-Service TermService -ErrorAction SilentlyContinue
    $rdpOn = ($rdp.Value -eq 0)
    Add-Finding -Id 'RA-RDP' -Category $cat -Title '원격 데스크톱(RDP) 수신 비활성' -Status $(if ($rdpOn) { 'WARN' } else { 'PASS' }) -Severity $(if ($rdpOn) { 'CAT II' } else { '' }) -NIST @('AC-17', 'CM-7') `
        -Evidence "fDenyTSConnections=$($rdp.Value) TermService=$($ts.Status) (Home 에디션은 RDP 호스트 미지원)" -Remediation '쓰지 않으면 설정 > 시스템 > 원격 데스크톱 끄기'
    $ra = Get-RegValue HKLM 'SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
    Add-Finding -Id 'RA-ASSIST' -Category $cat -Title 'Windows 원격 지원 요청 허용 안 함' -Status $(if ($ra.Value -eq 1) { 'WARN' } else { 'PASS' }) -Severity $(if ($ra.Value -eq 1) { 'CAT III' } else { '' }) `
        -STIG 'WN11-CC-000155' -NIST @('AC-17') -Evidence "fAllowToGetHelp=$(if ($ra.Exists) { $ra.Value } else { '없음' })" `
        -Remediation '시스템 속성 > 원격 > "이 컴퓨터에 대한 원격 지원 연결 허용" 해제'
    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if ($sshd) {
        $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
        $c = if (Test-Path $cfg) { Get-Content $cfg -ErrorAction SilentlyContinue } else { @() }
        $pw = -not ($c -match '^\s*PasswordAuthentication\s+no')
        Add-Finding -Id 'RA-SSHD' -Category $cat -Title 'OpenSSH 서버' -Status $(if ($sshd.Status -eq 'Running' -and $pw) { 'WARN' } else { 'INFO' }) -NIST @('AC-17', 'IA-2') `
            -Evidence "sshd=$($sshd.Status)/$($sshd.StartType), 암호 인증=$(if ($pw) { '허용' } else { '차단' })" -Remediation 'sshd_config: PasswordAuthentication no, 키 인증만 허용'
    }

    # --- 기타 원격 제어 도구 (RMM 악용 탐지: ATT&CK T1219) ----------------------
    $rmm = 'TeamViewer', 'AnyDesk', 'RustDesk', 'Splashtop', 'ScreenConnect', 'ConnectWise', 'LogMeIn', 'GoToAssist', 'GoTo Resolve', 'RemotePC', 'Supremo', 'UltraViewer',
           'Atera', 'NinjaRMM', 'NinjaOne', 'Kaseya', 'DWService', 'Ammyy', 'RealVNC', 'TightVNC', 'UltraVNC', 'TigerVNC', 'Radmin', 'MeshAgent', 'Parsec', 'Zoho Assist', 'NetSupport', 'ToDesk', 'Sunlogin', 'HopToDesk'
    $rx = ($rmm | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $found = New-Object System.Collections.Generic.List[string]
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or $_.PathName -match $rx } | ForEach-Object { $found.Add("서비스: $($_.DisplayName) [$($_.State)] $($_.PathName)") }
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $rx -or $_.Path -match $rx } | ForEach-Object { $found.Add("프로세스: $($_.ProcessName) $($_.Path)") }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $rx } | ForEach-Object { $found.Add("설치됨: $($_.DisplayName) $($_.DisplayVersion)") }
    }
    $f = @($found | Sort-Object -Unique)
    Add-Finding -Id 'RA-RMM' -Category $cat -Title "Chrome 원격 데스크톱 외 원격 제어 도구 ($($f.Count)건)" -Status $(if ($f) { 'WARN' } else { 'PASS' }) -Severity $(if ($f) { 'CAT II' } else { '' }) `
        -NIST @('AC-17', 'CM-7', 'CM-11') -Evidence $(if ($f) { $f -join "`n" } else { "알려진 원격 제어 도구 $($rmm.Count)종 없음" }) `
        -Remediation '직접 설치하지 않은 원격 도구는 침해 후 지속성 수단으로 자주 쓰인다(ATT&CK T1219). 제거 후 Google·Microsoft 계정 암호 변경'
}
