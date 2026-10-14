# 2-a. 현재 세션·연결 (NIST SI-4, AC-17, SC-7, CM-7)

function Invoke-CheckNetwork {
    param([bool]$IsAdmin)
    $cat = '2-a. 세션·연결'
    Write-Step '네트워크 연결·세션 점검'

    # 프로세스 정보 (경로·서명)
    $procs = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    function Get-ProcLabel([int]$procId) {
        $p = $procs[$procId]
        if (-not $p) { return [pscustomobject]@{ Name = "PID $procId"; Path = ''; Sig = 'Unknown'; Signer = '' } }
        $sig = if ($p.ExecutablePath) { Get-SignatureInfo $p.ExecutablePath } else { [pscustomobject]@{ Status = 'NoPath'; Signer = '' } }
        [pscustomobject]@{ Name = $p.Name; Path = $p.ExecutablePath; Sig = $sig.Status; Signer = $sig.Signer }
    }

    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)

    # --- LISTEN (외부 바인딩) -------------------------------------------------
    $listen = $tcp | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -notin '127.0.0.1', '::1' -and $_.LocalAddress -notmatch '^127\.' }
    $rows = foreach ($l in ($listen | Sort-Object LocalPort -Unique)) {
        $pl = Get-ProcLabel $l.OwningProcess
        [pscustomobject]@{ Port = $l.LocalPort; Addr = $l.LocalAddress; Proc = $pl.Name; Path = $pl.Path; Sig = $pl.Sig; Signer = $pl.Signer }
    }
    $sysPorts = 135, 139, 445, 5040, 7680   # RPC, NetBIOS, SMB, CDP, Delivery Optimization (Windows 기본)
    $sus = @($rows | Where-Object { $_.Sig -notin 'Valid' -or ($_.Port -notin $sysPorts -and $_.Port -lt 49152 -and $_.Signer -notmatch 'Microsoft') })
    $ev = ($rows | ForEach-Object { "{0,-6} {1,-15} {2} [{3}{4}]" -f $_.Port, $_.Addr, $_.Proc, $_.Sig, $(if ($_.Signer) { ": $($_.Signer)" }) }) -join "`n"
    Add-Finding -Id 'NET-LISTEN' -Category $cat -Title "모든 인터페이스에 열린 TCP 포트 ($($rows.Count)개)" -Status $(if ($sus) { 'WARN' } else { 'INFO' }) -Severity $(if ($sus) { 'CAT II' } else { '' }) `
        -NIST @('CM-7', 'SC-7') -Evidence $ev `
        -Remediation '필요 없는 서비스는 중지하거나 127.0.0.1 에만 바인딩. 개발 서버(npm/python 등)는 --host 127.0.0.1 로 실행. 확인: Get-NetTCPConnection -State Listen | ? LocalPort -eq <포트>'

    # --- 공인 IP 직접 연결 여부 (NAT 공유기 없이 인터넷에 노출) -------------------
    $pubIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)' -and -not (Get-IsPrivateIp $_.IPAddress) } | ForEach-Object IPAddress)
    $listenPorts = @($listen | ForEach-Object LocalPort | Sort-Object -Unique)

    # --- ESTABLISHED (외부): 들어온 연결(로컬 LISTEN 포트로 접속)과 나간 연결을 구분 ----
    $est = $tcp | Where-Object { $_.State -eq 'Established' -and -not (Get-IsPrivateIp $_.RemoteAddress) }
    $inbound = @($est | Where-Object { $_.LocalPort -in $listenPorts })
    $estRows = foreach ($g in ($est | Where-Object { $_.LocalPort -notin $listenPorts } | Group-Object OwningProcess)) {
        $pl = Get-ProcLabel ([int]$g.Name)
        $remotes = ($g.Group | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Sort-Object -Unique | Select-Object -First 6) -join ', '
        [pscustomobject]@{ Proc = $pl.Name; Path = $pl.Path; Sig = $pl.Sig; Signer = $pl.Signer; Count = $g.Count; Remotes = $remotes }
    }
    # NoPath = SYSTEM 프로세스라 일반 권한으로 경로를 못 읽음 (미서명과 구분)
    $unsigned = @($estRows | Where-Object { $_.Sig -notin 'Valid', 'NoPath' })
    $userPath = @($unsigned | Where-Object { Test-UserWritablePath $_.Path })
    $ev = ($estRows | Sort-Object Count -Descending | ForEach-Object { "{0} x{1} [{2}{3}] -> {4}" -f $_.Proc, $_.Count, $_.Sig, $(if ($_.Signer) { ": $($_.Signer)" }), $_.Remotes }) -join "`n"
    $st = if ($userPath) { 'FAIL' } elseif ($unsigned) { 'WARN' } else { 'PASS' }
    Add-Finding -Id 'NET-ESTAB' -Category $cat -Title "외부로 나가는 연결 프로세스 ($(@($estRows).Count)개, 미서명 $($unsigned.Count)개)" -Status $st `
        -Severity $(switch ($st) { 'FAIL' { 'CAT I' } 'WARN' { 'CAT II' } default { '' } }) -NIST @('SI-4', 'SC-7') -Evidence $ev `
        -Remediation '미서명 프로세스(특히 AppData·Temp 경로)는 경로 확인 -> VirusTotal 해시 조회 -> 모르는 것이면 종료 후 Defender 전체 검사. 해시: Get-FileHash <경로>. [NoPath] 는 SYSTEM 프로세스라 관리자 실행 시 서명 확인됨'

    $inEv = ($inbound | Group-Object LocalPort | ForEach-Object { $pl = Get-ProcLabel $_.Group[0].OwningProcess; "로컬 $($_.Name) ($($pl.Name)) <- $(($_.Group | ForEach-Object { $_.RemoteAddress } | Sort-Object -Unique | Select-Object -First 8) -join ', ')" }) -join "`n"
    Add-Finding -Id 'NET-INBOUND' -Category $cat -Title "외부 IP 가 이 PC 의 열린 포트로 접속 중 ($($inbound.Count)건)" -Status $(if ($inbound) { 'WARN' } else { 'PASS' }) -Severity $(if ($inbound) { 'CAT II' } else { '' }) `
        -NIST @('SC-7', 'SI-4', 'AC-17') -Evidence $(if ($inbound) { $inEv } else { '외부에서 들어온 연결 없음' }) `
        -Remediation '본인이 연 서비스가 아니면 해당 포트를 방화벽에서 막는다. 모르는 IP 는 AbuseIPDB 등에서 조회(스캐너인 경우가 많음)'

    $exposed = @($rows | Where-Object { $_.Addr -in @('0.0.0.0', '::') + $pubIps })
    Add-Finding -Id 'NET-PUBLICIP' -Category $cat -Title 'PC 가 공인 IP 에 직접 연결됨 (공유기 NAT 없음)' -Status $(if ($pubIps) { 'WARN' } else { 'PASS' }) -Severity $(if ($pubIps) { 'CAT II' } else { '' }) `
        -NIST @('SC-7') -Evidence $(if ($pubIps) { "공인 IPv4: $($pubIps -join ', ')`n모든 인터페이스/공인 IP 에 열린 TCP 포트 $($exposed.Count)개: $(($exposed | ForEach-Object { "$($_.Port)($($_.Proc))" }) -join ', ')`n-> 방화벽 허용 규칙이 있는 포트는 인터넷에서 바로 접속됨" } else { '사설 IP 만 사용 (공유기 NAT 뒤)' }) `
        -Remediation '가능하면 공유기(NAT) 뒤에 둔다. 아니면 네트워크 범주를 "공용"으로 두고 공용 프로필 인바운드 허용 규칙을 최소화(NET-FW-INBOUND 참고). 139/445(SMB)·9009 등은 공용망에서 차단'
    if ($userPath) {
        Add-Finding -Id 'NET-ESTAB-USERPATH' -Category $cat -Title '사용자 쓰기 가능 경로의 미서명 프로세스가 외부 통신' -Status FAIL -Severity 'CAT I' -NIST @('SI-4', 'SI-3') `
            -Evidence (($userPath | ForEach-Object { "$($_.Path) -> $($_.Remotes)" }) -join "`n") -Remediation 'Get-FileHash 로 SHA-256 확인 후 VirusTotal 조회, 출처를 모르면 프로세스 종료·격리'
    }

    # UDP 외부 바인딩 (정보)
    $udpOpen = $udp | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | Sort-Object LocalPort -Unique
    $ev = ($udpOpen | Select-Object -First 40 | ForEach-Object { $pl = Get-ProcLabel $_.OwningProcess; "$($_.LocalPort) $($pl.Name)" }) -join ', '
    Add-Finding -Id 'NET-UDP' -Category $cat -Title "모든 인터페이스 UDP 엔드포인트 ($(@($udpOpen).Count)개)" -Status INFO -NIST @('CM-7') -Evidence $ev

    # --- 포트 프록시 (STIG WN11-00-000395) -----------------------------------
    $pp = Invoke-Native 'netsh' @('interface', 'portproxy', 'show', 'all')
    $ppLines = @($pp | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+|\*' -and $_ -match '\d{2,5}' })
    Add-Finding -Id 'NET-PORTPROXY' -Category $cat -Title 'netsh 포트 프록시 미사용' -Status $(if ($ppLines) { 'FAIL' } else { 'PASS' }) -Severity $(if ($ppLines) { 'CAT II' } else { '' }) `
        -STIG 'WN11-00-000395' -NIST @('CM-7', 'SC-7') -Evidence $(if ($ppLines) { $ppLines -join "`n" } else { '설정된 포트 프록시 없음' }) `
        -Remediation 'netsh interface portproxy reset  (공격자가 내부 포워딩 터널로 자주 사용)'

    # --- 로그온 세션 ----------------------------------------------------------
    # qwinsta 는 Home 에디션에 없으므로 WMI 로그온 세션으로 대체 (2=대화형, 10=원격 대화형, 11=캐시 대화형)
    $types = @{ 2 = '대화형'; 3 = '네트워크'; 10 = '원격대화형(RDP)'; 11 = '캐시대화형' }
    $sessions = foreach ($s in (Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | Where-Object { $_.LogonType -in 2, 3, 10, 11 })) {
        $u = Get-CimAssociatedInstance -InputObject $s -ResultClassName Win32_Account -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $u) { continue }
        [pscustomobject]@{ User = "$($u.Domain)\$($u.Name)"; Type = [int]$s.LogonType; Start = $s.StartTime }
    }
    $remote = @($sessions | Where-Object { $_.Type -in 3, 10 })
    Add-Finding -Id 'NET-LOGON' -Category $cat -Title "로그온 세션 ($(@($sessions).Count)개, 원격·네트워크 $($remote.Count)개)" -Status $(if ($remote) { 'WARN' } else { 'INFO' }) `
        -Severity $(if ($remote) { 'CAT III' } else { '' }) -NIST @('AC-17', 'AC-12') `
        -Evidence (($sessions | Sort-Object Start | ForEach-Object { "$($_.Start) $($types[$_.Type]) $($_.User)" }) -join "`n") `
        -Remediation '본인이 아닌 원격·네트워크 로그온이 있으면 계정 암호 변경, 이벤트 로그 4624(LogonType 3/10) 확인. Chrome 원격 데스크톱 세션은 별도 서비스라 여기 나오지 않을 수 있음(4. 원격 접속 참조)'

    # --- SMB 수신 세션 (net session) -------------------------------------------
    if ($IsAdmin) {
        $sess = @(Get-SmbSession -ErrorAction SilentlyContinue)
        Add-Finding -Id 'NET-SMBSESSION' -Category $cat -Title "이 PC 에 접속한 SMB 세션 ($($sess.Count)개)" -Status $(if ($sess) { 'WARN' } else { 'PASS' }) -Severity $(if ($sess) { 'CAT II' } else { '' }) `
            -NIST @('AC-17', 'SI-4') -Evidence $(if ($sess) { ($sess | ForEach-Object { "$($_.ClientComputerName) $($_.ClientUserName) (열린 파일 $($_.NumOpens))" }) -join "`n" } else { '접속 세션 없음 (net session 과 동일)' }) `
            -Remediation '모르는 세션: Close-SmbSession -SessionId <id> 후 공유 해제·암호 변경'
    } else { Add-AdminSkip 'NET-SMBSESSION' $cat '이 PC 에 접속한 SMB 세션 (net session)' '' @('AC-17') }

    # --- SMB 공유 (STIG WN11-00-000060) --------------------------------------
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN|IPC|[A-Z])\$$' -and $_.Name -ne 'print$' })
    if ($shares) {
        $ev = foreach ($s in $shares) {
            $acc = (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', '
            "$($s.Name) -> $($s.Path) [$acc]"
        }
        $everyone = $ev -match 'Everyone|모든 사용자'
        Add-Finding -Id 'NET-SHARE' -Category $cat -Title "사용자 생성 공유 폴더 ($($shares.Count)개)" -Status $(if ($everyone) { 'FAIL' } else { 'WARN' }) -Severity 'CAT II' `
            -STIG 'WN11-00-000060' -NIST @('AC-3', 'AC-6') -Evidence ($ev -join "`n") -Remediation '안 쓰면 Remove-SmbShare -Name <이름>. 쓰면 Everyone 제거 후 특정 사용자만 허용'
    } else {
        Add-Finding -Id 'NET-SHARE' -Category $cat -Title '사용자 생성 공유 폴더' -Status PASS -STIG 'WN11-00-000060' -NIST @('AC-3') -Evidence '기본 관리 공유(C$, ADMIN$, IPC$) 외 공유 없음'
    }

    # --- 방화벽 (STIG WN11-00-000135) ----------------------------------------
    $fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $off = @($fw | Where-Object { -not $_.Enabled })
    $ev = ($fw | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled), 기본 인바운드=$($_.DefaultInboundAction), 로그=$($_.LogBlocked)" }) -join "`n"
    Add-Finding -Id 'NET-FW' -Category $cat -Title 'Windows 방화벽 3개 프로필 활성' -Status $(if ($off -or -not $fw) { 'FAIL' } else { 'PASS' }) -Severity $(if ($off) { 'CAT II' } else { '' }) `
        -STIG 'WN11-00-000135' -NIST @('SC-7') -Evidence $ev -Remediation 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True  (관리자)'

    $prof = Get-NetConnectionProfile -ErrorAction SilentlyContinue
    $script:NetProfiles = $prof
    $fwIn = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
    $public = @($fwIn | Where-Object { $_.Profile -match 'Public|Any' -or $_.Profile -eq 'Any' })
    # 공용 프로필에 열린 비-Microsoft 앱 규칙 (필터는 규칙별 조회가 매우 느려 -All 로 한 번에 받는다)
    $appF = @{}; Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $appF[$_.InstanceID] = $_.Program }
    $portF = @{}; Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $portF[$_.InstanceID] = "$($_.Protocol)/$($_.LocalPort)" }
    # 같은 규칙이 수백 번 중복 생성되는 경우가 있어 (이름·프로그램·포트) 로 묶어 센다
    $nonMs = @($public | Where-Object { -not $_.DisplayGroup } | ForEach-Object {
            $prog = $appF[$_.Name]; if ($prog -and $prog -ne 'Any') { $prog = Split-Path $prog -Leaf }
            "$($_.DisplayName) | prog=$prog | port=$($portF[$_.Name])"
        } | Group-Object | Sort-Object Count -Descending)
    $anyProg = @($nonMs | Where-Object { $_.Name -match 'prog=Any \| port=(TCP|UDP)/\d' })
    Add-Finding -Id 'NET-FW-INBOUND' -Category $cat -Title "공용망 인바운드 허용(앱·사용자 추가) $($nonMs.Count)종 / 전체 허용 규칙 $($fwIn.Count)개" -Status $(if ($anyProg) { 'WARN' } elseif ($nonMs) { 'INFO' } else { 'PASS' }) `
        -Severity $(if ($anyProg) { 'CAT II' } else { '' }) -STIG 'WN11-00-000140' -NIST @('SC-7', 'CM-7') `
        -Evidence ("프로그램 제한 없이 포트만 연 규칙 $($anyProg.Count)종:`n" + (($anyProg | ForEach-Object { "  x$($_.Count) $($_.Name)" }) -join "`n") + "`n`n전체(상위 40):`n" + (($nonMs | Select-Object -First 40 | ForEach-Object { "  x$($_.Count) $($_.Name)" }) -join "`n")) `
        -Remediation '앱 설치 때 "공용 네트워크 허용"으로 생긴 규칙이 많다. 필요 없는 것은 Disable-NetFirewallRule -DisplayName "<이름>"'
}
