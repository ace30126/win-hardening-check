# 2-b. 의심 파일·무결성 (NIST SI-7, SI-3, SI-4, CM-7)

$script:CoreBinaries = @(
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'advapi32.dll', 'sechost.dll', 'rpcrt4.dll', 'bcrypt.dll', 'bcryptprimitives.dll',
    'crypt32.dll', 'ncrypt.dll', 'lsasrv.dll', 'msv1_0.dll', 'kerberos.dll', 'wdigest.dll', 'samsrv.dll', 'secur32.dll', 'sspicli.dll', 'netapi32.dll',
    'ws2_32.dll', 'wininet.dll', 'winhttp.dll', 'dnsapi.dll', 'shell32.dll', 'ole32.dll', 'combase.dll', 'amsi.dll', 'wldp.dll', 'authz.dll',
    'lsass.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe', 'svchost.exe', 'explorer.exe', 'userinit.exe',
    'cmd.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe', 'taskhostw.exe', 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe',
    'WindowsPowerShell\v1.0\powershell.exe', 'WindowsPowerShell\v1.0\System.Management.Automation.dll', 'drivers\ntfs.sys', 'drivers\tcpip.sys',
    'drivers\afd.sys', 'drivers\netio.sys', 'drivers\fltmgr.sys', 'drivers\ksecdd.sys', 'drivers\cng.sys', 'drivers\ci.dll', 'ntoskrnl.exe', 'hal.dll'
)

function Get-CoreBinarySnapshot {
    $sys = Join-Path $env:SystemRoot 'System32'
    foreach ($rel in $script:CoreBinaries) {
        $p = Join-Path $sys $rel
        if ($rel -eq 'drivers\ci.dll') { $p = Join-Path $sys 'ci.dll' }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $fi = Get-Item -LiteralPath $p
        $sig = Get-SignatureInfo $p
        [pscustomobject]@{
            Path = $p; Sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            Version = $fi.VersionInfo.FileVersion; Size = $fi.Length; Modified = $fi.LastWriteTimeUtc.ToString('s')
            SigStatus = $sig.Status; Signer = $sig.Signer
        }
    }
}

function Invoke-CheckIntegrity {
    param([bool]$IsAdmin, [string]$BaselineDir, [switch]$NewBaseline, [switch]$Deep)
    $cat = '2-b. 무결성·의심 파일'
    Write-Step '무결성·자동실행·드라이버 점검'

    # --- 숨김 프로세스 교차 확인 ----------------------------------------------
    $a = @(Get-Process | ForEach-Object Id)
    $b = @(Get-CimInstance Win32_Process | ForEach-Object { [int]$_.ProcessId })
    Start-Sleep -Milliseconds 300
    $a2 = @(Get-Process | ForEach-Object Id)
    $onlyCim = @($b | Where-Object { $_ -notin $a -and $_ -notin $a2 -and $_ -ne 0 })
    $onlyPs = @($a | Where-Object { $_ -notin $b -and $_ -in $a2 -and $_ -ne 0 })
    # 짧은 시차로 생긴 차이는 한 번 더 확인
    $onlyCim = @($onlyCim | Where-Object { Get-CimInstance Win32_Process -Filter "ProcessId=$_" -ErrorAction SilentlyContinue })
    $diff = $onlyCim + $onlyPs
    Add-Finding -Id 'INT-HIDDENPROC' -Category $cat -Title '프로세스 목록 교차 확인 (Get-Process vs WMI)' -Status $(if ($diff) { 'WARN' } else { 'PASS' }) -Severity $(if ($diff) { 'CAT II' } else { '' }) `
        -NIST @('SI-4', 'SI-7') -Evidence $(if ($diff) { "WMI 에만: $($onlyCim -join ',') / Get-Process 에만: $($onlyPs -join ',')" } else { "두 API 의 PID 집합 일치 ($($a.Count)개)" }) `
        -Remediation '사용자 모드 루트킷은 API 후킹으로 프로세스를 숨긴다. 차이가 반복되면 Microsoft Defender 오프라인 검사(Start-MpWDOScan) 실행'

    # --- 드라이버 서명 --------------------------------------------------------
    $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object State -eq 'Running')
    $bad = foreach ($d in $drivers) {
        $p = Resolve-ExecutablePath $d.PathName
        $sig = Get-SignatureInfo $p
        if ($sig.Status -notin 'Valid') {
            # 카탈로그 서명 드라이버는 Get-AuthenticodeSignature 가 Valid 로 본다. NotFound 는 경로 해석 실패일 수 있어 따로 표시
            "$($d.Name) [$($sig.Status)] $p"
        }
    }
    $notFound = @($bad | Where-Object { $_ -match '\[(NotFound|NoPath)\]' })
    $realBad = @($bad | Where-Object { $_ -notmatch '\[(NotFound|NoPath)\]' })
    Add-Finding -Id 'INT-DRIVERS' -Category $cat -Title "실행 중 커널 드라이버 서명 ($($drivers.Count)개 중 이상 $($realBad.Count)개)" -Status $(if ($realBad) { 'FAIL' } elseif ($notFound) { 'WARN' } else { 'PASS' }) `
        -Severity $(if ($realBad) { 'CAT I' } elseif ($notFound) { 'CAT III' } else { '' }) -NIST @('SI-7', 'CM-14') `
        -Evidence $(if ($bad) { ($bad -join "`n") } else { '모든 실행 중 드라이버가 유효한 서명' }) `
        -Remediation '미서명·서명 무효 드라이버는 커널 루트킷의 대표 징후. 제조사 확인 -> 모르면 sc.exe stop/delete 전에 Defender 오프라인 검사. (취약 드라이버 차단 목록: 설정 > 장치 보안 > 코어 격리)'

    # --- 자동실행 지점 --------------------------------------------------------
    $auto = New-Object System.Collections.Generic.List[object]
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($k in $runKeys) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $auto.Add([pscustomobject]@{ Where = ($k -replace 'SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', '..\'); Name = $prop.Name; Cmd = [string]$prop.Value })
        }
    }
    foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object {
            $target = $_.FullName
            if ($_.Extension -eq '.lnk') { try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath } catch { } }
            $auto.Add([pscustomobject]@{ Where = 'Startup 폴더'; Name = $_.Name; Cmd = $target })
        }
    }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    $winlogonBad = @()
    if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe,?$') { $winlogonBad += "Shell=$($wl.Shell)" }
    if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { $winlogonBad += "Userinit=$($wl.Userinit)" }
    $ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { "$($_.PSChildName) -> Debugger=$dbg" }
    }
    $appinit = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($v.AppInit_DLLs -and $v.LoadAppInit_DLLs -eq 1) { "$k AppInit_DLLs=$($v.AppInit_DLLs)" }
    }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $knownAuth = 'msv1_0', ''
    $knownSec = 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'wsauth', ''
    $lsaBad = @(@($lsa.'Authentication Packages') | Where-Object { $_ -notin $knownAuth }) + @(@($lsa.'Security Packages') | Where-Object { $_ -notin $knownSec -and $_ -ne '""' })
    $hijack = @($winlogonBad) + @($ifeo) + @($appinit) + @($lsaBad | ForEach-Object { "LSA 패키지: $_" })
    Add-Finding -Id 'INT-HIJACK' -Category $cat -Title '하이재킹 지점 (Winlogon·IFEO·AppInit·LSA 패키지)' -Status $(if ($hijack) { 'FAIL' } else { 'PASS' }) -Severity $(if ($hijack) { 'CAT I' } else { '' }) `
        -NIST @('SI-7', 'CM-7') -Evidence $(if ($hijack) { $hijack -join "`n" } else { 'Winlogon Shell/Userinit 기본값, IFEO Debugger·AppInit_DLLs·추가 LSA 패키지 없음' }) `
        -Remediation '정상 소프트웨어가 쓰는 경우는 드물다(일부 백신·디버거). 출처를 모르면 해당 값 백업 후 삭제하고 Defender 오프라인 검사'

    # Run 키·시작 폴더: 서명 평가
    $autoEval = foreach ($e in $auto) {
        $p = Resolve-ExecutablePath $e.Cmd
        $sig = Get-SignatureInfo $p
        # WindowsApps 실행 별칭(스토어 앱)은 서명 API 가 읽지 못해 Error 가 나온다 -> 패키지 서명으로 보호되므로 OK
        $risk = if ($p -match '\\Microsoft\\WindowsApps\\') { 'OK' }
                elseif ($sig.Status -eq 'NotFound') { 'STALE' }
                elseif ($sig.Status -ne 'Valid' -and (Test-UserWritablePath $p)) { 'HIGH' }
                elseif ($sig.Status -ne 'Valid') { 'MED' } else { 'OK' }
        if ($e.Cmd -match '(?i)powershell.*(-enc|-e\s|frombase64|downloadstring|iex)|mshta|regsvr32.*/i:http|rundll32.*javascript|certutil.*-urlcache|bitsadmin') { $risk = 'HIGH' }
        [pscustomobject]@{ Where = $e.Where; Name = $e.Name; Path = $p; Sig = $sig.Status; Signer = $sig.Signer; Risk = $risk }
    }
    $high = @($autoEval | Where-Object Risk -eq 'HIGH'); $med = @($autoEval | Where-Object Risk -in 'MED', 'STALE')
    Add-Finding -Id 'INT-AUTORUN' -Category $cat -Title "시작 프로그램 (Run 키·시작 폴더 $(@($autoEval).Count)개)" -Status $(if ($high) { 'FAIL' } elseif ($med) { 'WARN' } else { 'PASS' }) `
        -Severity $(if ($high) { 'CAT I' } elseif ($med) { 'CAT II' } else { '' }) -NIST @('CM-7', 'SI-7') `
        -Evidence (($autoEval | Sort-Object Risk | ForEach-Object { "[$($_.Risk)] $($_.Where) :: $($_.Name) -> $($_.Path) [$($_.Sig)$(if ($_.Signer) { ": $($_.Signer)" })]" }) -join "`n") `
        -Remediation 'HIGH: 사용자 경로의 미서명 실행 파일 또는 인코딩/다운로드형 명령. 출처 확인 후 작업 관리자 > 시작 앱에서 끄고 파일 해시를 조회. STALE: 대상 파일이 없는 남은 항목 - 같은 경로에 악성 파일이 놓이면 실행되므로 항목 삭제'

    # --- 서비스 (사용자 경로·미서명) -------------------------------------------
    $svcBad = foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $p = Resolve-ExecutablePath $s.PathName
        if (-not $p -or $p -match '\\svchost\.exe$') { continue }
        $sig = Get-SignatureInfo $p
        $unquoted = ($s.PathName -notmatch '^"' -and $s.PathName -match '^[^"]*\s[^"]*\.exe' -and $p -match '\s')
        if ($sig.Status -ne 'Valid' -or (Test-UserWritablePath $p) -or $unquoted) {
            "$($s.Name) [$($s.State)/$($s.StartMode)] $p [$($sig.Status)]$(if (Test-UserWritablePath $p) { ' 사용자쓰기경로' })$(if ($unquoted) { ' 따옴표없는경로' })"
        }
    }
    Add-Finding -Id 'INT-SERVICES' -Category $cat -Title "의심 서비스 (미서명·사용자 경로·따옴표 없는 경로 $(@($svcBad).Count)개)" -Status $(if ($svcBad) { 'WARN' } else { 'PASS' }) `
        -Severity $(if ($svcBad) { 'CAT II' } else { '' }) -NIST @('CM-7', 'SI-7', 'AC-6') -Evidence (@($svcBad) -join "`n") `
        -Remediation '따옴표 없는 경로는 권한 상승 취약점(CWE-428): sc.exe config <svc> binPath= "\"C:\Program Files\...\app.exe\"". 미서명 서비스는 제조사 확인'

    # --- 예약 작업 -------------------------------------------------------------
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '^\\Microsoft\\' })
    $taskEval = foreach ($t in $tasks) {
        foreach ($act in @($t.Actions | Where-Object { $_.Execute })) {
            $p = Resolve-ExecutablePath $act.Execute
            $sig = Get-SignatureInfo $p
            $cmd = "$($act.Execute) $($act.Arguments)"
            $risk = if ($cmd -match '(?i)-enc\s|frombase64|downloadstring|iex\s*\(|mshta|certutil.*-urlcache|bitsadmin|\\temp\\') { 'HIGH' } elseif ($sig.Status -ne 'Valid' -and (Test-UserWritablePath $p)) { 'MED' } else { 'OK' }
            [pscustomobject]@{ Name = "$($t.TaskPath)$($t.TaskName)"; Path = $p; Sig = $sig.Status; RunLevel = $t.Principal.RunLevel; User = $t.Principal.UserId; Risk = $risk }
        }
    }
    $th = @($taskEval | Where-Object Risk -eq 'HIGH'); $tm = @($taskEval | Where-Object Risk -eq 'MED')
    Add-Finding -Id 'INT-TASKS' -Category $cat -Title "비-Microsoft 예약 작업 ($($tasks.Count)개)" -Status $(if ($th) { 'FAIL' } elseif ($tm) { 'WARN' } else { 'PASS' }) `
        -Severity $(if ($th) { 'CAT I' } elseif ($tm) { 'CAT III' } else { '' }) -NIST @('CM-7', 'SI-4') `
        -Evidence (($taskEval | Sort-Object Risk | ForEach-Object { "[$($_.Risk)] $($_.Name) -> $($_.Path) [$($_.Sig)] RunLevel=$($_.RunLevel) User=$($_.User)" }) -join "`n") `
        -Remediation '본인이 만든 작업인지 확인. 모르는 작업: Disable-ScheduledTask -TaskPath <경로> -TaskName <이름>. 사용자 경로 스크립트는 다른 프로세스가 바꿔치기할 수 있으니 ACL 확인'

    # --- WMI 영구 이벤트 구독 ---------------------------------------------------
    if ($IsAdmin) {
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Consumer' })
        Add-Finding -Id 'INT-WMI' -Category $cat -Title 'WMI 영구 이벤트 구독' -Status $(if ($consumers) { 'FAIL' } else { 'PASS' }) -Severity $(if ($consumers) { 'CAT I' } else { '' }) -NIST @('SI-4', 'CM-7') `
            -Evidence $(if ($consumers) { ($consumers | ForEach-Object { "$($_.CimClass.CimClassName) $($_.Name) $($_.CommandLineTemplate)$($_.ScriptText)" }) -join "`n" } else { '기본(SCM Event Log Consumer) 외 없음' }) `
            -Remediation 'ATT&CK T1546.003 지속성 기법. 모르는 구독은 __EventFilter·__FilterToConsumerBinding 과 함께 삭제'
    } else { Add-AdminSkip 'INT-WMI' $cat 'WMI 영구 이벤트 구독' '' @('SI-4') }

    # --- 핵심 시스템 바이너리 해시 기준선 ----------------------------------------
    $snap = @(Get-CoreBinarySnapshot)
    $unsignedCore = @($snap | Where-Object { $_.SigStatus -ne 'Valid' -or $_.Signer -notmatch 'Microsoft' })
    Add-Finding -Id 'INT-CORE-SIG' -Category $cat -Title "핵심 시스템 파일 서명 ($($snap.Count)개)" -Status $(if ($unsignedCore) { 'FAIL' } else { 'PASS' }) -Severity $(if ($unsignedCore) { 'CAT I' } else { '' }) -NIST @('SI-7') `
        -Evidence $(if ($unsignedCore) { ($unsignedCore | ForEach-Object { "$($_.Path) [$($_.SigStatus): $($_.Signer)]" }) -join "`n" } else { 'ntdll·kernel32·lsass·winlogon 등 모두 Microsoft 유효 서명' }) `
        -Remediation '관리자 cmd: sfc /scannow 후 DISM /Online /Cleanup-Image /RestoreHealth'

    New-Item -ItemType Directory -Force $BaselineDir | Out-Null
    $blFile = Join-Path $BaselineDir 'core-binaries.json'
    if ($NewBaseline -or -not (Test-Path $blFile)) {
        $doc = [ordered]@{ Created = (Get-Date).ToString('s'); Build = [Environment]::OSVersion.Version.ToString(); UBR = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR; Files = $snap }
        [IO.File]::WriteAllText($blFile, ($doc | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
        Add-Finding -Id 'INT-BASELINE' -Category $cat -Title '핵심 바이너리 해시 기준선' -Status INFO -NIST @('SI-7', 'CM-2') -Evidence "기준선 저장: $blFile ($($snap.Count)개). 다음 실행부터 비교" `
            -Remediation '기준선은 깨끗하다고 믿는 시점에 만들어야 의미가 있다. Windows 업데이트 직후 -NewBaseline 으로 갱신'
    } else {
        $bl = Get-Content $blFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $old = @{}; foreach ($f in $bl.Files) { $old[$f.Path] = $f }
        $updates = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn -and $_.InstalledOn -gt [datetime]$bl.Created })
        $changed = foreach ($f in $snap) {
            $o = $old[$f.Path]
            if (-not $o -or $o.Sha256 -eq $f.Sha256) { continue }
            # 버전이 올라가고 Microsoft 유효 서명이면 업데이트로 본다
            $explained = ($f.Version -ne $o.Version -and $f.SigStatus -eq 'Valid' -and $f.Signer -match 'Microsoft')
            [pscustomobject]@{ Path = $f.Path; Old = "$($o.Version) $($o.Sha256.Substring(0,12))"; New = "$($f.Version) $($f.Sha256.Substring(0,12))"; Explained = $explained }
        }
        $unexplained = @($changed | Where-Object { -not $_.Explained })
        $st = if ($unexplained) { 'FAIL' } elseif ($changed) { 'INFO' } else { 'PASS' }
        $ev = if ($changed) { ($changed | ForEach-Object { "$(if ($_.Explained) { '[업데이트]' } else { '[설명불가]' }) $($_.Path): $($_.Old) -> $($_.New)" }) -join "`n" } else { "기준선($($bl.Created))과 $($snap.Count)개 해시 일치" }
        if ($updates) { $ev += "`n기준선 이후 설치된 업데이트: $(($updates | ForEach-Object HotFixID) -join ', ')" }
        Add-Finding -Id 'INT-BASELINE' -Category $cat -Title '핵심 바이너리 해시 기준선 비교' -Status $st -Severity $(if ($unexplained) { 'CAT I' } else { '' }) -NIST @('SI-7', 'CM-3') -Evidence $ev `
            -Remediation '[설명불가] = 버전은 같은데 해시가 바뀜 또는 서명 이상. sfc /verifyfile=<경로> 로 확인하고 Defender 오프라인 검사. 업데이트로 바뀐 경우 -NewBaseline 으로 갱신'
    }

    # --- Defender --------------------------------------------------------------
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $issues = @()
        if (-not $mp.AntivirusEnabled) { $issues += '백신 꺼짐' }
        if (-not $mp.RealTimeProtectionEnabled) { $issues += '실시간 보호 꺼짐' }
        if (-not $mp.IsTamperProtected) { $issues += '변조 방지 꺼짐' }
        if ($mp.AntivirusSignatureAge -gt 7) { $issues += "정의 $($mp.AntivirusSignatureAge)일 경과" }
        $ev = "AMService=$($mp.AMServiceEnabled) RealTime=$($mp.RealTimeProtectionEnabled) Tamper=$($mp.IsTamperProtected) 정의=$($mp.AntivirusSignatureLastUpdated) 최근 빠른검사=$($mp.QuickScanEndTime) 전체검사=$($mp.FullScanEndTime)"
        Add-Finding -Id 'INT-DEFENDER' -Category $cat -Title 'Microsoft Defender 상태' -Status $(if ($issues) { 'FAIL' } else { 'PASS' }) -Severity $(if ($issues) { 'CAT I' } else { '' }) `
            -STIG 'WN11-00-000045' -NIST @('SI-3') -Evidence "$($issues -join ', ')`n$ev".Trim() -Remediation 'Windows 보안 > 바이러스 및 위협 방지에서 켜기. 정의 업데이트: Update-MpSignature'
        $thr = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-90) })
        # ThreatStatusID: 1=탐지만, 102=격리 실패, 103=제거 실패, 105=중단, 107=차단 실패 -> 아직 남아 있을 수 있음
        $active = @($thr | Where-Object { $_.ThreatStatusID -in 0, 1, 102, 103, 105, 107 })
        Add-Finding -Id 'INT-THREATS' -Category $cat -Title "최근 90일 탐지 위협 ($($thr.Count)건)" -Status $(if ($active) { 'FAIL' } elseif ($thr) { 'WARN' } else { 'PASS' }) `
            -Severity $(if ($active) { 'CAT I' } elseif ($thr) { 'CAT III' } else { '' }) -NIST @('SI-3', 'IR-5') `
            -Evidence (($thr | Select-Object -First 15 | ForEach-Object { "$($_.InitialDetectionTime) ThreatID=$($_.ThreatID) Status=$($_.ThreatStatusID) $($_.Resources -join ';')" }) -join "`n") `
            -Remediation '상세: Get-MpThreat / Get-MpThreatDetection. 같은 위협이 반복되면 감염 경로(다운로드 폴더·브라우저 확장 등) 확인'
    } else {
        Add-Finding -Id 'INT-DEFENDER' -Category $cat -Title 'Microsoft Defender 상태' -Status WARN -Severity 'CAT II' -STIG 'WN11-00-000045' -NIST @('SI-3') -Evidence 'Get-MpComputerStatus 실패 - 타사 백신 사용 여부 확인'
    }

    # --- -Deep: SFC / DISM -----------------------------------------------------
    if ($Deep) {
        if ($IsAdmin) {
            Write-Step 'sfc /verifyonly 실행 중 (10분 내외)'
            $sfc = (& sfc.exe /verifyonly) -join "`n" -replace "`0", ''
            $ok = $sfc -match '(did not find any integrity violations|무결성 위반을 찾지 못했습니다)'
            Add-Finding -Id 'INT-SFC' -Category $cat -Title 'SFC 시스템 파일 무결성 (sfc /verifyonly)' -Status $(if ($ok) { 'PASS' } else { 'FAIL' }) -Severity $(if ($ok) { '' } else { 'CAT I' }) -NIST @('SI-7') `
                -Evidence (($sfc -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 4) -join "`n") -Remediation 'sfc /scannow 후 DISM /Online /Cleanup-Image /RestoreHealth. 상세: %windir%\Logs\CBS\CBS.log'
            $dism = (& dism.exe /Online /Cleanup-Image /CheckHealth) -join "`n"
            $dok = $dism -match '(No component store corruption detected|구성 요소 저장소 손상이 검색되지 않았습니다)'
            Add-Finding -Id 'INT-DISM' -Category $cat -Title 'DISM 구성 요소 저장소 상태' -Status $(if ($dok) { 'PASS' } else { 'WARN' }) -Severity $(if ($dok) { '' } else { 'CAT II' }) -NIST @('SI-7') `
                -Evidence (($dism -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) -join "`n") -Remediation 'DISM /Online /Cleanup-Image /RestoreHealth'
        } else {
            Add-AdminSkip 'INT-SFC' $cat 'SFC 시스템 파일 무결성' '' @('SI-7')
        }
    }
}
