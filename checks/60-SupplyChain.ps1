# 5. 공급망·기타 (NIST CM-7, CM-8, CM-11, AC-6, CP-9, SC-7)
# 범위 밖: npm·pip 패키지(별도 typosquatting 프로젝트), AI 에이전트 설정

function Get-BrowserExtensions {
    $roots = @(
        @{ Browser = 'Chrome'; Path = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data' }
        @{ Browser = 'Edge'; Path = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data' }
        @{ Browser = 'Brave'; Path = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data' }
        @{ Browser = 'Whale'; Path = Join-Path $env:LOCALAPPDATA 'Naver\Naver Whale\User Data' }
    )
    $risky = 'debugger', 'nativeMessaging', 'cookies', 'webRequest', 'webRequestBlocking', 'declarativeNetRequest', 'proxy', 'management', 'clipboardRead', 'desktopCapture', 'history', 'downloads', 'privacy', 'scripting'
    foreach ($r in $roots) {
        if (-not (Test-Path $r.Path)) { continue }
        foreach ($prof in Get-ChildItem $r.Path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) {
            $ext = Join-Path $prof.FullName 'Extensions'
            if (-not (Test-Path $ext)) { continue }
            # Secure Preferences 에서 설치 출처(location)·활성 상태 확인
            $prefs = $null
            foreach ($pf in 'Secure Preferences', 'Preferences') {
                $pp = Join-Path $prof.FullName $pf
                if (Test-Path $pp) { try { $j = Get-Content $pp -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.extensions.settings) { $prefs = $j.extensions.settings; break } } catch { } }
            }
            foreach ($idDir in Get-ChildItem $ext -Directory -ErrorAction SilentlyContinue) {
                $verDir = Get-ChildItem $idDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                $mf = if ($verDir) { Join-Path $verDir.FullName 'manifest.json' }
                if (-not $mf -or -not (Test-Path $mf)) { continue }
                try { $m = Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                $name = [string]$m.name
                if ($name -match '^__MSG_(.+)__$') {
                    $key = $Matches[1]
                    $loc = Join-Path $verDir.FullName "_locales\$(if ($m.default_locale) { $m.default_locale } else { 'en' })\messages.json"
                    if (Test-Path $loc) { try { $msgs = Get-Content $loc -Raw -Encoding UTF8 | ConvertFrom-Json; $hit = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1; if ($hit) { $name = $hit.Value.message } } catch { } }
                }
                $perms = @($m.permissions) + @($m.optional_permissions) + @($m.host_permissions) | Where-Object { $_ -is [string] }
                $broadHost = @($perms + @($m.content_scripts | ForEach-Object { $_.matches })) -match '^(<all_urls>|\*://\*/\*|https?://\*/\*)$'
                $st = $null; $loc2 = $null
                if ($prefs -and $prefs.PSObject.Properties[$idDir.Name]) { $s = $prefs.($idDir.Name); $st = $s.state; $loc2 = $s.location; if ($s.disable_reasons) { $st = 0 } }
                [pscustomobject]@{
                    Browser = $r.Browser; Profile = $prof.Name; Id = $idDir.Name; Name = $name; Version = $m.version
                    Risky = @($perms | Where-Object { $_ -in $risky }); AllUrls = [bool]$broadHost
                    # location: 1=웹스토어, 2/3/6=다른 프로그램이 설치, 7/9=정책, 4=압축해제(개발자 모드), 8=명령줄, 5/10=컴포넌트
                    Sideloaded = ($loc2 -in 4, 8); External = ($loc2 -in 2, 3, 6); Policy = ($loc2 -in 7, 9)
                    Component = ($loc2 -in 5, 10); Enabled = ($st -ne 0)
                    UpdateUrl = [string]$m.update_url
                }
            }
        }
    }
}

function Invoke-CheckSupplyChain {
    param([bool]$IsAdmin, [string]$PrevJson)
    $cat = '5. 공급망·기타'
    Write-Step '브라우저·VS Code 확장, 계정, 랜섬웨어 대비, Wi-Fi 점검'

    # --- 브라우저 확장 ---------------------------------------------------------
    $exts = @(Get-BrowserExtensions | Where-Object { -not $_.Component })
    $script:Inventory = @{ BrowserExtensions = @($exts | ForEach-Object { "$($_.Browser)/$($_.Id)" }) }
    $sideload = @($exts | Where-Object { $_.Sideloaded -or ($_.UpdateUrl -and $_.UpdateUrl -notmatch 'clients2\.google\.com|edge\.microsoft\.com') })
    $risky = @($exts | Where-Object { $_.Enabled -and ($_.AllUrls -or $_.Risky -contains 'debugger' -or $_.Risky -contains 'nativeMessaging' -or ($_.Risky -contains 'cookies')) })
    $ev = ($exts | Sort-Object { -([int]$_.AllUrls + $_.Risky.Count) } | ForEach-Object {
            $flags = @(); if ($_.AllUrls) { $flags += '모든사이트' }; if ($_.Risky) { $flags += $_.Risky }; if ($_.Sideloaded) { $flags += '개발자모드설치' }; if ($_.External) { $flags += '다른프로그램이설치' }; if ($_.Policy) { $flags += '정책설치' }; if (-not $_.Enabled) { $flags += '비활성' }
            "$($_.Browser)/$($_.Profile) $($_.Name) $($_.Version) [$($_.Id)] $(if ($flags) { '{' + ($flags -join ',') + '}' })" }) -join "`n"
    Add-Finding -Id 'SC-BROWSER-EXT' -Category $cat -Title "브라우저 확장 $($exts.Count)개 (활성+강한 권한 $($risky.Count)개, 개발자 모드·비공식 업데이트 $($sideload.Count)개)" `
        -Status $(if ($sideload) { 'FAIL' } elseif ($risky) { 'WARN' } else { 'PASS' }) -Severity $(if ($sideload) { 'CAT II' } elseif ($risky) { 'CAT III' } else { '' }) -NIST @('CM-7', 'CM-11', 'SA-22') -Evidence $ev `
        -Remediation '"모든 사이트 읽기·변경" + cookies/webRequest 권한 확장은 로그인 세션(쿠키)을 훔칠 수 있다. 안 쓰는 확장은 제거하고, 필요한 것은 "클릭 시에만" 사이트 접근으로 제한(chrome://extensions > 세부정보). 개발자 모드 설치·비공식 update_url 은 출처 확인. '다른프로그램이설치'는 Office·백신 등이 끼워 넣은 확장이니 안 쓰면 제거'

    # --- VS Code 확장 (인벤토리 + 이전 회차 대비 추가분) -------------------------
    $codeExt = Join-Path $env:USERPROFILE '.vscode\extensions'
    if (Test-Path $codeExt) {
        $list = @()
        $ej = Join-Path $codeExt 'extensions.json'
        if (Test-Path $ej) { try { $list = @((Get-Content $ej -Raw -Encoding UTF8 | ConvertFrom-Json) | ForEach-Object { "$($_.identifier.id)@$($_.version)" }) } catch { } }
        if (-not $list) { $list = @(Get-ChildItem $codeExt -Directory | ForEach-Object { $_.Name -replace '-(\d+\.\d+\.\d+.*)$', '@$1' }) }
        $ids = @($list | ForEach-Object { ($_ -split '@')[0].ToLowerInvariant() } | Sort-Object -Unique)
        $script:Inventory.VSCodeExtensions = $ids
        $new = @()
        if ($PrevJson -and (Test-Path $PrevJson)) {
            try { $prev = (Get-Content $PrevJson -Raw -Encoding UTF8 | ConvertFrom-Json).Inventory.VSCodeExtensions; if ($prev) { $new = @($ids | Where-Object { $_ -notin $prev }) } } catch { }
        }
        $publishers = $ids | ForEach-Object { ($_ -split '\.')[0] } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "$($_.Name)($($_.Count))" }
        Add-Finding -Id 'SC-VSCODE-EXT' -Category $cat -Title "VS Code 확장 $($ids.Count)개$(if ($new) { " (이전 회차 이후 신규 $($new.Count)개)" })" -Status INFO -NIST @('CM-8', 'CM-11') `
            -Evidence "게시자: $($publishers -join ', ')$(if ($new) { "`n신규: $($new -join ', ')" })`n`n$(($list | Sort-Object) -join "`n")" `
            -Remediation 'VS Code 확장은 샌드박스 없이 사용자 권한으로 실행된다. 게시자 인증(파란 체크) 여부와 설치 수를 확인하고 안 쓰는 것은 제거: code --uninstall-extension <id>'
    }

    # --- 계정 --------------------------------------------------------------------
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdminMember = (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $me.User.Value })
    $local = Get-LocalUser -SID $me.User.Value -ErrorAction SilentlyContinue
    $acctType = if ($local.PrincipalSource) { [string]$local.PrincipalSource } else { '?' }
    Add-Finding -Id 'SC-ACCOUNT-ADMIN' -Category $cat -Title '일상 사용 계정이 관리자 그룹 소속인지' -Status $(if ($isAdminMember) { 'WARN' } else { 'PASS' }) -Severity $(if ($isAdminMember) { 'CAT II' } else { '' }) `
        -STIG 'WN11-00-000240' -NIST @('AC-6(2)', 'AC-6(5)') -Evidence "$($me.Name) 관리자 그룹=$([bool]$isAdminMember), 계정 종류=$acctType (MicrosoftAccount=Microsoft 계정, Local=로컬)" `
        -Remediation '관리자용 별도 로컬 계정을 만들고 평소 계정은 표준 사용자로 낮춘다(UAC 가 자격 증명을 요구 -> 악성코드의 무단 권한 상승 차단). 설정 > 계정 > 기타 사용자'

    $hello = Test-Path "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -ErrorAction SilentlyContinue
    $bio = @(Get-PnpDevice -Class Biometric -PresentOnly -ErrorAction SilentlyContinue | Where-Object Status -eq 'OK')
    Add-Finding -Id 'SC-HELLO' -Category $cat -Title 'Windows Hello (PIN·생체)' -Status INFO -NIST @('IA-2', 'IA-5') `
        -Evidence "Ngc 컨테이너 존재=$hello (PIN 설정 흔적, 관리자 아니면 확인 제한), 생체 장치=$(if ($bio) { ($bio | ForEach-Object FriendlyName) -join ', ' } else { '없음' })" `
        -Remediation 'Windows Hello PIN 은 TPM 에 묶여 원격 탈취가 어렵다. 설정 > 계정 > 로그인 옵션에서 PIN·지문/얼굴 사용 및 "Windows Hello 로그인만 허용" 켜기'

    # --- 랜섬웨어 대비 -----------------------------------------------------------
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    $cfa = if ($pref) { [int]$pref.EnableControlledFolderAccess } else { -1 }
    Add-Finding -Id 'SC-CFA' -Category $cat -Title '제어된 폴더 액세스(랜섬웨어 방지)' -Status $(if ($cfa -eq 1) { 'PASS' } else { 'WARN' }) -Severity $(if ($cfa -eq 1) { '' } else { 'CAT III' }) -NIST @('SI-3', 'CP-9') `
        -Evidence "EnableControlledFolderAccess=$(@{0='꺼짐';1='켜짐';2='감사 모드';-1='확인불가'}[$cfa])" `
        -Remediation 'Windows 보안 > 바이러스 및 위협 방지 > 랜섬웨어 방지 > 제어된 폴더 액세스 켜기 (개발 도구가 막히면 "허용된 앱"에 추가)'
    $sr = Get-RegValue HKLM 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' 'RPSessionInterval'
    $rp = if ($IsAdmin) { @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue) } else { $null }
    $fh = Get-Service fhsvc -ErrorAction SilentlyContinue
    $onedriveKfm = (Get-RegValue HKCU 'SOFTWARE\Microsoft\OneDrive\Accounts\Personal' 'UserFolder').Value
    $gdrive = Get-Process -Name 'GoogleDriveFS' -ErrorAction SilentlyContinue
    $evb = "시스템 보호(복원 지점)=$(if ($sr.Value -eq 1) { '켜짐' } elseif ($sr.Exists) { "RPSessionInterval=$($sr.Value)" } else { '확인불가' })$(if ($null -ne $rp) { ", 복원 지점 $($rp.Count)개" })" +
           ", 파일 히스토리 서비스=$($fh.Status), OneDrive=$(if ($onedriveKfm) { '사용' } else { '없음' }), Google Drive=$(if ($gdrive) { '실행 중' } else { '없음' })"
    Add-Finding -Id 'SC-BACKUP' -Category $cat -Title '백업·복원 수단' -Status $(if ($onedriveKfm -or $gdrive -or $fh.Status -eq 'Running') { 'INFO' } else { 'WARN' }) -Severity $(if ($onedriveKfm -or $gdrive -or $fh.Status -eq 'Running') { '' } else { 'CAT III' }) `
        -NIST @('CP-9', 'CP-10') -Evidence $evb `
        -Remediation '동기화(OneDrive·Drive)는 암호화된 파일도 그대로 동기화된다. 버전 기록 보존 기간을 확인하고, 오프라인(분리) 백업을 하나 더 둔다(3-2-1)'

    # --- Wi-Fi 프로필·네트워크 범주 ------------------------------------------------
    $profiles = Invoke-Native 'netsh' @('wlan', 'show', 'profiles')
    if ($profiles) {
        $names = @($profiles | Where-Object { $_ -match ':\s*(.+)$' -and $_ -match '(All User Profile|모든 사용자 프로필|User Profile|사용자 프로필)' } | ForEach-Object { ($_ -split ':', 2)[1].Trim() })
        $open = foreach ($n in $names) {
            $d = Invoke-Native 'netsh' @('wlan', 'show', 'profile', "name=$n")
            $auth = ($d | Where-Object { $_ -match '(Authentication|인증)\s*:' } | Select-Object -First 1) -replace '^.*:\s*', ''
            $auto = ($d | Where-Object { $_ -match '(Connection mode|연결 모드)\s*:' } | Select-Object -First 1) -replace '^.*:\s*', ''
            if ($auth -match '^(Open|개방|열기)') { "$n (인증 없음, $auto)" }
        }
        Add-Finding -Id 'SC-WIFI' -Category $cat -Title "저장된 Wi-Fi 프로필 $($names.Count)개 (개방형 $(@($open).Count)개)" -Status $(if ($open) { 'WARN' } else { 'PASS' }) -Severity $(if ($open) { 'CAT III' } else { '' }) `
            -NIST @('AC-18', 'SC-7') -Evidence $(if ($open) { @($open) -join "`n" } else { '개방형(암호 없는) 저장 프로필 없음' }) `
            -Remediation '개방형 프로필은 같은 이름의 가짜 AP(Evil Twin)에 자동 접속될 수 있다. 삭제: netsh wlan delete profile name="<이름>"'
    }
    $np = if ($script:NetProfiles) { $script:NetProfiles } else { Get-NetConnectionProfile -ErrorAction SilentlyContinue }
    $privateWifi = @($np | Where-Object { $_.NetworkCategory -eq 'Private' -and $_.InterfaceAlias -match '(?i)wi-?fi|wlan|무선' })
    Add-Finding -Id 'SC-NETCAT' -Category $cat -Title '현재 네트워크 범주 (공용/개인)' -Status $(if ($privateWifi) { 'INFO' } else { 'PASS' }) -NIST @('SC-7') `
        -Evidence (($np | ForEach-Object { "$($_.InterfaceAlias): $($_.Name) = $($_.NetworkCategory)" }) -join "`n") `
        -Remediation '집 외(카페·숙소) 네트워크는 반드시 "공용"으로. 개인으로 두면 파일 공유·네트워크 검색이 열린다: Set-NetConnectionProfile -InterfaceAlias "<이름>" -NetworkCategory Public (관리자)'
}
