# 1. API Key 계류 (NIST IA-5(1)(h), IA-5(7), SC-28, SC-12)
# 원문은 절대 저장하지 않는다. Evidence 에는 경로·줄·종류·마스킹값만 남긴다.

$script:SecretCat = '1. API Key 계류'

function Get-SecretRuleSet([string]$DataDir) {
    $cfg = Get-Content (Join-Path $DataDir 'secret-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $opts = [Text.RegularExpressions.RegexOptions]'Compiled, CultureInvariant'
    $rules = foreach ($r in $cfg.Rules) {
        [pscustomobject]@{
            Id = $r.Id; Name = $r.Name; Severity = $r.Severity
            Rx = New-Object Text.RegularExpressions.Regex($r.Regex, $opts)
            Group = if ($r.PSObject.Properties['Group']) { [int]$r.Group } else { 0 }
            MinEntropy = if ($r.PSObject.Properties['MinEntropy']) { [double]$r.MinEntropy } else { 0 }
        }
    }
    [pscustomobject]@{
        Rules = @($rules)
        Placeholder = New-Object Text.RegularExpressions.Regex($cfg.PlaceholderRegex)
        SkipDirs = @($cfg.SkipDirs | ForEach-Object { $_.ToLowerInvariant() })
        TextExt = [Collections.Generic.HashSet[string]]::new([string[]]$cfg.TextExtensions, [StringComparer]::OrdinalIgnoreCase)
        CertExt = [Collections.Generic.HashSet[string]]::new([string[]]$cfg.CertFileExtensions, [StringComparer]::OrdinalIgnoreCase)
        GenericExt = [Collections.Generic.HashSet[string]]::new([string[]]$cfg.GenericExtensions, [StringComparer]::OrdinalIgnoreCase)
        MaxBytes = [int64]$cfg.MaxFileBytes
    }
}

# JWT payload 의 role 확인 (Supabase service_role 등)
function Get-JwtRole([string]$jwt) {
    try {
        $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        $j = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        if ($j.role) { return [string]$j.role }
        ''
    } catch { '' }
}

# OPENSSH 개인키가 암호로 보호되는지 (kdf 가 bcrypt 면 보호)
function Test-OpenSshKeyEncrypted([string]$text) {
    if ($text -notmatch '(?s)-----BEGIN OPENSSH PRIVATE KEY-----(.+?)-----END') { return $null }
    try {
        $b = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
        $head = [Text.Encoding]::ASCII.GetString($b, 0, [Math]::Min(64, $b.Length))
        return ($head -match 'bcrypt')
    } catch { $null }
}

# 텍스트 한 덩어리에서 비밀값 찾기 -> @{Rule; Line; Masked; Note}
function Find-SecretsInText([string]$Text, $RuleSet, [bool]$AllowGeneric = $true) {
    $hits = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    # 줄 번호 계산용 개행 위치
    $nl = New-Object System.Collections.Generic.List[int]
    for ($i = $Text.IndexOf("`n"); $i -ge 0; $i = $Text.IndexOf("`n", $i + 1)) { $nl.Add($i) }
    foreach ($r in $RuleSet.Rules) {
        if ($r.Id -eq 'generic' -and -not $AllowGeneric) { continue }
        foreach ($m in $r.Rx.Matches($Text)) {
            $val = if ($r.Group -gt 0) { $m.Groups[$r.Group].Value } else { $m.Value }
            if (-not $val) { continue }
            if ($r.Id -in 'generic', 'url-credential', 'docker-auth') {
                if ($RuleSet.Placeholder.IsMatch($val)) { continue }
                if ($r.MinEntropy -gt 0 -and (Get-ShannonEntropy $val) -lt $r.MinEntropy) { continue }
                # 이미 구체 규칙으로 잡힌 값이면 중복 보고 안 함
                if ($seen.ContainsKey($val)) { continue }
            }
            if ($seen.ContainsKey($val)) { continue }
            $seen[$val] = 1
            $line = 1 + ($nl.BinarySearch($m.Index) | ForEach-Object { if ($_ -lt 0) { -bnot $_ } else { $_ } })
            $sev = $r.Severity; $note = ''
            if ($r.Id -eq 'jwt') {
                $role = Get-JwtRole $val
                if ($role -eq 'service_role') { $sev = 'CAT I'; $note = 'role=service_role (RLS 우회 키)' }
                elseif ($role) { $note = "role=$role" }
            }
            if ($r.Id -eq 'private-key') {
                if ($m.Value -match 'OPENSSH') {
                    $enc = Test-OpenSshKeyEncrypted $Text
                    if ($enc) { $sev = 'CAT III'; $note = '암호 보호됨' } elseif ($enc -eq $false) { $note = '암호 없음' }
                }
                elseif ($Text -match 'Proc-Type:\s*4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY') { $sev = 'CAT III'; $note = '암호 보호됨' }
                else { $note = '암호 없음' }
                $val = $m.Value
            }
            # 개인키는 본문까지 매치되므로 머리줄만 남긴다
            $masked = if ($r.Id -eq 'private-key') { ($m.Value -split '\r?\n|\\n')[0].Trim() } else { Get-MaskedSecret $val }
            $hits.Add([pscustomobject]@{ RuleId = $r.Id; Rule = $r.Name; Severity = $sev; Line = $line; Masked = $masked; Note = $note })
        }
    }
    $hits
}

$script:SevRank = @{ 'CAT I' = 3; 'CAT II' = 2; 'CAT III' = 1; '' = 0 }
function Get-MaxSeverity($items) {
    ($items | Sort-Object { $script:SevRank[$_.Severity] } -Descending | Select-Object -First 1).Severity
}

# 파일 ACL 에 Everyone/Users/Authenticated Users 읽기 허용이 있는지
function Get-BroadReadAce([string]$Path) {
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $broad = 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-7'
        $hit = foreach ($a in $acl.Access) {
            if ($a.AccessControlType -ne 'Allow') { continue }
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($sid -in $broad -and ($a.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)) { $a.IdentityReference.Value }
        }
        @($hit | Sort-Object -Unique)
    } catch { @() }
}

function Get-ScanFiles([string]$Root, $RuleSet, [string]$ExcludeRoot) {
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $lower = $dir.ToLowerInvariant()
        $skip = $false
        foreach ($s in $RuleSet.SkipDirs) {
            if ($lower.EndsWith('\' + $s)) { $skip = $true; break }
        }
        if ($skip -or ($ExcludeRoot -and $dir -eq $ExcludeRoot)) { continue }   # 점검 도구 폴더(규칙 예시·보고서) 제외
        try {
            $di = New-Object IO.DirectoryInfo($dir)
            if (($di.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $dir -ne $Root) { continue }   # 정션/심볼릭 링크 순환 방지
            foreach ($sub in $di.EnumerateDirectories()) { $stack.Push($sub.FullName) }
            foreach ($f in $di.EnumerateFiles()) {
                # OneDrive 등 클라우드 전용(미다운로드) 파일은 읽으면 다운로드가 발생하므로 제외
                if ($f.Attributes -band [IO.FileAttributes]::Offline -or ([int]$f.Attributes -band 0x400000)) { continue }
                $f
            }
        } catch { }
    }
}

function Invoke-CheckSecrets {
    param([string]$ScanPath, [string]$DataDir, [string]$ExcludeRoot)
    $cat = $script:SecretCat
    $rs = Get-SecretRuleSet $DataDir
    $nist = @('IA-5', 'SC-28')

    # --- 1) 파일 스캔 --------------------------------------------------------
    Write-Step "API Key 스캔: $ScanPath (시간이 걸릴 수 있음)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $weak = New-Object System.Collections.Generic.List[string]
    $scanned = 0; $fileHits = 0; $certFiles = New-Object System.Collections.Generic.List[string]
    $quick = New-Object Text.RegularExpressions.Regex('(?i)sk-|AIza|AKIA|ASIA|gh[pousr]_|github_pat|glpat|xox|hf_|ntn_|secret|token|key|passw|BEGIN|eyJ|://|GOCSPX|1//0|_live_|sbp_|sb_secret|gsk_|xai-|pplx-|r8_|npm_|pypi-|SG\.|auth', 'Compiled')
    $slow = New-Object System.Collections.Generic.List[string]
    $fileSw = New-Object Diagnostics.Stopwatch
    foreach ($f in (Get-ScanFiles $ScanPath $rs $ExcludeRoot)) {
        # 이전 파일이 느렸으면 기록 (읽기·정규식 합산)
        if ($fileSw.ElapsedMilliseconds -ge 2000) { $slow.Add(('{0:N1}s  {1}' -f $fileSw.Elapsed.TotalSeconds, $lastFile.Replace($env:USERPROFILE, '~'))) }
        $fileSw.Reset()
        $ext = $f.Extension
        if ($rs.CertExt.Contains($ext)) { $certFiles.Add($f.FullName); continue }
        if (-not $rs.TextExt.Contains($ext) -and $f.Name -notmatch '^\.env|credentials$|^config$|_history') { continue }
        if ($f.Length -eq 0 -or $f.Length -gt $rs.MaxBytes) { continue }
        if ($scanned -gt 0 -and $scanned % 10000 -eq 0) { Write-Host ("    ... {0:N0}개 검사, {1:N0}초, 현재 {2}" -f $scanned, $sw.Elapsed.TotalSeconds, $f.DirectoryName.Replace($env:USERPROFILE, '~')) -ForegroundColor DarkGray }
        $lastFile = $f.FullName
        $fileSw.Start()
        $text = $null
        try {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            $probe = [Math]::Min(8192, $bytes.Length)
            if ([Array]::IndexOf($bytes, [byte]0, 0, $probe) -ge 0) {
                # UTF-16 LE 텍스트(BOM)면 디코딩, 아니면 바이너리로 보고 건너뜀
                if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $text = [Text.Encoding]::Unicode.GetString($bytes) } else { continue }
            } else { $text = [Text.Encoding]::UTF8.GetString($bytes) }
        } catch { continue }
        $scanned++
        if (-not $quick.IsMatch($text)) { continue }
        # 일반 할당 규칙은 설정 파일에만 (소스 코드의 token= 변수 할당 오탐 방지)
        $allowGen = $rs.GenericExt.Contains($ext) -or $f.Name -match '^\.env|credentials|_history'
        $hits = @(Find-SecretsInText $text $rs $allowGen | Sort-Object Line)
        if (-not $hits) { continue }
        $fileHits++
        $broad = Get-BroadReadAce $f.FullName
        $sev = Get-MaxSeverity $hits
        $status = if ($sev -eq 'CAT III' -and -not ($hits | Where-Object { $_.RuleId -notin 'generic', 'jwt', 'private-key' })) { 'WARN' } else { 'FAIL' }
        if ($broad) { $status = 'FAIL'; $sev = 'CAT I' }
        $ev = ($hits | Select-Object -First 15 | ForEach-Object { "L$($_.Line) [$($_.Rule)] $($_.Masked)$(if ($_.Note) { " - $($_.Note)" })" }) -join "`n"
        if ($hits.Count -gt 15) { $ev += "`n... 외 $($hits.Count - 15)건" }
        if ($broad) { $ev += "`n[ACL] 광범위 읽기 허용: $($broad -join ', ')" }
        $rem = '키를 폐기(rotate)한 뒤 파일에서 삭제. 계속 써야 하면 Windows 자격 증명 관리자/DPAPI(SecretManagement 모듈) 또는 1Password CLI 등 비밀 저장소로 옮기고 환경변수 참조로 바꾼다.'
        if ($broad) { $rem += " ACL: icacls `"$($f.FullName)`" /inheritance:r /grant:r `"$($env:USERNAME):F`"" }
        if ($f.Name -match 'ConsoleHost_history') { $rem = '히스토리에 남은 키는 폐기 후 해당 줄 삭제. 앞으로는 Read-Host -AsSecureString 이나 비밀 저장소 사용. (Set-PSReadLineOption -AddToHistoryHandler 로 키 패턴 줄 기록 차단 가능)' }
        if ($status -eq 'WARN') { $weak.Add("$($f.FullName.Replace($env:USERPROFILE, '~'))`n$(($ev -split "`n" | Select-Object -First 3) -join "`n")"); continue }
        Add-Finding -Id "SEC-FILE-$fileHits" -Category $cat -Title "평문 비밀값: $($f.FullName.Replace($env:USERPROFILE, '~'))" -Status $status -Severity $sev -Evidence $ev -Remediation $rem -NIST $nist
    }
    $sw.Stop()
    if ($fileSw.ElapsedMilliseconds -ge 2000) { $slow.Add(('{0:N1}s  {1}' -f $fileSw.Elapsed.TotalSeconds, $lastFile.Replace($env:USERPROFILE, '~'))) }
    if ($slow.Count) {
        Add-Finding -Id 'SEC-SLOW' -Category $cat -Title "스캔이 느린 파일 $($slow.Count)개 (2초 이상)" -Status INFO -NIST $nist `
            -Evidence (($slow | Select-Object -First 40) -join "`n") -Remediation '키가 없을 폴더(퍼징 코퍼스·빌드 산출물 등)면 data\secret-rules.json 의 SkipDirs 에 추가한다.'
    }
    if ($weak.Count) {
        Add-Finding -Id 'SEC-WEAK' -Category $cat -Title "약한 신호: 설정 파일의 키·토큰형 할당 ($($weak.Count)개 파일)" -Status WARN -Severity 'CAT III' -NIST $nist `
            -Evidence (($weak | Select-Object -First 60) -join "`n`n") -Remediation '서비스별 패턴이 아니라 이름(KEY/TOKEN/SECRET=)과 엔트로피로만 잡은 항목이다. 실제 키인지 열어 보고, 맞으면 폐기 후 비밀 저장소로 옮긴다.'
    }
    Add-Finding -Id 'SEC-SUMMARY' -Category $cat -Title '파일 스캔 요약' -Status INFO -Evidence "검사 파일 $scanned 개, 비밀값 발견 파일 $fileHits 개, 소요 $([int]$sw.Elapsed.TotalSeconds)초 (제외 폴더: $($rs.SkipDirs.Count)개 규칙, $([int]($rs.MaxBytes/1MB))MB 초과 제외)" -NIST $nist

    if ($certFiles.Count) {
        Add-Finding -Id 'SEC-CERTFILE' -Category $cat -Title '인증서 설치 파일(.pfx/.p12) 존재' -Status WARN -Severity 'CAT II' -STIG 'WN11-00-000130' -NIST @('IA-5', 'SC-12') `
            -Evidence (($certFiles | Select-Object -First 20 | ForEach-Object { $_.Replace($env:USERPROFILE, '~') }) -join "`n") `
            -Remediation '개인키가 들어 있는 파일이다. 설치를 마쳤다면 삭제하고, 보관이 필요하면 암호화된 저장소로 옮긴다.'
    }

    # --- 2) 환경변수 ---------------------------------------------------------
    $envHits = foreach ($scope in 'User', 'Machine') {
        $vars = [Environment]::GetEnvironmentVariables($scope)
        foreach ($k in $vars.Keys) {
            $v = [string]$vars[$k]
            $h = @(Find-SecretsInText $v $rs | Where-Object { $_.RuleId -ne 'generic' })
            if ($h) { foreach ($x in $h) { "[$scope] $k = $($x.Masked) ($($x.Rule))" } }
            elseif ($k -match '(?i)(API_?KEY|SECRET|TOKEN|PASSWORD|ACCESS_KEY)' -and $v.Length -ge 16 -and -not $rs.Placeholder.IsMatch($v)) {
                "[$scope] $k = $(Get-MaskedSecret $v) (이름 기반)"
            }
        }
    }
    if ($envHits) {
        Add-Finding -Id 'SEC-ENV' -Category $cat -Title '영구 환경변수에 저장된 키' -Status WARN -Severity 'CAT II' -NIST $nist -Evidence ($envHits -join "`n") `
            -Remediation '영구 환경변수는 레지스트리(HKCU\Environment)에 평문 저장되고 같은 사용자의 모든 프로세스가 읽는다. 필요한 프로세스에서만 비밀 저장소로 주입하도록 바꾼다. 삭제: [Environment]::SetEnvironmentVariable("<NAME>", $null, "User")'
    } else {
        Add-Finding -Id 'SEC-ENV' -Category $cat -Title '영구 환경변수에 저장된 키' -Status PASS -NIST $nist -Evidence '사용자·시스템 환경변수에서 키 패턴 없음'
    }

    # --- 3) git credential helper / .git-credentials -------------------------
    $helper = Invoke-Native 'git' @('config', '--global', '--get-all', 'credential.helper')
    if ($helper -match '\bstore\b') {
        Add-Finding -Id 'SEC-GITCRED' -Category $cat -Title 'git credential.helper = store (평문 저장)' -Status FAIL -Severity 'CAT II' -NIST $nist -Evidence "credential.helper=$($helper -join ',')" `
            -Remediation 'git config --global credential.helper manager  (Git Credential Manager 로 전환 후 ~\.git-credentials 삭제)'
    } elseif ($helper) {
        Add-Finding -Id 'SEC-GITCRED' -Category $cat -Title 'git credential.helper' -Status PASS -NIST $nist -Evidence "credential.helper=$($helper -join ',')"
    }

    # --- 4) 자격 증명 관리자(대상 이름만) -------------------------------------
    $ck = Invoke-Native 'cmdkey' @('/list')
    if ($ck) {
        $targets = @($ck | Where-Object { $_ -match '(대상|Target):\s*(.+)$' } | ForEach-Object { ($_ -replace '^.*?(대상|Target):\s*', '').Trim() })
        Add-Finding -Id 'SEC-CREDMAN' -Category $cat -Title 'Windows 자격 증명 관리자 저장 항목' -Status INFO -NIST @('IA-5') `
            -Evidence "저장 항목 $($targets.Count)개`n$(($targets | Select-Object -First 30) -join "`n")" -Remediation '쓰지 않는 항목은 제어판 > 자격 증명 관리자에서 삭제'
    }

    # --- 5) SSH 개인키 -------------------------------------------------------
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (Test-Path $sshDir) {
        $keys = Get-ChildItem $sshDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 64KB } | ForEach-Object {
            $t = try { [IO.File]::ReadAllText($_.FullName) } catch { '' }
            if ($t -match '-----BEGIN (\w+ )?PRIVATE KEY-----') {
                $enc = if ($t -match 'OPENSSH') { Test-OpenSshKeyEncrypted $t } else { $t -match 'ENCRYPTED' }
                $broad = Get-BroadReadAce $_.FullName
                [pscustomobject]@{ Name = $_.Name; Encrypted = $enc; Broad = $broad }
            }
        }
        foreach ($k in $keys) {
            $st = if ($k.Broad) { 'FAIL' } elseif ($k.Encrypted) { 'PASS' } else { 'WARN' }
            Add-Finding -Id "SEC-SSH-$($k.Name)" -Category $cat -Title "SSH 개인키 ~\.ssh\$($k.Name)" -Status $st -Severity $(if ($st -eq 'PASS') { '' } else { 'CAT II' }) -NIST @('IA-5', 'SC-12') `
                -Evidence "암호 보호: $(if ($k.Encrypted) { '예' } else { '아니오' })$(if ($k.Broad) { "`n광범위 읽기 허용: $($k.Broad -join ', ')" })" `
                -Remediation "암호 추가: ssh-keygen -p -f `"$sshDir\$($k.Name)`"  / ssh-agent 서비스로 매번 입력 부담을 줄인다."
        }
    }
}
