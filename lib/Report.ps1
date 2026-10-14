# 보고서: ACL 제한, 이전 회차 비교, 단일 파일 HTML

function Protect-ReportDirectory([string]$Path, [string]$ExtraSid) {
    # 상속 끊고 현재 사용자 + SYSTEM 만 (경로·마스킹 값도 민감 정보). 다른 관리자 계정으로 승격됐으면 원래 사용자도
    try {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $sids = @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
        if ($ExtraSid) { $sids += New-Object Security.Principal.SecurityIdentifier($ExtraSid) }
        foreach ($sid in $sids) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inh, 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch { Write-Warning "보고서 폴더 ACL 설정 실패: $($_.Exception.Message)" }
}

function Get-FindingKey($f) { if ($f.Id -like 'SEC-FILE-*') { "SEC-FILE|$($f.Title)" } else { $f.Id } }

function Get-FindingDiff($Current, [string]$PrevJson) {
    if (-not $PrevJson -or -not (Test-Path $PrevJson)) { return $null }
    try { $prev = Get-Content $PrevJson -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    $bad = 'FAIL', 'WARN'
    $p = @{}; foreach ($f in $prev.Findings) { $p[(Get-FindingKey $f)] = $f }
    $c = @{}; foreach ($f in $Current) { $c[(Get-FindingKey $f)] = $f }
    [ordered]@{
        PrevStarted = $prev.Meta.Started
        New = @($c.Keys | Where-Object { $c[$_].Status -in $bad -and (-not $p.ContainsKey($_) -or $p[$_].Status -notin $bad) } | ForEach-Object { [ordered]@{ Id = $c[$_].Id; Title = $c[$_].Title; Status = $c[$_].Status } })
        Resolved = @($p.Keys | Where-Object { $p[$_].Status -in $bad -and $c.ContainsKey($_) -and $c[$_].Status -eq 'PASS' } | ForEach-Object { [ordered]@{ Id = $p[$_].Id; Title = $p[$_].Title; Status = $p[$_].Status } })
    }
}

# 보고서 맨 위 "오늘 할 일": 점검 결과를 일반 사용자 말로 묶어 우선순위대로. 정의 순서가 곧 우선순위
function Get-TopActions($Findings) {
    $bad = 'FAIL', 'WARN'
    $platform = 'WN11-00-000020', 'WN11-00-000030', 'PLT-HVCI', 'PLT-LSAPPL', 'INT-DEFENDER', 'PLT-UPDATE'
    $defs = @(
        @{ Match = { $_.Id -like 'SEC-FILE-*' -and $_.Status -eq 'FAIL' }
            Title = '평문으로 저장된 API 키·토큰 파일 {0}개'
            Why = '이 파일이 새어 나가면 남이 내 클라우드·AI 계정을 쓰고 요금은 내가 냅니다. 메신저·백업·화면 공유로도 쉽게 새어 나갑니다.'
            How = '1) 키를 발급한 서비스 웹사이트에서 그 키를 폐기(삭제)하고 새로 발급  2) 파일에서 키를 지우거나 파일을 삭제  3) 새 키는 꼭 필요한 한 곳에만. 파일만 지우고 폐기를 안 하면 이미 복사된 키는 계속 살아 있습니다.' }
        @{ Match = { $_.Id -eq 'NET-PUBLICIP' -and $_.Status -in $bad }
            Title = 'PC가 인터넷에 직접 연결되어 있음'
            Why = '공유기 없이 연결되면 PC에서 열어 둔 모든 포트가 전 세계에서 보입니다. 자동 공격 도구가 하루에도 수천 번 두드립니다.'
            How = '가장 쉬운 방법은 공유기(Wi-Fi 공유기도 됨) 뒤에 연결하는 것입니다. 어렵다면 아래 "열린 포트" 항목부터 정리하세요.' }
        @{ Match = { $_.Id -in 'NET-LISTEN', 'NET-INBOUND', 'NET-FW-INBOUND', 'NET-FW', 'NET-PORTPROXY', 'NET-SHARE' -and $_.Status -in $bad }
            Title = '외부에서 접속할 수 있는 통로 {0}건'
            Why = '열린 포트와 방화벽 허용 규칙은 집의 열린 창문과 같습니다. 쓰지 않는 창문은 닫아 두는 게 안전합니다.'
            How = '항목을 눌러 어떤 프로그램이 포트를 열었는지 확인 → 모르는 프로그램은 끄거나 삭제. 개발 서버는 0.0.0.0 대신 127.0.0.1 로 실행. 방화벽: 설정 > 개인 정보 및 보안 > Windows 보안 > 방화벽 및 네트워크 보호 > 앱이 방화벽을 통과하도록 허용.' }
        @{ Match = { $_.Id -like 'RA-*' -and $_.Status -in $bad -and $_.Severity -in 'CAT I', 'CAT II' }
            Title = '원격 접속 도구 설정 {0}건'
            Why = '원격 접속 도구는 편리한 만큼, 설정이 느슨하면 남이 내 PC를 그대로 조종할 수 있는 통로가 됩니다.'
            How = '쓰지 않는 원격 도구는 삭제. 쓰는 도구는 항목의 조치 안내대로 PIN 생략·지원 코드 접속 등을 끕니다.' }
        @{ Match = { $_.Id -in $platform -and $_.Status -eq 'FAIL' }
            Title = 'Windows 기본 보호 기능 {0}개가 꺼져 있음'
            Why = 'Windows에 이미 들어 있는데 꺼져 있는 보호 기능입니다. 켜기만 하면 되는 가장 싼 방어입니다.'
            How = 'Windows 보안 > 장치 보안(코어 격리·메모리 무결성), 설정 > 개인 정보 및 보안 > 장치 암호화, 설정 > Windows 업데이트. Secure Boot 는 PC 제조사 BIOS 설정에서 켭니다.' }
        @{ Match = { $_.Id -like 'WN11-*' -and $_.Id -notin $platform -and $_.Status -eq 'FAIL' -and $_.Severity -eq 'CAT I' }
            Title = 'Windows 핵심 보안 설정 {0}개 (미 국방부 기준 최고 위험 등급)'
            Why = '미 국방부 보안 기준(STIG)에서 "바로 고쳐야 할" 등급으로 분류한 설정입니다.'
            How = '각 항목을 눌러 조치 방법을 확인합니다. 대부분 레지스트리 값 하나입니다. 바꾸기 전에 시스템 복원 지점을 만들어 두세요(시작 메뉴에서 "복원 지점 만들기").' }
        @{ Match = { $_.Id -eq 'SC-ACCOUNT-ADMIN' -and $_.Status -in $bad }
            Title = '매일 쓰는 계정이 관리자 계정임'
            Why = '관리자 계정으로 웹서핑·메일을 하면 악성 파일이 PC 전체 권한을 바로 얻습니다.'
            How = '설정 > 계정 > 기타 사용자에서 관리자 계정을 하나 더 만들고, 지금 계정은 표준 사용자로 바꿉니다. 프로그램 설치 때만 관리자 암호를 넣으면 됩니다.' }
        @{ Match = { ($_.Id -like 'SEC-SSH-*' -or $_.Id -in 'SEC-ENV', 'SEC-GITCRED', 'SEC-CERTFILE') -and $_.Status -in $bad }
            Title = '암호 없이 저장된 접속 키·인증서 {0}건'
            Why = 'SSH 키·인증서 파일은 그 자체가 열쇠입니다. 암호가 없으면 파일만 복사해도 서버에 들어갑니다.'
            How = '항목의 조치 안내대로 SSH 키에 암호 추가(ssh-keygen -p), 설치가 끝난 인증서 파일(.pfx) 삭제.' }
        @{ Match = { $_.Id -in 'SC-CFA', 'SC-BACKUP' -and $_.Status -in $bad }
            Title = '랜섬웨어 대비 {0}건'
            Why = '랜섬웨어는 파일을 암호화하고 돈을 요구합니다. 백업이 있으면 협박이 통하지 않습니다.'
            How = 'Windows 보안 > 바이러스 및 위협 방지 > 랜섬웨어 방지 > 제어된 폴더 액세스 켜기. 중요한 파일은 외장 디스크나 클라우드에 따로 백업.' }
    )
    $out = foreach ($d in $defs) {
        $hit = @($Findings | Where-Object $d.Match)
        if (-not $hit) { continue }
        [ordered]@{ Title = ($d.Title -f $hit.Count); Why = $d.Why; How = $d.How; Ids = @($hit | ForEach-Object { $_.Id }) }
    }
    @($out)
}

function New-HtmlReport($Result) {
    $json = ($Result | ConvertTo-Json -Depth 6 -Compress) -replace '</', '<\/' -replace ' ', ' '
    $tpl = @'
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>하드닝 점검 보고서</title>
<style>
:root{
  --bg:#f6f7f9;--panel:#ffffff;--ink:#1b1f24;--muted:#5d6570;--line:#e2e5ea;--chip:#eef0f3;
  --fail:#c62828;--fail-bg:#fdecec;--warn:#a15c00;--warn-bg:#fff4e0;--pass:#1e7a3c;--pass-bg:#e8f5ec;
  --info:#2f5fa7;--info-bg:#e9f0fb;--skip:#6b7280;--skip-bg:#f0f1f3;--accent:#2f5fa7;
  --mono:ui-monospace,SFMono-Regular,Consolas,"D2Coding",monospace;
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --bg:#111418;--panel:#1a1e24;--ink:#e6e8eb;--muted:#9aa3ad;--line:#2b313a;--chip:#232932;
  --fail:#ff7b72;--fail-bg:#3a1d1d;--warn:#f0b35a;--warn-bg:#3a2c15;--pass:#6fd08c;--pass-bg:#173022;
  --info:#7fb0ff;--info-bg:#1a2a44;--skip:#9aa3ad;--skip-bg:#23272e;--accent:#7fb0ff;}}
:root[data-theme="dark"]{
  --bg:#111418;--panel:#1a1e24;--ink:#e6e8eb;--muted:#9aa3ad;--line:#2b313a;--chip:#232932;
  --fail:#ff7b72;--fail-bg:#3a1d1d;--warn:#f0b35a;--warn-bg:#3a2c15;--pass:#6fd08c;--pass-bg:#173022;
  --info:#7fb0ff;--info-bg:#1a2a44;--skip:#9aa3ad;--skip-bg:#23272e;--accent:#7fb0ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 "Pretendard","Malgun Gothic",system-ui,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--muted);font-size:13px}
.meta b{color:var(--ink);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:20px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer}
.tile .n{font-size:26px;font-weight:700;line-height:1.1}
.tile .l{color:var(--muted);font-size:12px}
.tile.sel{outline:2px solid var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.panel h2{font-size:15px;margin:0 0 10px}
.cats{display:grid;gap:6px}
.cat{display:grid;grid-template-columns:200px 1fr 120px;gap:10px;align-items:center;font-size:13px;cursor:pointer}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--chip)}
.bar span{display:block;height:100%}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:16px 0 8px}
.controls input,.controls select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}
.controls input{flex:1;min-width:200px}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:999px;padding:4px 10px;font-size:12px;cursor:pointer}
.chip.on{background:var(--accent);color:var(--panel);border-color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;background:var(--chip)}
tr.row{cursor:pointer}
tr.row:hover td{background:var(--chip)}
.st{display:inline-block;min-width:44px;text-align:center;border-radius:6px;padding:1px 6px;font-size:12px;font-weight:700}
.FAIL{color:var(--fail);background:var(--fail-bg)}.WARN{color:var(--warn);background:var(--warn-bg)}.PASS{color:var(--pass);background:var(--pass-bg)}
.INFO{color:var(--info);background:var(--info-bg)}.SKIP,.NA,.ERROR{color:var(--skip);background:var(--skip-bg)}.ERROR{color:var(--fail)}
.sev{font-size:12px;color:var(--muted);white-space:nowrap}
.sev.c1{color:var(--fail);font-weight:700}
.id{font-family:var(--mono);font-size:12px;color:var(--muted);white-space:nowrap}
.detail td{background:var(--bg);padding:12px 14px}
.detail h4{margin:8px 0 4px;font-size:12px;color:var(--muted);font-weight:600}
pre{margin:0;white-space:pre-wrap;word-break:break-all;font-family:var(--mono);font-size:12px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;max-height:360px;overflow:auto}
.note{color:var(--warn);font-size:13px}
.diff li{margin:2px 0}
.todo{border-left:4px solid var(--fail)}
.todo ol{margin:8px 0 0;padding-left:22px}
.todo li{margin:0 0 14px}
.todo li b{font-size:15px}
.todo .why{margin:3px 0}
.todo .how{color:var(--muted);margin:3px 0 6px}
.filterNote{margin:8px 0;font-size:13px}
.theme{float:right}
footer{color:var(--muted);font-size:12px;margin-top:24px}
@media (max-width:720px){.cat{grid-template-columns:1fr}.hide-sm{display:none}th,td{padding:7px 6px}}
</style>
</head>
<body>
<div class="wrap">
  <button class="chip theme" id="theme">테마</button>
  <h1>하드닝 점검 보고서</h1>
  <div class="meta" id="meta"></div>
  <div class="panel todo" id="todoPanel" hidden><h2>오늘 할 일</h2><p class="meta">위에서부터 중요한 순서입니다. "해당 항목 보기"를 누르면 아래 표에 근거와 조치 방법이 나옵니다. 이 도구는 아무 설정도 바꾸지 않습니다.</p><ol id="todo"></ol></div>
  <div class="tiles" id="tiles"></div>
  <div class="panel" id="diffPanel" hidden><h2>이전 회차 대비</h2><div id="diff"></div></div>
  <div class="panel"><h2>영역별 결과</h2><div class="cats" id="cats"></div></div>
  <div class="controls">
    <input id="q" type="search" placeholder="검색 (제목·ID·증거·NIST)">
    <select id="cat"><option value="">전체 영역</option></select>
    <span id="sevChips"></span>
  </div>
  <div class="filterNote" id="filterNote"></div>
  <table>
    <thead><tr><th>상태</th><th>등급</th><th>항목</th><th class="hide-sm">ID</th><th class="hide-sm">NIST</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <footer id="foot"></footer>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
  var R = JSON.parse(document.getElementById('data').textContent);
  var F = R.Findings || [];
  var ORDER = {FAIL:0,ERROR:1,WARN:2,SKIP:3,INFO:4,PASS:5,'N/A':6};
  var SEV = {'CAT I':0,'CAT II':1,'CAT III':2,'':3};
  var state = {status:'', cat:'', sev:'', q:'', ids:null, idsLabel:''};
  function el(t, cls, txt){ var e=document.createElement(t); if(cls) e.className=cls; if(txt!=null) e.textContent=txt; return e; }
  function stCls(s){ return s==='N/A' ? 'NA' : s; }

  var m = R.Meta;
  var meta = document.getElementById('meta');
  [['PC', m.Computer], ['사용자', m.User], ['관리자', m.IsAdmin ? '예' : '아니오 (일부 SKIP)'], ['프로필', m.Profile], ['OS', m.OS], ['시작', m.Started.replace('T',' ')], ['소요', m.DurationSec + '초']]
    .forEach(function(p, i){ if(i) meta.appendChild(document.createTextNode(' · ')); meta.appendChild(document.createTextNode(p[0] + ' ')); meta.appendChild(el('b', null, String(p[1]))); });
  meta.appendChild(el('div', null, '기준: ' + m.Standard));

  var counts = {}; F.forEach(function(f){ counts[f.Status]=(counts[f.Status]||0)+1; });
  var cat1 = F.filter(function(f){ return f.Status==='FAIL' && f.Severity==='CAT I'; }).length;
  var tiles = document.getElementById('tiles');
  [['FAIL','FAIL'],['WARN','WARN'],['PASS','PASS'],['INFO','INFO'],['SKIP','SKIP (권한)'],['N/A','N/A (해당없음)']].forEach(function(t){
    var d = el('div','tile'); d.dataset.st = t[0];
    var n = el('div','n', String(counts[t[0]]||0)); n.className = 'n'; n.style.color = 'var(--' + ({FAIL:'fail',WARN:'warn',PASS:'pass',INFO:'info'}[t[0]]||'skip') + ')';
    d.appendChild(n); d.appendChild(el('div','l', t[1] + (t[0]==='FAIL' ? ' · CAT I ' + cat1 : '')));
    d.onclick = function(){ state.ids = null; state.status = state.status===t[0] ? '' : t[0]; render(); };
    tiles.appendChild(d);
  });

  var A = R.Actions || [];
  if (A.length){
    document.getElementById('todoPanel').hidden = false;
    var ol = document.getElementById('todo');
    A.forEach(function(a){
      var li = el('li'); li.appendChild(el('b', null, a.Title));
      li.appendChild(el('div','why', a.Why)); li.appendChild(el('div','how', a.How));
      var b = el('button','chip', '해당 항목 보기 (' + a.Ids.length + ')');
      b.onclick = function(){ state.ids = {}; a.Ids.forEach(function(i){ state.ids[i] = 1; }); state.idsLabel = a.Title; state.status = ''; state.cat = ''; state.sev = ''; render(); document.getElementById('rows').scrollIntoView({behavior:'smooth'}); };
      li.appendChild(b); ol.appendChild(li);
    });
  } else if (F.length) {
    document.getElementById('todoPanel').hidden = false;
    document.getElementById('todo').appendChild(el('li', null, '급하게 고칠 항목이 없습니다. 아래 WARN 항목을 여유 있을 때 살펴보세요.'));
  }

  if (R.Diff){
    document.getElementById('diffPanel').hidden = false;
    var dv = document.getElementById('diff');
    dv.appendChild(el('div','meta','기준 회차: ' + R.Diff.PrevStarted.replace('T',' ')));
    [['신규 문제', R.Diff.New], ['해소됨', R.Diff.Resolved]].forEach(function(p){
      dv.appendChild(el('h4', null, p[0] + ' (' + (p[1]||[]).length + ')'));
      var ul = el('ul','diff'); (p[1]||[]).forEach(function(x){ ul.appendChild(el('li', null, '[' + x.Status + '] ' + x.Title + ' (' + x.Id + ')')); }); dv.appendChild(ul);
    });
  }

  var cats = {}; F.forEach(function(f){ (cats[f.Category] = cats[f.Category] || []).push(f); });
  var catBox = document.getElementById('cats'), catSel = document.getElementById('cat');
  Object.keys(cats).sort().forEach(function(c){
    var list = cats[c], cc = {}; list.forEach(function(f){ cc[f.Status]=(cc[f.Status]||0)+1; });
    var row = el('div','cat'); row.appendChild(el('div', null, c));
    var bar = el('div','bar'), judged = list.length;
    [['FAIL','fail'],['WARN','warn'],['PASS','pass'],['INFO','info'],['SKIP','skip'],['N/A','line']].forEach(function(s){
      if(!cc[s[0]]) return; var sp = el('span'); sp.style.width = (100*cc[s[0]]/judged) + '%'; sp.style.background = 'var(--' + s[1] + ')'; sp.title = s[0] + ' ' + cc[s[0]]; bar.appendChild(sp); });
    row.appendChild(bar);
    row.appendChild(el('div','meta', 'FAIL ' + (cc.FAIL||0) + ' · WARN ' + (cc.WARN||0) + ' · ' + list.length));
    row.onclick = function(){ state.ids = null; state.cat = state.cat===c ? '' : c; catSel.value = state.cat; render(); };
    catBox.appendChild(row);
    var o = el('option', null, c); o.value = c; catSel.appendChild(o);
  });
  catSel.onchange = function(){ state.ids = null; state.cat = this.value; render(); };
  document.getElementById('q').oninput = function(){ state.ids = null; state.q = this.value.toLowerCase(); render(); };
  var sevBox = document.getElementById('sevChips');
  ['CAT I','CAT II','CAT III'].forEach(function(s){ var b = el('button','chip', s); b.onclick = function(){ state.ids = null; state.sev = state.sev===s ? '' : s; render(); }; b.dataset.sev = s; sevBox.appendChild(b); });

  function render(){
    Array.prototype.forEach.call(tiles.children, function(t){ t.classList.toggle('sel', t.dataset.st===state.status); });
    Array.prototype.forEach.call(sevBox.children, function(b){ b.classList.toggle('on', b.dataset.sev===state.sev); });
    var body = document.getElementById('rows'); body.textContent = '';
    var fn = document.getElementById('filterNote'); fn.textContent = '';
    if (state.ids){
      fn.appendChild(document.createTextNode('"' + state.idsLabel + '" 항목만 보는 중 '));
      var clr = el('button','chip','전체 보기'); clr.onclick = function(){ state.ids = null; render(); }; fn.appendChild(clr);
    }
    var list = F.filter(function(f){
      if (state.ids) return !!state.ids[f.Id];
      if (state.status && f.Status !== state.status) return false;
      if (!state.status && f.Status === 'N/A') return false;
      if (state.cat && f.Category !== state.cat) return false;
      if (state.sev && f.Severity !== state.sev) return false;
      if (state.q && (f.Title + ' ' + f.Id + ' ' + f.Evidence + ' ' + f.NIST + ' ' + f.STIG).toLowerCase().indexOf(state.q) < 0) return false;
      return true;
    }).sort(function(a,b){ return (ORDER[a.Status]-ORDER[b.Status]) || (SEV[a.Severity]-SEV[b.Severity]) || a.Category.localeCompare(b.Category) || a.Id.localeCompare(b.Id); });
    list.forEach(function(f){
      var tr = el('tr','row');
      var td = el('td'); td.appendChild(el('span','st ' + stCls(f.Status), f.Status)); tr.appendChild(td);
      tr.appendChild(el('td','sev' + (f.Severity==='CAT I' ? ' c1' : ''), f.Severity));
      var t = el('td'); t.appendChild(el('div', null, f.Title)); t.appendChild(el('div','meta', f.Category)); tr.appendChild(t);
      tr.appendChild(el('td','id hide-sm', f.Id)); tr.appendChild(el('td','id hide-sm', f.NIST));
      var det = el('tr','detail'); det.hidden = true; var dd = el('td'); dd.colSpan = 5;
      if (f.Note) dd.appendChild(el('div','note', f.Note));
      if (f.Evidence){ dd.appendChild(el('h4', null, '증거')); dd.appendChild(el('pre', null, f.Evidence)); }
      if (f.Remediation){ dd.appendChild(el('h4', null, '조치 (스크립트는 변경하지 않음 - 직접 검토 후 적용)')); dd.appendChild(el('pre', null, f.Remediation)); }
      var refs = []; if (f.STIG) refs.push('STIG ' + f.STIG); if (f.NIST) refs.push('NIST SP 800-53 Rev.5 ' + f.NIST);
      if (refs.length){ dd.appendChild(el('h4', null, '근거')); dd.appendChild(el('div', null, refs.join(' · '))); }
      det.appendChild(dd);
      tr.onclick = function(){ det.hidden = !det.hidden; };
      body.appendChild(tr); body.appendChild(det);
    });
    document.getElementById('foot').textContent = list.length + '개 표시 (N/A 는 N/A 타일을 눌러야 보임) · 이 보고서에는 파일 경로와 마스킹된 키 일부가 들어 있으니 공유하지 마세요.';
  }
  var root = document.documentElement, themes = ['', 'light', 'dark'], ti = 0;
  try { var saved = localStorage.getItem('ha-theme'); if (saved) { ti = themes.indexOf(saved); root.dataset.theme = saved; } } catch(e){}
  document.getElementById('theme').onclick = function(){ ti = (ti+1) % 3; if (themes[ti]) root.dataset.theme = themes[ti]; else delete root.dataset.theme; try { localStorage.setItem('ha-theme', themes[ti]); } catch(e){} };
  render();
})();
</script>
</body>
</html>
'@
    $tpl.Replace('__DATA__', $json)
}
