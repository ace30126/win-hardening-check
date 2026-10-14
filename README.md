# 내 PC 보안 점검기 (Windows Hardening Audit)

**더블클릭 한 번으로** 내 Windows PC의 보안 상태를 점검하고, 무엇부터 고치면 되는지 **"오늘 할 일"** 로 알려 주는 도구입니다.

- **아무것도 바꾸지 않습니다.** 읽기만 하고, 설정 변경·파일 삭제를 하지 않습니다.
- **인터넷으로 아무것도 보내지 않습니다.** 결과는 내 PC 안에만 저장됩니다.
- **설치가 필요 없습니다.** Windows에 기본으로 들어 있는 PowerShell만 씁니다.
- 판정 기준: 미 국방부 정보시스템국(DISA)의 *Windows 11 보안 기술 구현 가이드(STIG)* 262개 규칙 + 미 국립표준기술연구소(NIST) SP 800-53 Rev.5

## 무엇을 점검하나요?

| 영역 | 쉬운 설명 |
|---|---|
| 1. 흩어진 API 키 | `.env`, 설정 파일, 메모장, PowerShell 기록 등에 **평문으로 저장된 키·토큰**(OpenAI·Anthropic·AWS·GitHub 등 32종)을 찾습니다. 키 값은 저장하지 않고 앞뒤 몇 글자만 표시합니다. |
| 2. 네트워크 | 외부에서 들어올 수 있는 **열린 포트**, 공유기 없이 인터넷에 직접 연결됐는지, 방화벽 허용 규칙 |
| 3. 의심 프로그램 | 시작 프로그램·서비스·예약 작업 중 서명 없는 것, 드라이버, Windows Defender 상태 |
| 4. 기본 보안 설정 | Windows 보안 설정 약 200개 (STIG 기준, 개인 PC에 맞게 조정) |
| 5. 원격 접속 | Chrome 원격 데스크톱·AnyDesk·TeamViewer 등 원격 제어 도구 30종과 그 설정 |
| 6. 기타 | 브라우저·VS Code 확장, 관리자 계정 사용, 랜섬웨어 대비, 개방형 Wi-Fi |

## 사용법 (3단계)

1. 이 페이지 위쪽 초록색 **`Code` 버튼 → `Download ZIP`** 으로 내려받고 압축을 풉니다.
2. 압축을 푼 폴더에서 **`Run-Audit.cmd`** 를 더블클릭합니다.
   - "Windows의 PC 보호" 파란 창이 뜨면 **추가 정보 → 실행** 을 누릅니다. (인터넷에서 받은 파일이라 나오는 확인 창입니다)
   - "이 앱이 디바이스를 변경하도록 허용하시겠어요?" 창에서 **예** 를 누릅니다. 관리자 권한이 있어야 보안 설정 약 90개를 더 볼 수 있습니다. **아니요** 를 눌러도 나머지 점검은 진행됩니다.
3. **10~20분** 기다리면 보고서가 브라우저로 열립니다. 맨 위 **"오늘 할 일"** 부터 보세요.

> 코드를 직접 확인하고 싶다면 모든 점검 내용이 `checks\` 폴더의 PowerShell 스크립트에 그대로 있습니다.

## 보고서 읽는 법

- **오늘 할 일**: 중요한 순서대로 묶은 조치 목록입니다. "해당 항목 보기"를 누르면 근거와 조치 방법이 나옵니다.
- **FAIL**: 기준에 맞지 않음 / **WARN**: 확인 권장 / **PASS**: 정상 / **N/A**: 개인 PC에는 해당 없음 / **SKIP**: 관리자 권한이 없어 못 봄
- **CAT I · II · III**: 위험 등급입니다. CAT I 이 가장 높습니다.
- 다시 점검하면 **이전 회차 대비** 새로 생긴 문제와 해결된 문제를 보여 줍니다.

**보고서는 공유하지 마세요.** 키가 들어 있는 파일 경로와 키 앞뒤 몇 글자가 들어 있습니다. 보고서 폴더(`reports\`)는 본인만 열 수 있게 자동으로 잠깁니다.

## 자주 묻는 질문

**Q. 백신이 경고하거나 오래 걸려요.**
API 키 점검이 사용자 폴더의 텍스트 파일을 하나씩 읽기 때문입니다. 파일이 많으면 20분 이상 걸릴 수 있습니다. 키 점검을 빼려면 PowerShell에서 `-Skip Secrets` 옵션을 쓰세요.

**Q. FAIL이 100개가 넘어요. 다 고쳐야 하나요?**
아닙니다. 미 국방부 기준이라 일반 PC에는 엄격합니다. "오늘 할 일" 상위 3~5개만 처리해도 위험이 크게 줄어듭니다.

**Q. 조치는 자동으로 해 주나요?**
아니요. 설정을 잘못 바꾸면 쓰던 프로그램이 안 될 수 있어서, 이 도구는 **점검과 안내만** 합니다. 항목마다 직접 적용할 수 있는 방법을 적어 두었습니다. 바꾸기 전에 시스템 복원 지점을 만들어 두세요.

**Q. Windows 10에서도 되나요?**
실행은 됩니다. 판정 기준이 Windows 11 STIG라 일부 항목은 맞지 않을 수 있습니다.

## 고급 옵션 (PowerShell)

```powershell
cd <압축 푼 폴더>
powershell -ExecutionPolicy Bypass -File .\Invoke-HardeningAudit.ps1 [옵션]
```

| 옵션 | 설명 |
|---|---|
| `-Skip Secrets,Network,...` | 영역 건너뛰기 (Secrets, Network, Integrity, Baseline, RemoteAccess, SupplyChain) |
| `-ScanPath <경로>` | API 키를 찾을 폴더 (기본: 내 사용자 폴더) |
| `-AuditProfile Strict` | STIG 원문 그대로 판정 (기본 `Personal` 은 Home·개인 PC 적용성 반영) |
| `-NewBaseline` | 핵심 시스템 파일 해시 기준선 저장 (Windows 업데이트 직후 권장, 이후 변조 비교) |
| `-Deep` | 시스템 파일 무결성 검사(sfc, DISM) 추가, 관리자 필요, 10분 내외 |
| `-CompareTo <results.json>` | 비교할 이전 결과 지정 (기본: 직전 결과) |

- 개인 PC 적용성(N/A·권고 처리)은 `data\stig-overrides.json`, 키 점검 제외 폴더는 `data\secret-rules.json` 의 `SkipDirs` 에서 조정합니다.
- 결과는 `reports\<시각>\report.html` 과 `results.json` 으로 저장됩니다.

## 기준 데이터 갱신 (개발자용)

새 STIG가 나오면 XCCDF와 CCI 목록을 `src\` 에 넣고 실행합니다.

```powershell
.\tools\Build-Controls.ps1 -StigXml .\src\U_MS_Windows_11_STIG_V2R?_Manual-xccdf.xml -CciXml .\src\U_CCI_List.xml
```

- STIG: DISA 배포본 (Microsoft PowerStig 저장소 `source/StigData/Archive/Windows.Client` 보관본)
- CCI: <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip>

## 한계

- 점검 도구이지 백신이 아닙니다. 악성코드 탐지는 Windows Defender 등 백신에 맡기세요.
- 키 탐지는 패턴 기반이라 놓치거나 잘못 잡는 경우가 있습니다(테스트용 가짜 키 등).
- 표준 사용자 계정에서 다른 관리자 계정 암호로 승인하면, 일부 사용자별 설정(HKCU)은 그 관리자 계정 기준으로 읽힙니다.

## 라이선스·출처

MIT License. 판정 기준과 탐지 규칙의 출처는 [NOTICE.md](NOTICE.md)에 있습니다.
