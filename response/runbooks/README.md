# 📔 런북

Finding 유형별 대응 절차입니다.

런북은 **경보가 떴을 때 당직 분석가가 무엇을 하는가**를 적은 대응 매뉴얼입니다. 탐지 룰 구현 근거나 공격 재현 같은 설계 · 검증 내용은 [설계 문서](../../docs)에 둡니다.

## 공통 양식

모든 런북은 같은 섹션 구조를 따릅니다.

| # | 섹션 | 내용 |
|---|---|---|
| 0 | 문서 정보 | 런북 ID, 담당, 연계 런북 |
| 1 | 트리거 · 분류 기준 | 어떤 Finding이 이 런북으로 오는가, 다른 런북과의 경계 |
| 2 | 심각도 판정 | HIGH / CRITICAL을 가르는 기준 |
| 3 | 대응 대상 | 조치할 리소스 종류 |
| 4 | 조사 절차 | 판별 필드, 조회 명령어, 판단 결론 |
| 5 | 대응 조치 | 단계별 명령어와 승인 필요 여부 |
| 6 | 승인 · 서비스 영향 | 정탐 · 오탐일 때의 영향 |
| 7 | 완료 · 격리 확인 | 실제로 차단됐는지 검증 |
| 8 | 오탐 처리 · 기록 | |
| 9 | 대표 사례 | |
| 10 | 사후 조치 · 재발 방지 | |

## R3 런북 🙋

> 공동 작성 — **탐지 · 판단 파트 담당: 본인** / 자동화 · 알림 · 대응 Lambda: 팀원

<!-- ✍️ 키워드: HIGH vs CRITICAL 기준선 (권한 범위 이탈 성공 여부) · 세션 무효화 ≠ 키 비활성화 · NAT IP 함정 · Invoke는 데이터 이벤트 · 완료 확인 (AccessDenied)
     참고: 노션 'R3 RunBook — IAM 자격증명·권한상승 대응 런북(상세판)' -->

## R1 ~ R6 목록

Finding은 **심각도로 먼저** 나누고(MEDIUM 이하 → R1), HIGH 이상은 **ATT&CK 전술(category)** 에 따라 분기합니다. 조건에 맞지 않으면 R6으로 갑니다.

| 런북 | 다루는 영역 | 분류 조건 | 대표 사례 | 대응 |
|---|---|---|---|---|
| R1 | 조사 · 티켓 | 심각도 MEDIUM 이하 | Wazuh MEDIUM (예: Rule 533) | MEDIUM은 Jira 티켓 + Discord, LOW · INFO는 기록 |
| R2 | 웹 진입 · 탐색 | Initial Access · Reconnaissance | Wazuh 100120, 100131 | HIGH 승인 후 WAF 차단, CRITICAL 자동 차단 |
| R3 | IAM 자격증명 | Credential Access · `AwsIamAccessKey` | Wazuh 100301, GuardDuty `InstanceCredentialExfiltration` | 명시적 Deny로 세션 무효화 |
| R4 | 침해 워크로드 | Command and Control (+ TorClient 등) | GuardDuty `BitcoinTool.B`, `AttackSequence:EC2` | 승인 후 격리 SG 교체 |
| R5 | 데이터 · 서비스 | Exfiltration · Impact | GuardDuty `DNSDataExfiltration` | 승인 분기, 판단 결과 기록 |
| R6 | 미분류 | 위 조건에 맞지 않음 | Wazuh 31151, 100220 | 원문 보존, 수동 재분류, 분류 규칙 보완 |

분류 우선순위는 **명시 지정한 Finding 유형 → 일반 category → 리소스별 세부 조치** 순입니다.

---
[← 메인으로](/README.md)
