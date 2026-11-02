# ⚙️ 대응 워크플로 (Step Functions)

| 파일 | 내용 |
|---|---|
| [`socing-securityhub-finding-machine.asl.json`](socing-securityhub-finding-machine.asl.json) | 메인 상태 머신 (`renewal-socing-securityhub-finding-machine`) |
| [`tcp-dos-response.asl.json`](tcp-dos-response.asl.json) | TCP DoS 대응 테스트 상태 머신 |
| [`eventbridge-rules.json`](eventbridge-rules.json) | EventBridge 규칙과 이벤트 패턴 |

## 이벤트 처리 흐름

| 순서 | 단계 | 구성요소 | 하는 일 |
|---|---|---|---|
| 1 | 탐지 | Wazuh (Suricata 포함), GuardDuty | Finding 생성 |
| 2 | 통합 | Security Hub | ASFF로 모음 |
| 3 | 선별 | EventBridge | 조건에 맞는 Finding만 Step Functions로 |
| 4 | 정규화 | `finding-parser` | 공통 JSON 생성 |
| 5 | 보강 | EnrichContext | EC2면 인스턴스 정보 조회 |
| 6 | 분기 | RouteRunbook · RouteSeverity | MEDIUM 이하 R1, 나머지 category로 R2 ~ R6 |
| 7 | 중복 억제 | `R2-Alert-Dedup` + DynamoDB | 60초 안 같은 IP · 런북은 1건만 |
| 8 | 알림 · 승인 | `king_all` + Discord 버튼 | 승인 대기 15분 |
| 9 | 대응 | 런북별 대응 Lambda | 차단 · 격리 |
| 10 | 기록 | Jira, 증거 S3 | MEDIUM 티켓, HIGH 이상 증거 보관 |

## EventBridge 규칙

| 규칙 | 조건 |
|---|---|
| GuardDuty 경로 | `Security Hub Findings - Imported`, Workload 계정, GuardDuty, HIGH · CRITICAL, Workflow NEW, RecordState ACTIVE |
| Wazuh 경로 | HIGH 이상, Finding ID가 `wazuh-rule`로 시작 |

## 상태 머신

승인을 기다려야 해서 콜백(`waitForTaskToken`)을 지원하는 **Standard 유형**을 씁니다.

| 상태 | 유형 | 하는 일 |
|---|---|---|
| NormalizeFinding | Task | 공통 JSON 생성 |
| RouteEnrichment | Choice | EC2면 보강, 아니면 건너뜀 |
| EnrichContext | Task | EC2 정보 보강 |
| RouteRunbook | Choice | severity와 category로 런북 지정 |
| RouteSeverity_Rn | Choice | HIGH / CRITICAL / 그 외 |
| NotifyDiscordAndWaitApproval_Rn | Task (`waitForTaskToken`, 900초) | 알림 후 버튼 응답 대기 |
| ApprovalReceived_Rn | Choice | APPROVED면 대응, 아니면 기록 후 종료 |
| NotifyCriticalDiscord | Task | CRITICAL 결과 통보 |

## 승인 모델

| 규칙 | 내용 | 이유 |
|---|---|---|
| 대응 대상 | Workflow NEW, RecordState ACTIVE만 | 이미 처리한 Finding에 다시 조치하지 않기 위해 |
| 승인 권한자 | Discord 서명 · 채널 · 승인자 확인 | 아무나 버튼을 눌러 차단하는 것 방지 |
| 승인 대기 | 15분 | |
| 중복 응답 | 첫 결정만 반영 | 두 사람이 다른 버튼을 눌러도 한 번만 실행 |
| 결정 종류 | APPROVED · FALSE_POSITIVE · ALLOWED_ACTIVITY | 오탐과 정상 행위도 판단 기록으로 남김 |
| 미승인 · 시간 초과 | 조치 없이 기록만 | 잘못된 차단보다 조치를 미루는 쪽을 택함 |
| 자동 실행 | R2 CRITICAL (유출 성공) | 피해가 확정된 경우라 바로 차단 |

---
[← 메인으로](/README.md)
