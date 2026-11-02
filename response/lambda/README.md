# λ 대응 Lambda

비밀값(Discord 봇 토큰, Jira API 토큰 등)은 모두 **환경변수**로 주입하며 코드에는 포함되어 있지 않습니다.

## 함수 목록

| 함수 | 런북 | 하는 일 | 원복 |
|---|---|---|---|
| [`socing-securityhub-finding-parser`](socing-securityhub-finding-parser) | 공통 | Finding을 공통 JSON으로 정규화 | - |
| [`socing-securityhub-enrich-ec2`](socing-securityhub-enrich-ec2) | 공통 | EC2 인스턴스 정보 보강 | - |
| [`securityhub-enrich-iam`](securityhub-enrich-iam) | 공통 | IAM 주체 정보 보강 | - |
| [`king_all`](king_all) | 공통 | 런북별 Discord 알림과 승인 버튼 | - |
| [`soc-discord-approval-test`](soc-discord-approval-test) | 공통 | 버튼 응답 서명 검증, 상태 머신에 결정 전달 | - |
| [`soc-evidence-collector`](soc-evidence-collector) | 공통 | 공통 + 런북별 증거 수집 → 증거 S3 | - |
| [`soc-r1-jira-ticket`](soc-r1-jira-ticket) | R1 | MEDIUM 티켓 발행, 같은 Finding 중복 방지 | - |
| [`R2-Alert-Dedup`](R2-Alert-Dedup) | R2 | 60초 중복 억제 (DynamoDB 조건부 쓰기) | - |
| [`R2-WAF-Block`](R2-WAF-Block) | R2 | WAF IP set에 공격 IP /32 추가, 사설 · 루프백 IP 거부 | IP set에서 삭제 |
| [`R3-high-Respond`](R3-high-Respond) | R3 | HIGH: 발급 시각 이전 세션만 Deny (`SOC-R3-RevokeOlderSessions`) | 정책 분리 |
| [`r3_critical_respond`](r3_critical_respond) | R3 | CRITICAL: 역할 전체 Deny (`SOC-R3-Quarantine`) | 정책 분리 |
| [`R4_Lambda_Function`](R4_Lambda_Function) | R4 | 대상 EC2의 SG를 격리용 SG로 교체 | 원래 SG로 복구 |
| [`R4_Critical_Function`](R4_Critical_Function) | R4 | CRITICAL 시 여러 EC2 중 격리 대상 선택 · 승인 | 원래 SG로 복구 |
| [`R7-Webshell-High-Response`](R7-Webshell-High-Response) | R6 → R4 (웹셸) | 웹셸 HIGH 조사 · 대응 | - |
| [`R7-Webshell-Critical-Response`](R7-Webshell-Critical-Response) | R6 → R4 (웹셸) | 웹셸 CRITICAL 조사 · 대응 | - |
| [`R7-TCPDoS-Response`](R7-TCPDoS-Response) | R4 (TCP DoS) | SG 교체, 지정 연결 종료, NACL deny, IAM Deny, EBS 스냅샷 | restore 모드 |

## 공통 실행 권한

- 대응 Lambda는 **Security 계정**에서 실행되고, Workload 계정 리소스에는 **AssumeRole**로 접근합니다.
- 역할마다 필요한 API만 허용합니다. 예: `R2-WAF-Block`은 `wafv2:UpdateIPSet`, `R4_Lambda_Function`은 `ec2:ModifyNetworkInterfaceAttribute`.

## 격리 방식

| 격리 유형 | 방식 | 고려 사항 |
|---|---|---|
| 증거 보존 | 격리 전 EBS 스냅샷, SSM으로 휘발성 정보 수집 | 격리 후에는 휘발성 정보가 사라질 수 있음 |
| 네트워크 (SG) | 인 · 아웃바운드 규칙 없는 격리 SG로 교체 | 이미 맺어진 연결은 안 끊길 수 있어 TCP DoS는 `ss -K`로 별도 종료 |
| 네트워크 (NACL) | 공유 NACL에 /32 deny | 같은 서브넷 통신은 못 막음 |
| IAM | 명시적 Deny 정책 연결 | 역할의 임시 세션은 비활성화가 아니라 무효화해야 함 |

### R3 격리 정책 비교

| | `SOC-R3-RevokeOlderSessions` | `SOC-R3-Quarantine` |
|---|---|---|
| 조건 | `aws:TokenIssueTime` < 특정 시각 | 없음 |
| 막는 대상 | 그 시각 **이전에 발급된** 자격증명만 | 이 역할로 받은 **모든** 자격증명 |
| 효과 | 탈취된 토큰만 죽이고 서비스 유지 | 역할 자체를 사용 불가로 |
| 쓰는 곳 | HIGH · CRITICAL | CRITICAL |

---
[← 메인으로](/README.md)
