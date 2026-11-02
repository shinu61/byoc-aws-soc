# 🏢 AWS Organizations 구성

> 팀 작업 · 프로젝트 전체 구조를 이해하기 위한 참고 자료입니다.
> Organization Trail은 [CloudTrail 탐지 파이프라인](../../detection/cloudtrail-pipeline)에서 다룹니다.

## 계정 구조

| 계정 | 계정 ID | 역할 |
|---|---|---|
| Management | 526545815789 | Organizations 관리, 위임 관리자 지정 |
| Workload | 059865587057 | 공격 대상 웹 서비스 |
| Security | 229251311221 | 로그 수집 · 탐지 · 자동 대응 |

보안 서비스는 **Security 계정을 위임 관리자로 지정**해 운영합니다. 관리 계정은 조직 전체를 바꿀 수 있는 가장 큰 권한을 가지므로, 보안 업무를 그 계정에서 하면 계정이 노출됐을 때 조직 전체가 위험해집니다.

## 위임 관리자

| 서비스 | 위임 관리자 | 적용 범위 |
|---|---|---|
| GuardDuty | Security | Workload를 멤버로 연결 (서울 리전). 자동 활성화가 꺼져 있어 멤버를 수동으로 추가 |
| Security Hub | Security | Workload의 GuardDuty Finding을 Security 계정에서 수신 |
| CloudTrail | Security | 조직 Trail 하나로 두 계정의 관리 이벤트를 Security 버킷에 수집 |

## SCP

| 정책 | 내용 |
|---|---|
| `FullAWSAccess` | AWS 기본 정책 |
| `DenyLeaveAndCloseAccount` | 멤버 계정의 조직 탈퇴(`organizations:LeaveOrganization`)와 계정 해지(`account:CloseAccount`) 차단 |

## IAM Identity Center

팀원은 SSO로 로그인해 계정별 권한 세트로 접근합니다.

| 계정 | 권한 세트 |
|---|---|
| Workload | `General-Operator` |
| Security | `Security-Operator` |

---
[← 메인으로](/README.md)
