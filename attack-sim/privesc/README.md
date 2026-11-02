# 🗡️ IAM 권한상승 재현

> 🙋 **담당: 본인**

EC2 인스턴스 역할 자격증명 탈취부터 `iam:PassRole` + Lambda 생성을 통한 권한상승까지 재현한 기록입니다.

> ⚠️ 통제된 실습 환경에서만 수행했으며, 실습 후 모든 리소스를 원복했습니다.

| 파일 | 내용 |
|---|---|
| [`privesc-poc.py`](privesc-poc.py) | 관리자 역할을 입혀 실행한 Lambda (자기 신원 확인용) |

## 공격 흐름

```
① IMDS 자격증명 탈취 ─▶ ② 정찰 ─▶ ③ CreateFunction (role=관리자 역할) ─▶ ④ Invoke ─▶ 관리자 권한 획득
   (S-5 · T1552.005)                  └─ PassRole이 CreateFunction에 포함 (S-6 · T1548)
```

| 단계 | ATT&CK | 탐지 |
|---|---|---|
| IMDS 자격증명 탈취 | T1552.005 | GuardDuty `InstanceCredentialExfiltration`, CloudTrail |
| IAM 남용 · 권한상승 | T1078.004 · T1548 | CloudTrail → Wazuh 100300 · 100301 |

## 사전 세팅 (취약 정책 부착)

| 항목 | 값 |
|---|---|
| 탈취 대상 역할 | `web-alb-demo-ssm-role` (원래 `AmazonSSMManagedInstanceCore`만) |
| 훈련용 취약 권한 | `iam:PassRole` + `lambda:CreateFunction` · `InvokeFunction` (인라인 `vuln-privesc-demo`) |
| 악용할 상위 역할 | `escalated-demo-role` (AdministratorAccess) |
| 초기 셸 확보 | 웹 취약점 대신 SSM 접속으로 대체 |

<!-- ✍️ 직접 작성 · 참고: 노션 '권한상승 시나리오 — 사전 세팅 세트' -->

## 단계별 재현

<!-- ✍️ 직접 작성 · 참고: 노션 '권한상승 확인 › 1. 자격증명 탈취 ~ PassRole 공격으로' -->

## 탐지 결과

| 룰 | 결과 |
|---|---|
| 100300 (HIGH) | |
| 100301 (CRITICAL) | ✅ `privesc-poc-6`에서 탐지 (2026-10-06) |

## 원복 절차

```bash
aws lambda delete-function --function-name privesc-poc --profile workload
aws iam detach-role-policy --role-name escalated-demo-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile workload
aws iam delete-role-policy --role-name web-alb-demo-ssm-role \
  --policy-name vuln-privesc-demo --profile workload
```

원복 명령은 실환경에서는 그대로 **대응 조치**가 됩니다 (R3 런북 5장).

<!-- ✍️ 직접 작성 · 참고: 노션 '권한상승 시나리오 — 생성된 리소스 정리 (2026-10-03)' -->

## 의사결정 기록

| 결정 | 대안 | 이유 |
|---|---|---|
| 취약 권한을 의도적으로 부착 | 최소권한 유지 ("권한상승 불가"로 결론) | |
| PassRole + Lambda 생성 경로 | `AttachRolePolicy`, `CreateAccessKey` | |

<!-- ✍️ 직접 작성 · 참고: 노션 '의사결정 로그 — 권한상승 시나리오 설계 (2026-10-03)' -->

---
[← 메인으로](/README.md)
