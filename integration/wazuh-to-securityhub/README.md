# 🔄 Wazuh → Security Hub (ASFF) 연동

> 🙋 **담당: 본인**

Wazuh alert를 AWS Security Finding Format(ASFF)으로 변환해 Security Hub로 보내는 스크립트입니다.

| 파일 | 내용 |
|---|---|
| [`custom-securityhub.py`](custom-securityhub.py) | 변환 · 전송 스크립트 |
| [`custom-securityhub`](custom-securityhub) | integratord가 호출하는 래퍼 (Wazuh 내장 Python 실행) |
| [`ossec-integration.xml`](ossec-integration.xml) | Manager의 integration 설정 (level 6 이상) |

## 동작 방식

```
Wazuh alert ─▶ wazuh-integratord ─▶ custom-securityhub.py ─▶ BatchImportFindings ─▶ Security Hub
               (level ≥ 6)          (ASFF 변환 · 묶기)
```

| 항목 | 설계 |
|---|---|
| 전송 방식 | Manager의 integratord에 스크립트 등록, Wazuh 내장 Python + boto3 |
| 전송 대상 | level 6 이상 |
| 대상 리소스 | agent별 EC2 정보(라벨) → `AwsEc2Instance`, CloudTrail 알림은 IAM 주체 → `AwsIamAccessKey` |
| 출발지 IP | ALB 뒤라서 `X-Forwarded-For`에서 실제 IP 추출 |
| ASFF Types | `TTPs/<ATT&CK 전술>/Wazuh-Rule<룰 ID>` |
| 인증 | Manager 인스턴스 역할에 Security Hub 가져오기 인라인 정책 |

<!-- ✍️ 직접 작성 · 참고: 노션 'Wazuh ↔ Security Hub 연동 방향 문의 — 왜 이 방향을 택했는지' -->

## 필드 매핑 (level → Severity)

| Wazuh level | ASFF Severity | 예시 |
|---|---|---|
| 4 ~ 6 | LOW | SQLi 단발 (31164, level 6) |
| 7 ~ 9 | MEDIUM | 의심 행위 |
| 10 ~ 12 | HIGH | 100120 (12), 100300 (10) |
| 13 이상 | CRITICAL | 100131 · 100301 (13), 100220 (14) |

## 중복 묶기 (dedup)

| 알림 종류 | 묶음 단위 | Finding ID 예시 |
|---|---|---|
| 서버 알림 | 룰 + 서버(agent) + 날짜(KST) | `wazuh/rule-100120/agent-003/2026-10-06` |
| CloudTrail 알림 | 룰 + IAM 주체 + 날짜(KST) | |

같은 묶음에 알림이 다시 오면 새 Finding을 만들지 않고 **횟수 +1, 마지막 관측 시각만 갱신**합니다. 누적 횟수는 상태 파일(`/var/ossec/logs/securityhub-state.json`)에 저장합니다.

<!-- ✍️ 직접 작성 · 참고: 노션 'wazhu↔security hub 연결(2) › 4-D. 변환 스크립트 수정 — 왜 묶기로 바꿨는지' -->

## 사용법

```bash
python3 custom-securityhub.py --check   <alert.json>   # 한 줄 요약 + 형식 검사 (AWS 호출 없음)
python3 custom-securityhub.py --fields  <alert.json>   # 주요 필드만 출력
python3 custom-securityhub.py --dry-run <alert.json>   # 변환 결과 전체 출력
python3 custom-securityhub.py --send    <alert.json>   # 수동 전송
```

## 트러블슈팅

<!-- ✍️ 직접 작성 · 참고: 노션 'wazhu↔security hub 연결 (1)·(2)' -->

---
[← 메인으로](/README.md)
