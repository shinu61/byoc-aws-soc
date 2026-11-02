# 🔄 Wazuh → Security Hub (ASFF) 연동

> 🙋 **담당: 본인**

Wazuh alert를 AWS Security Finding Format(ASFF)으로 변환해 Security Hub로 보내는 스크립트입니다.

| 파일 | 내용 |
|---|---|
| [`custom-securityhub.py`](custom-securityhub.py) | 변환 · 전송 스크립트 |
| [`custom-securityhub`](custom-securityhub) | integratord가 호출하는 래퍼 |
| [`ossec-integration.xml`](ossec-integration.xml) | Manager의 integration 설정 |

## 동작 방식

<!-- ✍️ 키워드: A안(Wazuh → Security Hub) vs B안 · 대응 시작점을 EventBridge 하나로 · wazuh-integratord · level 6 이상 · BatchImportFindings · X-Forwarded-For
     참고: 노션 'Wazuh ↔ Security Hub 연동 방향 문의', '8주차 wazhu↔security hub 연결' -->

## 필드 매핑 (level → Severity)

<!-- ✍️ 키워드: 4~6 LOW · 7~9 MEDIUM · 10~12 HIGH · 13+ CRITICAL · 내부 기준 (공식 1:1 대응 없음)
     참고: 노션 설계문서 4.4 -->

## 중복 묶기 (dedup)

<!-- ✍️ 키워드: 처음엔 알림마다 새 ID → 누적 · 룰 + 서버 + 날짜(KST) · CloudTrail은 룰 + IAM 주체 + 날짜 · count +1 · LastObservedAt · 상태 파일
     참고: 노션 'wazhu↔security hub 연결(2) › 4-D' -->

## 사용법

<!-- ✍️ 키워드: --check · --fields · --dry-run · --send
     참고: 노션 스크립트 상단 주석 -->

## 트러블슈팅

<!-- ✍️ 키워드: IAM 인라인 정책 추가 · 내장 Python · boto3 · wazuh 계정으로 실행
     참고: 노션 'wazhu↔security hub 연결 (1)·(2)' -->

---
[← 메인으로](/README.md)
