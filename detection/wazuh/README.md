# 🔍 Wazuh 탐지 룰

| 파일 | 내용 |
|---|---|
| [`local_rules.xml`](local_rules.xml) | 커스텀 룰 |
| [`local_decoder.xml`](local_decoder.xml) | 커스텀 디코더 |
| [`lists/`](lists) | CDB 목록 (악성 IP · 도메인 · 해시, 의심 명령, audit 키) |

## 룰 목록

| 룰 ID | 탐지 내용 | 소스 | 시나리오 | ATT&CK | Severity (level) | 런북 |
|---|---|---|---|---|---|---|
| 100113 | 포트스캔 (Suricata 1000001) | Suricata | S-1 | T1046 | LOW | R1 |
| 100120 | 같은 IP에서 60초 안에 SQLi 8회 이상 | Apache | S-2 | T1190 | HIGH (12) | R2 |
| 100130 | 응답에 SQL 에러 노출 (Suricata 1000003) | Suricata | S-2 | T1190 | HIGH (12) | R2 |
| 100131 | 응답에 32자리 해시 2개 이상 · 유출 성공 (Suricata 1000004) | Suricata | S-2 | T1190 | CRITICAL (13) | R2 |
| 100110 · 100111 | DVWA 웹 경로 .php 생성 · 수정 | FIM | S-3 | T1505.003 | HIGH (12) | R6 → R4 |
| 100112 | .php 수정 + 웹셸 의심 문자열 | FIM | S-3 | T1505.003 | CRITICAL (14) | R6 → R4 |
| 100220 | 웹서버 계정의 `/bin/bash` 실행 | auditd | S-3 | T1505.003 | CRITICAL (14) | R6 → R4 |
| 100210 | 사용자 터미널에서 root 권한으로 의심 명령 실행 | auditd | 호스트 권한상승 | T1059.004 | LOW (6) | R1 |
| 100114 | TCP SYN Flood (Suricata 1000002) | Suricata | S-9 | T1499.001 | HIGH (10) | R4 |
| 100300 🙋 | EC2 인스턴스 역할이 Lambda 생성 | CloudTrail | S-6 | T1548 | HIGH (10) | R3 |
| 100301 🙋 | 인스턴스 역할이 관리자급 역할을 Lambda에 전달 | CloudTrail | S-6 | T1548 | CRITICAL (13) | R3 |

100300 · 100301은 [CloudTrail 탐지 파이프라인](../cloudtrail-pipeline)에서 자세히 다룹니다.

## 심각도 산정 기준

같은 공격이라도 **"시도"와 "성공"을 나눠** 등급을 매깁니다.

| Severity | Wazuh level | 판단 기준 | 처리 |
|---|---|---|---|
| LOW | 4 ~ 6 | 정보성, 단발 정찰 · 시도 | 기록만. 반복되면 상관 룰로 올림 |
| MEDIUM | 7 ~ 9 | 의심 행위, 당장 피해 가능성은 낮음 | Jira 검토 티켓 (R1) |
| HIGH | 10 ~ 12 | 공격 시도 · 반복 확인, 아직 성공은 아님 | 사람이 승인한 뒤 조치 |
| CRITICAL | 13 이상 | 공격 성공, 피해 확정 | 일부는 승인 없이 자동 대응 |

> SQL 에러 노출(1000003)은 따옴표 하나만 넣어도 발생합니다. CRITICAL로 두면 단순 시도에도 자동 차단이 걸리므로 HIGH로 두고, 응답에 실제 해시가 보이는 경우(1000004)만 CRITICAL로 정했습니다.

## 검증 방법

룰을 배포하기 전에 `wazuh-logtest`로 샘플 로그를 넣어 어떤 디코더와 룰에 매칭되는지 확인했습니다.

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---
[← 메인으로](/README.md)
