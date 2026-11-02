# ☁️ CloudTrail 탐지 파이프라인 (B줄기)

> 🙋 **담당: 본인**

GuardDuty가 잡지 못하는 클라우드 API 공격을 CloudTrail 로그로 탐지하는 경로입니다.

| 파일 | 내용 |
|---|---|
| [`ossec-aws-s3.xml`](ossec-aws-s3.xml) | Wazuh Manager의 aws-s3 모듈 설정 |
| [`local_internal_options.conf`](local_internal_options.conf) | JSON 디코더 필드 수 한도 상향 |
| [`../wazuh/local_rules.xml`](../wazuh/local_rules.xml) | 탐지 룰 100300 · 100301 |

## 왜 필요한가

<!-- ✍️ 키워드: GuardDuty가 못 잡는 IAM 권한상승 · A줄기 · GuardDuty · B줄기 구분 · GuardDuty = 센서, Wazuh = 통합 본부
     참고: 노션 '의사결정 로그 (10/03)', '설계 근거 — 왜 Wazuh까지 쓰는가' -->

## 1단계 · Organization Trail 구성

<!-- ✍️ 키워드: buildyoursoc-org-trail · 조직 전체 · 멀티 리전 · Security 계정 S3 버킷 · AWSLogs/<org-id>/<계정>/ 경로
     참고: 노션 'CloudTrail Organization Trail 구성', 'CloudTrail 중앙 로그 저장 구성' -->

## 2단계 · S3 → Wazuh 연동 (aws-s3 wodle 설정 · IAM 권한)

<!-- ✍️ 키워드: aws-s3 wodle · interval 10m · aws_organization_id · Manager 인스턴스 역할에 S3 읽기 권한 (키 파일 없음)
     참고: 노션 '권한상승 확인 › C-2: Wazuh 연결' -->

## 3단계 · 탐지 룰 100300 / 100301

<!-- ✍️ 키워드: 부모 80200 · CreateFunction · assumed-role/.../i- · requestParameters.role · level 10 HIGH / 13 CRITICAL · T1548
     참고: 노션 '🛠️ 트러블슈팅' › 탐지 룰 (최종) -->

## 트러블슈팅: 경보가 울리지 않았던 3가지 원인

<!-- ✍️ 키워드: ① decoder_order_size 1024 · ② aws_organization_id 미설정 (핵심 원인) · ③ 80202 eventName 화이트리스트 (aws-eventnames) · A안 vs B안 비교
     참고: 노션 '🛠️ 트러블슈팅: CloudTrail 기반 권한상승 탐지 룰 경보 미생성' -->

## 검증 결과

<!-- ✍️ 키워드: privesc-poc-6 · rule 100301 CRITICAL · 2026-10-06
     참고: 노션 '🛠️ 트러블슈팅' › 검증 (최종) -->

---
[← 메인으로](/README.md)
