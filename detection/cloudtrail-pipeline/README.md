# ☁️ CloudTrail 탐지 파이프라인 (B줄기)

> 🙋 **담당: 본인**

GuardDuty가 잡지 못하는 클라우드 API 공격을 CloudTrail 로그로 탐지하는 경로입니다.

```
Organization Trail → S3 → Wazuh aws-s3 모듈 → 커스텀 룰 → Security Hub
```

## 왜 필요한가

<!-- TODO -->

## 1단계 · Organization Trail 구성

<!-- TODO: 조직 Trail 생성, 대상 계정·리전, S3 저장 경로 -->

## 2단계 · S3 → Wazuh 연동 (aws-s3 wodle 설정 · IAM 권한)

<!-- TODO -->

## 3단계 · 탐지 룰 100300 / 100301

<!-- TODO -->

## 트러블슈팅: 경보가 울리지 않았던 3가지 원인

<!-- TODO -->

## 검증 결과

<!-- TODO -->

---
[← 메인으로](/README.md)
