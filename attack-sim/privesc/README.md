# 🗡️ IAM 권한상승 재현

> 🙋 **담당: 본인**

EC2 인스턴스 역할 자격증명 탈취부터 `iam:PassRole` + Lambda 생성을 통한 권한상승까지 재현한 기록입니다.

> ⚠️ 통제된 실습 환경에서만 수행했으며, 실습 후 모든 리소스를 원복했습니다.

| 파일 | 내용 |
|---|---|
| [`privesc-poc.py`](privesc-poc.py) | 관리자 역할을 입혀 실행한 Lambda |

## 공격 흐름

<!-- ✍️ 키워드: IMDS 자격증명 탈취 (S-5 · T1552.005) · 정찰 · PassRole + CreateFunction (S-6 · T1548) · Invoke · Capital One 2019
     참고: 노션 '권한상승 확인', 설계문서 6.1 -->

## 사전 세팅 (취약 정책 부착)

<!-- ✍️ 키워드: web-alb-demo-ssm-role (원래 최소권한) · vuln-privesc-demo · escalated-demo-role (Admin) · 초기 셸은 SSM으로 대체
     참고: 노션 '권한상승 시나리오 — 사전 세팅 세트' -->

## 단계별 재현

<!-- ✍️ 키워드: IAM 열거 AccessDenied · PassRole 찔러보기 · whoami 결과
     참고: 노션 '권한상승 확인 › 1 ~ PassRole 공격으로' -->

## 탐지 결과

<!-- ✍️ 키워드: 100300 HIGH · 100301 CRITICAL · privesc-poc-6
     참고: 노션 '🛠️ 트러블슈팅' › 검증 -->

## 원복 절차

<!-- ✍️ 키워드: Lambda 삭제 · Admin 정책 분리 · 취약 정책 삭제 · 원복 = 실환경 대응 조치
     참고: 노션 '권한상승 시나리오 — 생성된 리소스 정리 (10/03)' -->

## 의사결정 기록

<!-- ✍️ 키워드: 최소권한 확인 → ①안 확정 · PassRole vs AttachRolePolicy vs CreateAccessKey · B줄기 구축 정당화
     참고: 노션 '의사결정 로그 — 권한상승 시나리오 설계 (10/03)' -->

---
[← 메인으로](/README.md)
