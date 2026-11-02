# 🏗️ Security 계정 인프라

> 🙋 **담당: 본인**

로그 수집 · 분석 서버가 위치하는 Security 계정의 네트워크와 서버 구성입니다.

## 구성도

<!-- ✍️ 키워드: 10.1.0.0/16 · Public 10.1.0.0/24 (NAT · IGW) · Private 10.1.10.0/24 · Wazuh Manager 10.1.10.10 · t3.medium
     참고: 노션 '4주차 전반전' -->

## 설계 결정 (Private 배치 · NAT Instance · 단일 AZ)

<!-- ✍️ 키워드: Private 서브넷 배치 이유 · NAT Gateway 대신 NAT Instance (비용 · 멘토 조언) · 단일 AZ ap-northeast-2a · CIDR 비중첩 (Peering 조건)
     참고: 노션 '4주차 전반전 › 3. 설계 결정 사항' -->

## VPC Peering (Workload ↔ Security)

<!-- ✍️ 키워드: 연결 상태 · 라우팅 테이블 · SG 3중 관문 · SG 참조 대신 CIDR · TCP 1514 / 1515 · ping 지연 비교 (Peering vs NAT)
     참고: 노션 '4주차 후반전 › 3-4, 5. 배운 것' -->

## Wazuh Manager 구축과 크로스 계정 Agent 연동

<!-- ✍️ 키워드: SSM 접속 · 포트포워딩 · SSO 프로필 · MANAGER_IP 주입 · Agent 등록 (client.keys)
     참고: 노션 '4주차 후반전 › 3. 작업 순서' -->

## 트러블슈팅

<!-- ✍️ 키워드: 계정 · IP 혼동 · 보안그룹 이름 중복 · WSL 환경 (AWS CLI · Session Manager Plugin)
     참고: 노션 '삽질로그1', '삽질로그2', '4주차 후반전 › 4' -->

---
[← 메인으로](/README.md)
