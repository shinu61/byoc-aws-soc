# 🏗️ Security 계정 인프라

> 🙋 **담당: 본인**

로그 수집 · 분석 서버가 위치하는 Security 계정의 네트워크와 서버 구성입니다.

## 구성도

```
Security VPC 10.1.0.0/16
├── Public  10.1.0.0/24   NAT Instance · IGW
└── Private 10.1.10.0/24  Wazuh Manager (10.1.10.10 · t3.medium)
        ▲
        │ VPC Peering (TCP 1514 · 1515만 허용)
        │
Workload VPC 10.0.0.0/16
├── Private 10.0.10.0/24  Web A · Suricata (Wazuh Agent)
└── Private 10.0.11.0/24  Web B (Wazuh Agent)
```

| 구성요소 | 주소 | 비고 |
|---|---|---|
| Security VPC | 10.1.0.0/16 | Workload(10.0.0.0/16)와 겹치지 않게 (Peering 조건) |
| Public 서브넷 | 10.1.0.0/24 | NAT Instance, IGW |
| Private 서브넷 | 10.1.10.0/24 | Wazuh Manager 고정 IP 10.1.10.10 |
| Wazuh Manager SG | TCP 1514 · 1515 | 출처: Workload Private 서브넷 CIDR만 |
| 관리 접속 | SSM Session Manager | 대시보드는 SSM 포트포워딩 (443 → 로컬 8443) |

## 설계 결정 (Private 배치 · NAT Instance · 단일 AZ)

<!-- ✍️ 직접 작성 · 참고: 노션 '4주차 전반전 › 3. 설계 결정 사항' -->

| 결정 | 이유 |
|---|---|
| Wazuh Manager를 Private 서브넷에 배치 | |
| NAT Gateway 대신 NAT Instance | |
| 단일 AZ (ap-northeast-2a) | |
| VPC CIDR 10.1.0.0/16 | |

## VPC Peering (Workload ↔ Security)

Peering은 **연결 상태 · 양쪽 라우팅 테이블 · 양쪽 Security Group** 세 가지가 모두 맞아야 통신됩니다. 크로스 계정에서는 상대 계정의 SG를 참조하기 어려워 출처를 CIDR로 지정했습니다.

<!-- ✍️ 직접 작성 · 참고: 노션 '4주차 후반전 › 3-4. Peering 경로 검증, 5. 배운 것' -->

## Wazuh Manager 구축과 크로스 계정 Agent 연동

<!-- ✍️ 직접 작성 · 참고: 노션 '4주차 후반전 › 3. 작업 순서' -->

## 트러블슈팅

<!-- ✍️ 직접 작성 · 참고: 노션 '삽질로그1, 삽질로그2, 4주차 후반전 › 4. 삽질 포인트' -->

---
[← 메인으로](/README.md)
