# 🌐 Suricata 탐지 룰

Web A · B의 트래픽을 **VPC Traffic Mirroring**으로 복제해 Suricata EC2 한 대에서 분석합니다. 탐지 결과(`eve.json`)는 같은 서버의 Wazuh Agent가 Manager로 보냅니다.

| 파일 | 내용 |
|---|---|
| [`local.rules`](local.rules) | 커스텀 룰 |
| [`threshold.config`](threshold.config) | 임계값 설정 |
| [`ossec-agent-eve.xml`](ossec-agent-eve.xml) | Wazuh Agent의 eve.json 수집 설정 |

## 룰 목록

| SID | 탐지 내용 | 조건 | Wazuh 룰 | 시나리오 |
|---|---|---|---|---|
| 1000001 | 포트스캔 | 출발지별 60초에 SYN 20개 | 100113 | S-1 |
| 1000002 | TCP SYN Flood | 출발지별 10초에 SYN 500개 | 100114 | S-9 |
| 1000003 | SQLi 성공 · MySQL 에러 노출 | 응답에 `You have an error in your SQL syntax` | 100130 | S-2 |
| 1000004 | SQLi 데이터 유출 | 응답에 32자리 해시 2개 이상 | 100131 | S-2 |

## Traffic Mirroring · VXLAN 구성

```
Web A · B (ENI) ──Traffic Mirroring──▶ Suricata ENI (UDP 4789 · VXLAN)
                                         │
                                         └─ suricata.yaml: VXLAN_PORTS 4789 디코딩
```

- 미러링 대상: Web A · B의 네트워크 인터페이스
- Suricata SG는 Workload VPC에서 오는 UDP 4789만 허용
- ALB를 거친 요청이라 Suricata는 ALB 내부 IP를 봅니다. 실제 공격자 IP는 `X-Forwarded-For`에서 가져옵니다.

## Wazuh 연계

```
Suricata eve.json ─▶ Wazuh Agent ─▶ Manager ─▶ 커스텀 룰(1001xx) ─▶ Security Hub
```

---
[← 메인으로](/README.md)
