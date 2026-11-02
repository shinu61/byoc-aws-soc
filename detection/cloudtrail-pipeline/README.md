# ☁️ CloudTrail 탐지 파이프라인 (B줄기)

> 🙋 **담당: 본인**

GuardDuty가 잡지 못하는 클라우드 API 공격을 CloudTrail 로그로 탐지하는 경로입니다.

```
Organization Trail → S3 → Wazuh aws-s3 모듈 → 커스텀 룰 → Security Hub
```

| 파일 | 내용 |
|---|---|
| [`ossec-aws-s3.xml`](ossec-aws-s3.xml) | Wazuh Manager의 aws-s3 모듈 설정 |
| [`local_internal_options.conf`](local_internal_options.conf) | JSON 디코더 필드 수 한도 상향 |
| [`../wazuh/local_rules.xml`](../wazuh/local_rules.xml) | 탐지 룰 100300 · 100301 (`aws,privilege_escalation` 그룹) |

## 왜 필요한가

<!-- ✍️ 직접 작성 · 참고: 노션 '의사결정 로그 — 권한상승 시나리오 설계, 설계 근거 — GuardDuty가 탐지하는데 왜 Wazuh까지 쓰는가' -->

## 1단계 · Organization Trail 구성

| 항목 | 값 |
|---|---|
| Trail | `buildyoursoc-org-trail` (Management 계정) |
| 범위 | 조직 전체 계정, 멀티 리전 |
| 저장 버킷 | `buildyoursoc-cloudtrail-229251311221` (Security 계정) |
| 로그 경로 | `AWSLogs/o-xh9ev4njmt/<계정 ID>/CloudTrail/ap-northeast-2/...` |

<!-- ✍️ 직접 작성 · 참고: 노션 'CloudTrail Organization Trail 구성, CloudTrail 중앙 로그 저장 구성' -->

## 2단계 · S3 → Wazuh 연동 (aws-s3 wodle 설정 · IAM 권한)

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <bucket type="cloudtrail">
    <name>buildyoursoc-cloudtrail-229251311221</name>
    <aws_organization_id>o-xh9ev4njmt</aws_organization_id>
    <regions>ap-northeast-2</regions>
  </bucket>
</wodle>
```

- 인증은 키 파일 없이 Manager 인스턴스 역할(`whs4-g2-security-wazuh-manager-ssm-role`)에 S3 읽기 권한을 붙여 처리했습니다.

<!-- ✍️ 직접 작성 · 참고: 노션 '권한상승 확인 › C-2: Wazuh 연결' -->

## 3단계 · 탐지 룰 100300 / 100301

```xml
<group name="aws,privilege_escalation,">
  <rule id="100300" level="10">
    <if_sid>80200</if_sid>
    <field name="aws.source">cloudtrail</field>
    <field name="aws.eventSource">lambda.amazonaws.com</field>
    <field name="aws.eventName" type="pcre2">^CreateFunction</field>
    <field name="aws.userIdentity.arn" type="pcre2">assumed-role/.+/i-</field>
    <description>[HIGH][AWS] EC2 instance role created a Lambda function (privilege escalation attempt): $(aws.userIdentity.arn)</description>
    <mitre><id>T1548</id></mitre>
  </rule>

  <rule id="100301" level="13">
    <if_sid>100300</if_sid>
    <field name="aws.requestParameters.role" type="pcre2">(?i)(escalated|admin)</field>
    <description>[CRITICAL][AWS] Privilege escalation: instance role passed privileged role to Lambda: $(aws.requestParameters.role)</description>
  </rule>
</group>
```

| 룰 | level | Severity | 의미 |
|---|---|---|---|
| 100300 | 10 | HIGH | EC2 인스턴스 역할(`assumed-role/.../i-...`)이 Lambda를 생성 |
| 100301 | 13 | CRITICAL | 그때 넘긴 역할이 관리자급 (`escalated` · `admin`) |

<!-- ✍️ 직접 작성 · 참고: 노션 '룰 설계 이유 — 왜 이 조건을 골랐는지' -->

## 트러블슈팅: 경보가 울리지 않았던 3가지 원인

| # | 원인 | 해결 |
|---|---|---|
| ① | JSON 디코더 필드 수 한도 초과 | `analysisd.decoder_order_size=1024` |
| ② | 조직 Trail 경로 미설정 | `aws_organization_id` 지정 |
| ③ | 부모 룰 80202의 eventName 화이트리스트 | 부모를 80200으로 변경 |

<!-- ✍️ 직접 작성 · 참고: 노션 '🛠️ 트러블슈팅: CloudTrail 기반 권한상승 탐지 룰 경보 미생성' -->

## 검증 결과

`privesc-poc-6`에서 **rule 100301 (level 13, CRITICAL)** 탐지를 확인했습니다. (2026-10-06)

<!-- ✍️ 직접 작성 · 참고: 노션 '트러블슈팅 페이지의 검증 부분 · 캡처' -->

---
[← 메인으로](/README.md)
