"""Send R2/R4/R5 alerts and persist Step Functions approval requests."""

import hashlib
import json
import math
import os
import re
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from urllib import error, parse, request

SUPPORTED_RUNBOOKS = frozenset(("R2", "R4", "R5","R3","R7"))
SEND_IF = {"severity": "HIGH", "record_state": "ACTIVE", "workflow_status": "NEW"}
REQUIRED = ("finding_id", "account_id", "region", "runbook_id", *SEND_IF)
KST = timezone(timedelta(hours=9))


def _text(value, limit=512):
    return (" ".join(str(value).split())[:limit] if value is not None else "") or "미확인"


def _observed_at(value):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo:
            return date.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")
    except (AttributeError, TypeError, ValueError):
        pass
    return "미확인"


def _clean_title(value):
    """'[Wazuh] [HIGH][DVWA] ...' 앞의 대괄호 태그를 떼서 중복 표기 삭제"""
    cleaned = re.sub(r"^(?:\s*\[[^\]]*\])+\s*", "", str(value or ""))
    return cleaned or "미확인"


def _latest_seen(event):
    """description의 최신 Apache 로그 시각(UTC)을 KST로 변환"""
    match = re.search(
        r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]",
        str(event.get("description") or ""),
    )
    if match:
        try:
            seen = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
            return seen.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")
        except ValueError:
            pass
    return "미확인"


def _build_r2_message(event, approval_id=None):
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")
    try:
        count = int(details.get("count"))
    except (TypeError, ValueError):
        count = None
    try:
        ip = ip_address(event.get("source_ip")) if isinstance(event.get("source_ip"), str) else None
    except ValueError:
        ip = None
    ip_text = str(ip) if ip and not ip.is_unspecified else "미확인"
    target_name = _text(event.get("resource_name") or event.get("resource_id"), 160)
    target = f"{target_name}\n(ALB 분산 환경 · 다른 서버의 동일 공격 알림은 중복 억제될 수 있음)"
    request_url = parse.unquote_plus(str(details.get("request_url") or ""))
    reason_map = {
        "100120": "동일 IP에서 60초 내 SQLi 8회 이상 (룰 100120)",
        "100130": "HTTP 응답에 SQL 에러 노출 · 주입이 DB까지 도달 (룰 100130)",
    }
    reason = reason_map.get(str(details.get("rule_id")), "미확인")
    action = (
        f"WAF r2-blocklist에 {ip_text}/32 추가\n해제: WAF IP set에서 해당 IP 삭제"
        if ip_text != "미확인" else "공격 IP 미확인 · 차단 불가"
    )
    resource_account = details.get("resource_account_id")
    if resource_account:
        account_name, account_id = "대상 계정 · 리전", resource_account
    else:
        account_name, account_id = "Security Hub 계정 · 리전", event.get("account_id")
    fields = [
        ("대상", target, False),
        ("공격 IP", ip_text, True),
        ("HIGH 판정 누적 (오늘)", f"{count}회" if isinstance(count, int) and count > 0 else "미확인", True),
        ("요청 · HTTP 응답", f"{_text(details.get('request_method'), 16)} {_text(request_url, 380)}\nHTTP {_text(details.get('http_status'), 16)}", False),
        ("탐지 룰", f"{_text(details.get('rule_id'), 80)} · level {_text(details.get('rule_level'), 16)}", True),
        (account_name, f"{_text(account_id, 32)} / {_text(event.get('region'), 64)}", True),
        ("최초 탐지", _observed_at(event.get("first_observed_at")), True),
        ("최근 탐지", _observed_at(event.get("last_observed_at")), True),
        ("승인 시 조치", action, False),
        ("Finding ID", _text(event.get("finding_id")), False),
    ]
    prefix = "[TEST] " if event.get("sample") is True else ""
    embed = {
        "title": f"{prefix}[{_text(event.get('severity'))}][R2] {_clean_title(event.get('title'))}"[:256],
        "description": f"HIGH 판단 근거: {reason}",
        "color": 15158332,
        "fields": [{"name": name, "value": value[:512], "inline": inline} for name, value, inline in fields],
        "footer": {"text": "R2 · 공격 IP 차단 검토"},
    }
    message = {"allowed_mentions": {"parse": []}, "embeds": [embed]}
    if approval_id:
        message["content"] = (
            "🧪 R2 승인 대기 연결 시험 · 실제 차단은 실행하지 않습니다."
            if event.get("sample") is True else "R2 대응 승인 대기"
        )
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": 3, "label": "차단 승인", "custom_id": f"soc:r2:approval:{approval_id}:approve"},
            {"type": 2, "style": 2, "label": "오탐", "custom_id": f"soc:r2:approval:{approval_id}:false_positive"},
        ]}]
    elif event.get("sample") is True:
        message["content"] = "🧪 R2 버튼 연결 테스트 · 모의 승인 대기"
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": 3, "label": "모의 차단 승인", "custom_id": "soc:r2:test:approve"},
            {"type": 2, "style": 2, "label": "모의 오탐", "custom_id": "soc:r2:test:false_positive"},
        ]}]
    return message


def _first_value(event, *names):
    for name in names:
        value = event.get(name)
        if value is not None and value != "":
            return value
    return None


def _ip_text(value):
    try:
        address = ip_address(value) if isinstance(value, str) else None
        return str(address) if address and not address.is_unspecified else "미확인"
    except ValueError:
        return "미확인"


def _port_text(value):
    if type(value) is int or (isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value)):
        port = int(value)
        if 0 <= port <= 65535:
            return str(port)
    return "미확인"


def _build_r4_message(event, approval_id=None):
    # Display only the fields requested by the R4 owner. Do not infer one IP
    # from another or replace observation times with finding update times.
    fields = [
        ("Finding 유형", _text(event.get("finding_type"), 256), False),
        ("심각도", _text(event.get("severity"), 32), True),
        ("인스턴스 ID", _text(event.get("instance_id"), 64), True),
        ("인스턴스 상태", _text(event.get("instance_state"), 48), True),
        ("담당자", _text(event.get("owner"), 160), True),
        ("연결 방향", _text(event.get("direction"), 32), True),
        ("출발지 IP", _ip_text(event.get("source_ip")), True),
        ("통신 상대 IP", _ip_text(event.get("remote_ip")), True),
        ("상대 포트", _port_text(event.get("remote_port")), True),
        ("프로토콜", _text(event.get("protocol"), 32), True),
        ("최초 탐지", _observed_at(_first_value(event, "event_first_seen", "first_observed_at")), True),
        ("마지막 탐지", _observed_at(_first_value(event, "event_last_seen", "last_observed_at")), True),
    ]
    prefix = "[TEST] " if event.get("sample") is True else ""
    message = {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"{prefix}[{_text(event.get('severity'), 32)}][R4] EC2 격리 검토",
            "color": 15158332,
            "fields": [{"name": name, "value": value, "inline": inline} for name, value, inline in fields],
            "footer": {"text": "R4 · 승인 결과에 따라 담당 상태머신에서 대응"},
        }],
    }
    buttons = (
        ("격리 승인", "approve", 3),
        ("정상 행위", "allowed_activity", 2),
        ("오탐", "false_positive", 2),
    )
    if approval_id:
        message["content"] = (
            "🧪 R4 승인 대기 연결 시험 · 실제 격리 호출이 없는 테스트 실행에서 확인하세요."
            if event.get("sample") is True else "R4 대응 승인 대기"
        )
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": label,
             "custom_id": f"soc:r4:approval:{approval_id}:{action}"}
            for label, action, style in buttons
        ]}]
    elif event.get("sample") is True:
        message["content"] = "🧪 R4 버튼 연결 테스트 · 모의 승인 대기"
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": f"모의 {label}",
             "custom_id": f"soc:r4:test:{action}"}
            for label, action, style in buttons
        ]}]
    return message


def _r5_dns_ec2_scope(event):
    if event.get("resource_type") != "AwsEc2Instance":
        return False
    # The API format and native GuardDuty type use different separators.
    # Only this agreed representative case gets an EC2 isolation button.
    types = {
        "Trojan:EC2/DNSDataExfiltration",
        "Trojan:EC2-DNSDataExfiltration",
        "TTPs/Command and Control/Trojan:EC2-DNSDataExfiltration",
        "TTPs/Exfiltration/Trojan:EC2/DNSDataExfiltration",
    }
    return any(isinstance(event.get(key), str) and event[key] in types
               for key in ("classifier", "finding_type"))



def _security_groups_text(value):
    if not isinstance(value, list):
        return "미확인"
    # EC2 enrichment emits group IDs. Also accept the DescribeInstances group
    # shape without serializing the entire object or displaying other metadata.
    group_ids = []
    for group in value:
        group_id = group.get("GroupId") if isinstance(group, dict) else group
        if isinstance(group_id, str) and re.fullmatch(r"sg-(?:[a-f0-9]{8}|[a-f0-9]{17})", group_id):
            if group_id not in group_ids:
                group_ids.append(group_id)
    return "\n".join(group_ids)[:512] or "미확인"



def _dns_blocked_text(value):
    # False is meaningful evidence, not a missing value. Do not treat the
    # string "false" as true; the normalized contract supplies a JSON boolean.
    if value is True:
        return "차단됨"
    if value is False:
        return "차단되지 않음"
    return "미확인"



def _build_r5_message(event, approval_id=None):
    if not _r5_dns_ec2_scope(event):
        raise ValueError("R5 notification currently supports only EC2 DNSDataExfiltration")
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")
    target = dict.fromkeys(
        _text(event[key], 160) for key in ("resource_name", "instance_id") if event.get(key)
    )
    fields = [
        ("Finding 유형", _text(event.get("finding_type"), 256), False),
        ("심각도", _text(event.get("severity"), 32), True),
        ("대상 EC2", "\n".join(target) or "미확인", True),
        ("Private IP", _ip_text(event.get("private_ip")), True),
        ("현재 Security Group", _security_groups_text(event.get("security_groups")), False),
        ("DNS 도메인", _text(details.get("dns_domain"), 512), False),
        ("프로토콜", _text(details.get("dns_protocol"), 32), True),
        ("DNS 차단 여부", _dns_blocked_text(details.get("dns_blocked")), True),
        ("최초 탐지", _observed_at(event.get("first_observed_at")), True),
        ("최근 탐지", _observed_at(event.get("last_observed_at")), True),
        ("Finding ID", _text(event.get("finding_id"), 512), False),
    ]
    prefix = "[TEST] " if event.get("sample") is True else ""
    message = {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"{prefix}[{_text(event.get('severity'), 32)}][R5] DNS 유출 · EC2 격리 검토",
            "color": 15158332,
            "fields": [{"name": name, "value": value, "inline": inline} for name, value, inline in fields],
            "footer": {"text": "R5 · 승인 결과를 상태머신에 전달 · 실제 조치는 담당 대응 Lambda에서 수행"},
        }],
    }
    buttons = (
        ("EC2 격리 승인", "approve", 3),
        ("정상 행위", "allowed_activity", 2),
        ("오탐", "false_positive", 2),
    )
    if approval_id:
        message["content"] = (
            "🧪 R5 승인 대기 연결 시험 · 실제 격리 호출이 없는 테스트 실행에서 확인하세요."
            if event.get("sample") is True else "R5 대응 승인 대기"
        )
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": label,
             "custom_id": f"soc:r5:approval:{approval_id}:{action}"}
            for label, action, style in buttons
        ]}]
    elif event.get("sample") is True:
        message["content"] = "🧪 R5 버튼 연결 테스트 · 모의 승인 대기"
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": f"모의 {label}",
             "custom_id": f"soc:r5:test:{action}"}
            for label, action, style in buttons
        ]}]
    return message

def _r3_principal(event):
    """R3 대상 IAM 주체 이름 (역할 또는 사용자). 없으면 None."""
    for key in ("role_name", "iam_role_name", "user_name"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _r3_scope(event):
    # R3 는 IAM 주체가 확인된 경우에만 보낸다 (누구를 무효화할지 모르면 승인 버튼을 줄 수 없음).
    return event.get("resource_type") == "AwsIamAccessKey" and _r3_principal(event) is not None


def _r3_call(event):
    """호출 API·결과·자격증명 발급 EC2.
    정규화 필드가 있으면 그 값을, 없으면 파서가 만든 description 요약을 읽는다.
    요약 형식: '... → lambda:CreateFunction20150331 · 결과 실패(AccessDenied) · 출발지 x · EC2 Role 자격증명(i-...)'"""
    description = str(event.get("description") or "")
    details = event.get("details") if isinstance(event.get("details"), dict) else {}

    def field(*names):
        return _first_value(event, *names) or _first_value(details, *names)

    service = field("event_source")
    name = field("event_name")
    match = re.search(r"→\s*([A-Za-z0-9.-]+):([A-Za-z0-9_]+)", description)
    if match:
        service, name = service or match.group(1), name or match.group(2)
    if isinstance(service, str):
        service = service.replace(".amazonaws.com", "")
    api = f"{service}:{name}" if service and name else None

    error_code = field("error_code")
    if error_code:
        result = f"실패 ({error_code})"
    else:
        match = re.search(r"결과\s*(성공|실패\(([^)]*)\))", description)
        result = None if not match else ("성공" if match.group(1) == "성공" else f"실패 ({match.group(2)})")

    instance = field("credential_instance_id")
    if not instance:
        match = re.search(r"EC2 Role 자격증명\((?:[^)]*\s)?(i-[0-9a-f]{8,17})\)", description)
        instance = match.group(1) if match else None
    return api, result, instance


def _r3_key_kind(key_id):
    if isinstance(key_id, str) and key_id.startswith("ASIA"):
        return "임시 자격증명 (STS 세션)"
    if isinstance(key_id, str) and key_id.startswith("AKIA"):
        return "영구 Access Key"
    return "미확인"


def _build_r3_message(event, approval_id=None):
    if not _r3_scope(event):
        raise ValueError("R3 notification requires an AwsIamAccessKey resource with a role or user name")
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")

    principal = _r3_principal(event)
    principal_type = _text(event.get("principal_type"), 32)
    key_id = event.get("access_key_id")
    api, result, instance = _r3_call(event)
    target_account = details.get("resource_account_id") or details.get("principal_account_id")

    policies = event.get("attached_policies")
    policies_text = (
        "\n".join(dict.fromkeys(_text(p, 128) for p in policies if isinstance(p, str) and p.strip()))[:512]
        if isinstance(policies, list) else ""
    ) or "미확인"
    admin_text = {True: "⚠️ 예", False: "아니요"}.get(event.get("is_admin_like"), "미확인") \
        if type(event.get("is_admin_like")) is bool else "미확인"

    # 승인 시 조치: 임시 자격증명은 키 비활성화가 불가능하므로 역할 세션 무효화, 영구 키는 키 비활성화
    is_user_key = isinstance(key_id, str) and key_id.startswith("AKIA")
    if is_user_key:
        action = f"Access Key {_text(key_id, 32)} 비활성화\n해제: 키 다시 활성화"
        approve_label = "키 비활성화 승인"
    else:
        action = (f"역할 {_text(principal, 128)} 세션 무효화\n"
                  "(승인 시각 이전에 발급된 토큰 전부 Deny · aws:TokenIssueTime)\n"
                  "해제: 역할에서 무효화 정책 삭제")
        approve_label = "세션 무효화 승인"

    reason = " · ".join(x for x in (api, result) if x) or "미확인"
    fields = [
        ("Finding 유형", _text(event.get("finding_type") or event.get("classifier"), 256), False),
        ("심각도", _text(event.get("severity"), 32), True),
        ("탐지 룰", f"{_text(details.get('rule_id'), 32)} · level {_text(details.get('rule_level'), 8)}", True),
        ("IAM 주체", f"{principal_type} · {_text(principal, 128)}", False),
        ("자격증명", f"{_text(key_id, 32)}\n{_r3_key_kind(key_id)}", True),
        ("자격증명 발급 EC2", _text(instance, 32), True),
        ("호출 API", _text(api, 128), True),
        ("결과", _text(result, 128), True),
        ("호출 출발지 IP", _ip_text(event.get("source_ip")), True),
        ("대상 계정 · 리전", f"{_text(target_account, 32)} / {_text(event.get('region'), 64)}", True),
        ("연결된 정책", policies_text, True),
        ("관리자급 권한", admin_text, True),
        ("최초 탐지", _observed_at(event.get("first_observed_at")), True),
        ("최근 탐지", _observed_at(event.get("last_observed_at")), True),
        ("승인 시 조치", action, False),
        ("Finding ID", _text(event.get("finding_id"), 512), False),
    ]
    prefix = "[TEST] " if event.get("sample") is True else ""
    message = {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"{prefix}[{_text(event.get('severity'), 32)}][R3] IAM 자격증명 대응 검토 · {_text(principal, 100)}"[:256],
            "description": f"탐지: {_clean_title(event.get('title'))}"[:300] + f"\n판단 근거: {reason}",
            "color": 15158332,
            "fields": [{"name": name, "value": value[:1024], "inline": inline} for name, value, inline in fields],
            "footer": {"text": "R3 · 승인 결과를 상태머신에 전달 · 실제 조치는 담당 대응 Lambda에서 수행"},
        }],
    }
    if event.get("source_url"):
        try:
            parsed = parse.urlsplit(str(event["source_url"]))
            if parsed.scheme == "https" and parsed.hostname:
                message["embeds"][0]["url"] = str(event["source_url"])
        except ValueError:
            pass
    buttons = (
        (approve_label, "approve", 4),       # 빨간색: 자격증명 차단은 파괴적 조치
        ("정상 행위", "allowed_activity", 2),
        ("오탐", "false_positive", 2),
    )
    if approval_id:
        message["content"] = (
            "🧪 R3 승인 대기 연결 시험 · 실제 무효화 호출이 없는 테스트 실행에서 확인하세요."
            if event.get("sample") is True else "R3 대응 승인 대기"
        )
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": label,
             "custom_id": f"soc:r3:approval:{approval_id}:{action_id}"}
            for label, action_id, style in buttons
        ]}]
    elif event.get("sample") is True:
        message["content"] = "🧪 R3 버튼 연결 테스트 · 모의 승인 대기"
        message["components"] = [{"type": 1, "components": [
            {"type": 2, "style": style, "label": f"모의 {label}",
             "custom_id": f"soc:r3:test:{action_id}"}
            for label, action_id, style in buttons
        ]}]
    return message


def _build_r7_message(event, approval_id=None):
    # R7은 미분류 Finding이라 정해진 대응 조치가 없으므로 버튼 없이 알림만 보낸다.
    # 승인 모드로 잘못 호출되면 아무도 응답할 수 없는 대기가 생기므로 예외로 막는다.
    if approval_id:
        raise ValueError("R7 does not support approval buttons")
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")

    def code(value, limit):
        # 외부 입력(시그니처·요약)은 인라인 코드로 감싸 마크다운·링크 렌더링을 막음
        text = _text(value, limit)
        return text if text == "미확인" else f"`{text.replace('`', 'ˋ')}`"

    def endpoint(ip_value, port_value):
        # IP와 포트를 "IP:포트"로 표시, 포트가 없으면 IP만 표시
        ip_text, port_text = _ip_text(ip_value), _port_text(port_value)
        if ip_text == "미확인" or port_text == "미확인":
            return ip_text
        return f"[{ip_text}]:{port_text}" if ":" in ip_text else f"{ip_text}:{port_text}"

    # description = "[요약 문구] {Suricata EVE JSON}" 형태 → 요약 문구와 EVE JSON을 분리
    description = str(event.get("description") or "")
    summary, eve = description, {}
    start = description.find("{")
    if start >= 0:
        try:
            parsed, _ = json.JSONDecoder().raw_decode(description, start)
            if isinstance(parsed, dict):
                summary, eve = description[:start].strip(), parsed
        except ValueError:
            pass
    alert = eve.get("alert") if isinstance(eve.get("alert"), dict) else {}

    # 정규화 결과에는 source 대신 product 키로 출처가 들어옴
    source = str(event.get("source") or event.get("product") or "").strip().lower()
    source_name = {"guardduty": "GuardDuty", "wazuh": "Wazuh", "suricata": "Suricata"}.get(source, "기타")
    severity = _text(event.get("severity"), 32)
    types = _first_value(event, "types", "finding_types")
    types = types if isinstance(types, list) else []
    types_text = "\n".join(dict.fromkeys(_text(t, 128) for t in types if isinstance(t, str) and t.strip()))
    resource = dict.fromkeys(
        _text(event[key], 160) for key in ("resource_type", "resource_name", "resource_id") if event.get(key)
    )

    fields = [
        ("출처", source_name, True),
        ("심각도", severity, True),
        ("Finding 유형", _text(event.get("finding_type"), 256), False),
        ("카테고리", _text(event.get("category"), 128), True),
        ("Types", types_text[:512] or "미확인", True),
        ("대상 리소스", "\n".join(resource) or "미확인", False),
    ]
    if source == "suricata":
        # details에 값이 있으면 우선 사용하고, 없으면 description의 EVE JSON에서 읽음
        def pick(key, eve_value):
            value = details.get(key)
            return eve_value if value is None or value == "" else value

        fields += [
            ("시그니처", code(pick("signature", alert.get("signature")), 256), False),
            ("SID", _text(pick("signature_id", alert.get("signature_id")), 16), True),
            ("Suricata 분류", _text(pick("alert_category", alert.get("category")), 128), True),
            ("프로토콜", _text(pick("proto", eve.get("proto")), 16), True),
            ("출발지", endpoint(pick("src_ip", eve.get("src_ip")), pick("src_port", eve.get("src_port"))), True),
            ("목적지", endpoint(pick("dest_ip", eve.get("dest_ip")), pick("dest_port", eve.get("dest_port"))), True),
        ]
    elif source == "wazuh":
        # Wazuh는 정규화된 최상위 필드와 details에서 읽음
        # 목적지 = 로그를 보낸 에이전트(대상 서버) IP. 없으면 enrichment의 private_ip
        fields += [
            ("프로토콜", _text(event.get("protocol"), 16), True),
            ("출발지", endpoint(event.get("source_ip"), event.get("source_port")), True),
            ("목적지", endpoint(_first_value(details, "agent_ip") or event.get("private_ip"),
                              event.get("dest_port")), True),
        ]
    fields += [
        ("계정 · 리전", f"{_text(event.get('account_id'), 32)} / {_text(event.get('region'), 64)}", True),
        ("최초 탐지", _observed_at(event.get("first_observed_at")), True),
        ("최근 탐지", _observed_at(event.get("last_observed_at")), True),
        ("요약", code(summary, 300), False),
        ("Finding ID", _text(event.get("finding_id"), 512), False),
    ]
    prefix = "[TEST] " if event.get("sample") is True else ""
    colors = {"CRITICAL": 15158332, "HIGH": 15158332, "MEDIUM": 15105570}
    message = {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"{prefix}[{severity}][R7][{source_name}] {_clean_title(event.get('title'))}"[:256],
            "description": "분류 사유: Step Functions 분류 조건 미일치 (Default)",
            "color": colors.get(severity, 9807270),
            "fields": [{"name": name, "value": value, "inline": inline} for name, value, inline in fields],
            "footer": {"text": "R7 · 분류 검토 필요 · 자동 조치 없음"},
        }],
    }
    if event.get("sample") is True:
        message["content"] = "🧪 R7 알림 테스트 · 버튼 없음"
    return message


def build_message(event, approval_id=None):
    if event.get("runbook_id") == "R2":
        return _build_r2_message(event, approval_id)
    if event.get("runbook_id") == "R4":
        return _build_r4_message(event, approval_id)
    if event.get("runbook_id") == "R5":
        return _build_r5_message(event, approval_id)
    if event.get("runbook_id") == "R3":
        return _build_r3_message(event, approval_id)
    if event.get("runbook_id") == "R7":
        return _build_r7_message(event, approval_id)
    raise ValueError("Unsupported notification runbook")


def _bot_config():
    token = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    channel = os.environ.get("DISCORD_CHANNEL_ID", "").strip()
    if not token or any(char.isspace() for char in token):
        raise ValueError("Configure DISCORD_BOT_TOKEN")
    if not re.fullmatch(r"[0-9]{17,20}", channel):
        raise ValueError("Configure DISCORD_CHANNEL_ID")
    return token, channel


def _input(event):
    if not isinstance(event, dict):
        raise ValueError("Input must be a common Finding JSON object")
    is_approval = any(key in event for key in ("finding", "taskToken", "executionArn", "approvalTimeoutSeconds"))
    if not is_approval:
        return event, None
    finding, task_token, execution = event.get("finding"), event.get("taskToken"), event.get("executionArn")
    timeout = event.get("approvalTimeoutSeconds", 900)
    if not isinstance(finding, dict):
        raise ValueError("Approval input requires a finding object")
    if not isinstance(task_token, str) or not task_token.strip() or len(task_token) > 2048:
        raise ValueError("Approval input requires a valid taskToken")
    if not isinstance(execution, str) or not re.fullmatch(
        r"arn:aws(?:-us-gov|-cn)?:states:[a-z0-9-]+:\d{12}:execution:[^:\s]+:[^:\s]+", execution
    ):
        raise ValueError("Approval input requires an executionArn")
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError("approvalTimeoutSeconds must be an integer from 1 to 86400")
    return finding, {"task_token": task_token, "execution_arn": execution, "timeout": timeout}


def _approval_table():
    name = os.environ.get("APPROVAL_TABLE_NAME", "").strip()
    if not name:
        raise ValueError("Configure APPROVAL_TABLE_NAME")
    # Boto3 is included in the Lambda Python runtime. Flat notification tests
    # do not import it or require AWS credentials.
    import boto3
    from botocore.config import Config

    return boto3.resource("dynamodb", config=Config(
        connect_timeout=2, read_timeout=3,
        retries={"mode": "standard", "total_max_attempts": 2},
    )).Table(name)


def _create_approval(table, finding, metadata, channel):
    # A repeat invocation with the same Task Token uses the same request key.
    approval_id = hashlib.sha256(metadata["task_token"].encode("utf-8")).hexdigest()[:32]
    now = int(time.time())
    item = {
        "approval_id": approval_id,
        "task_token": metadata["task_token"],
        "execution_arn": metadata["execution_arn"],
        "finding_id": finding["finding_id"],
        "runbook_id": finding["runbook_id"],
        "account_id": finding["account_id"],
        "region": finding["region"],
        "channel_id": channel,
        "status": "SENDING",
        "created_at": now,
        "updated_at": now,
        "expires_at": now + metadata["timeout"],
        "sample": finding.get("sample") is True,
    }
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(approval_id)")
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "ConditionalCheckFailedException":
            raise RuntimeError("Approval store write failed") from None
        try:
            stored = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True).get("Item", {})
        except Exception:
            raise RuntimeError("Approval store read failed") from None
        if (
            stored.get("status") == "PENDING" and stored.get("message_id")
            and stored.get("expires_at", 0) > now
            and all(stored.get(key) == item[key] for key in (
                "task_token", "execution_arn", "finding_id", "runbook_id", "channel_id"
            ))
        ):
            return approval_id, stored["message_id"]
        raise RuntimeError("Approval request is already in progress, expired, or closed") from None
    return approval_id, None


def _mark_approval_failed(table, approval_id):
    try:
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #status = :failed, updated_at = :now REMOVE task_token",
            ConditionExpression="#status = :sending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":failed": "FAILED", ":sending": "SENDING", ":now": int(time.time())},
        )
    except Exception:
        # Preserve the original error; a SENDING record must not authorize a callback.
        pass


def _mark_approval_pending(table, approval_id, message_id):
    try:
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #status = :pending, message_id = :message, updated_at = :now",
            ConditionExpression="#status = :sending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":pending": "PENDING", ":sending": "SENDING", ":message": message_id, ":now": int(time.time())},
        )
    except Exception:
        raise RuntimeError("Approval message binding failed") from None


def _send_message(payload, token, channel, approval_mode=False):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    post = request.Request(
        f"https://discord.com/api/v10/channels/{channel}/messages", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bot {token}",
                 "User-Agent": "SecurityHub-Notifier/1.0"}, method="POST",
    )
    try:
        with request.urlopen(post, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError(f"Discord HTTP {response.status}")
            message = json.load(response)
    except error.HTTPError as exc:
        if exc.code == 429:
            if approval_mode:
                raise RuntimeError("Discord rate limited approval notification") from None
            try:
                delay = exc.headers.get("Retry-After")
                if delay is None:
                    delay = json.loads(exc.read())["retry_after"]
                return {"sent": False, "reason": "rate_limited", "retry_after": max(1, math.ceil(float(delay)))}
            except (KeyError, TypeError, ValueError, OverflowError):
                raise RuntimeError("Invalid Discord rate-limit response") from None
        raise RuntimeError(f"Discord HTTP {exc.code}") from None
    except (error.URLError, TimeoutError, OSError):
        raise RuntimeError("Discord request failed") from None
    except (TypeError, ValueError):
        raise RuntimeError("Invalid Discord response") from None
    if not isinstance(message, dict) or not isinstance(message.get("id"), str) or not message["id"]:
        raise RuntimeError("Discord did not confirm a message ID")
    return {"sent": True, "message_id": message["id"]}


def lambda_handler(event, context):
    if isinstance(event, dict) and event.get("severity") in ("MEDIUM", "CRITICAL"):
        return _handle_ordinary_notification(event)
    finding, metadata = _input(event)
    missing = [key for key in REQUIRED if not isinstance(finding.get(key), str) or not finding[key].strip()]
    
    # 필수 필드가 빠진거 있는지 확인
    if missing:
        raise ValueError("Missing required fields: " + ", ".join(missing))
    
    # runbook_id가 R2/R4/R5인지 확인 + Severity, record_state, workflow_status도 제대로 된건지 확인
    if finding["runbook_id"] not in SUPPORTED_RUNBOOKS or any(finding[key] != value for key, value in SEND_IF.items()):
        if metadata:
            raise ValueError("Approval input is outside supported R2/R3/R4/R5 HIGH ACTIVE NEW scope")
        reason = "outside_r2_high_scope" if finding["runbook_id"] == "R2" else "outside_supported_high_scope"
        return {"sent": False, "reason": reason}
    
    # details가 dict가 맞는지
    if not isinstance(finding.get("details", {}), dict):
        raise ValueError("details must be an object")
    
    # R5인데 EC2 + DNSDataExfiltration 범위인지 확인
    if finding["runbook_id"] == "R5" and not _r5_dns_ec2_scope(finding):
        if metadata:
            raise ValueError("R5 approval currently supports only EC2 DNSDataExfiltration")
        return {"sent": False, "reason": "outside_r5_dns_ec2_scope"}

    # R3인데 IAM 주체(AwsIamAccessKey + 역할/사용자 이름)가 확인되는지
    if finding["runbook_id"] == "R3" and not _r3_scope(finding):
        if metadata:
            raise ValueError("R3 approval requires an AwsIamAccessKey resource with a role or user name")
        return {"sent": False, "reason": "outside_r3_iam_scope"}

    # R7은 버튼이 없으므로 승인 모드를 승인 레코드(SENDING)를 쓰기 전에 거부
    if finding["runbook_id"] == "R7" and metadata:
        raise ValueError("R7 does not support approval mode")

    token, channel = _bot_config()
    # Validate the display data before writing a token or posting a message.

    payload = build_message(finding) # Discord에 메시지를 보내는 함수 
    table, approval_id = None, None
    
    # 승인 모드 -> 승인 레코드 생성 + 버튼 포함 재빌드
    if metadata:
        table = _approval_table()
        approval_id, existing_message = _create_approval(table, finding, metadata, channel)
        if existing_message:
            return {"sent": True, "finding_id": finding["finding_id"], "message_id": existing_message,
                    "approval_id": approval_id, "approval_status": "PENDING", "reused": True}
        payload = build_message(finding, approval_id)
    try:
        # Discord 1회 Post
        result = _send_message(payload, token, channel, approval_mode=bool(metadata))
        if metadata:
            _mark_approval_pending(table, approval_id, result["message_id"])
    except Exception:
        if table is not None:
            _mark_approval_failed(table, approval_id)
        raise
    if not result["sent"]:
        return result
    result["finding_id"] = finding["finding_id"]
    if metadata:
        result.update(approval_id=approval_id, approval_status="PENDING")
    return result


"""Ordinary MEDIUM/CRITICAL notifications; no approval tokens or response actions."""

CRITICAL_NOTIFICATION_RUNBOOKS = frozenset(("R2", "R3", "R4", "R5", "R7"))
ORDINARY_REQUIRED = ("finding_id", "account_id", "region", "severity", "record_state", "workflow_status")
APPROVAL_INPUT_KEYS = ("finding", "taskToken", "executionArn", "approvalTimeoutSeconds")
JIRA_NOTIFICATION_HOST = "example.atlassian.net"


def _ordinary_bot_config(severity):
    token = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    name = "DISCORD_MEDIUM_CHANNEL_ID" if severity == "MEDIUM" else "DISCORD_CRITICAL_CHANNEL_ID"
    channel = os.environ.get(name, "").strip()
    if not token or any(char.isspace() for char in token):
        raise ValueError("Configure DISCORD_BOT_TOKEN")
    if not re.fullmatch(r"[0-9]{17,20}", channel):
        raise ValueError("Configure " + name)
    return token, channel


def _ordinary_fields(finding):
    resource = finding.get("instance_id") or finding.get("resource_id")
    fields = [
        ("Finding 유형", _text(finding.get("finding_type") or finding.get("classifier"), 256), False),
        ("대상 리소스", _text(finding.get("resource_name") or resource, 200), False),
        ("리소스 ID", _text(resource, 256), False),
        ("계정 · 리전", f"{_text(finding.get('account_id'), 32)} / {_text(finding.get('region'), 64)}", True),
        ("출발지 IP", _ip_text(finding.get("source_ip")), True),
        ("최초 탐지", _observed_at(finding.get("first_observed_at")), True),
        ("최근 탐지", _observed_at(finding.get("last_observed_at")), True),
        ("Finding ID", _text(finding.get("finding_id"), 512), False),
    ]
    return fields


def _ordinary_message(finding, runbook, fields, description, footer):
    # Bounded fields keep this single embed well below Discord's total limit.
    prefix = "[TEST] " if finding.get("sample") is True else ""
    severity = finding["severity"]
    return {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"{prefix}[{severity}][{runbook}] {_clean_title(finding.get('title'))}"[:256],
            "description": description[:512],
            "color": 15158332 if severity == "CRITICAL" else 15105570,
            "fields": [{"name": _text(name, 128), "value": _text(value, 512), "inline": inline}
                       for name, value, inline in fields[:25]],
            "footer": {"text": footer[:256]},
        }],
    }


def _build_critical_notification(finding):
    runbook = finding["runbook_id"]
    details = finding.get("details", {})
    fields = _ordinary_fields(finding)
    if finding.get("resource_type") == "AwsEc2Instance":
        fields += [
            ("인스턴스 상태", _text(finding.get("instance_state"), 64), True),
            ("담당자", _text(finding.get("owner"), 128), True),
            ("Private IP", _ip_text(finding.get("private_ip")), True),
            ("VPC ID", _text(finding.get("vpc_id"), 64), True),
            ("현재 Security Group", _security_groups_text(finding.get("security_groups")), False),
            ("IR 자동화 설정", {True: "활성화", False: "비활성화"}.get(finding.get("ir_automation_enabled"), "미확인")
             if type(finding.get("ir_automation_enabled")) is bool else "미확인", True),
        ]
    if runbook == "R2":
        fields += [("탐지 룰", _text(details.get("rule_id"), 80), True),
                   ("반복 횟수", _text(details.get("count"), 32), True)]
    elif runbook == "R3":
        fields += [("Principal 유형", _text(finding.get("principal_type"), 64), True),
                   ("사용자 / 역할", _text(finding.get("user_name") or finding.get("role_name") or finding.get("iam_role_name"), 128), True)]
    elif runbook == "R5" and details.get("dns_domain"):
        fields += [("DNS 도메인", _text(details.get("dns_domain"), 256), False),
                   ("DNS 프로토콜", _text(details.get("dns_protocol"), 32), True),
                   ("DNS 차단 여부", _dns_blocked_text(details.get("dns_blocked")), True)]
    block = finding.get("block_result") or {}
    if block:
        ip = block.get("ip") or finding.get("source_ip")
        status = "WAF 차단 완료" if block.get("blocked") else "차단 안 함"
        fields.append(("대응 상태", f"{status} · {_text(ip, 64)}", False))
    elif finding.get("block_error"):
        fields.append(("대응 상태", "자동 차단 실패 · 수동 확인 필요", False))
    else:
        fields.append(("대응 상태", "대응 결과 미전달 · 차단/격리 완료 여부 확인 필요", False))
    if block:
        description = "CRITICAL 경보 탐지 · 자동 대응(차단/격리) 수행됨. 아래 대응 상태 확인."
        footer = "CRITICAL · 승인 버튼 없음 · 자동 대응 결과 포함"
    else:
        description = "CRITICAL 경보 탐지 · 긴급 확인 필요. 이 알림 Lambda는 차단·격리를 실행하지 않습니다."
        footer = "CRITICAL · 승인 버튼 없음 · 실제 대응 결과와 별도인 탐지 알림"
    return _ordinary_message(finding, runbook, fields, description, footer)


def _medium_ticket(finding):
    container = finding.get("r1_ticket")
    ticket = container.get("result") if isinstance(container, dict) else None
    if not isinstance(ticket, dict):
        raise ValueError("MEDIUM notification requires r1_ticket.result")
    if ticket.get("status") == "SKIPPED":
        if ticket.get("reason") not in ("finding_closed", "finding_not_active_new"):
            raise ValueError("Unconfirmed skipped Jira ticket result")
        return None
    key = ticket.get("jira_key")
    if (ticket.get("status") != "CREATED" or ticket.get("manual_review_required") is not False
            or not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}-[0-9]{1,20}", key)
            or not key.startswith("SOC-")
            or ticket.get("finding_id") != finding["finding_id"]):
        raise ValueError("MEDIUM notification requires a confirmed Jira ticket result")
    url = ticket.get("jira_url")
    try:
        parsed = parse.urlsplit(url) if isinstance(url, str) else None
        valid = (parsed and parsed.scheme == "https" and parsed.hostname == JIRA_NOTIFICATION_HOST and not parsed.username
                 and not parsed.password and parsed.port is None and not parsed.query
                 and not parsed.fragment and parsed.path == "/browse/" + key)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("MEDIUM notification requires a valid matching Jira ticket URL")
    return ticket


def _build_medium_notification(finding, ticket):
    runbook = finding.get("runbook_id") or ticket.get("runbook_id") or "R1"
    if not isinstance(runbook, str) or runbook not in {"R1", "R2", "R3", "R4", "R5", "R7"}:
        raise ValueError("Invalid MEDIUM notification runbook")
    existing = ticket.get("deduplicated") is True
    fields = [("Jira 티켓", f"{ticket['jira_key']}\n{ticket['jira_url']}", False),
              ("티켓 처리", "기존 티켓 연결" if existing else "티켓 생성 확인", True)]
    fields += _ordinary_fields(finding)
    payload = _ordinary_message(
        finding, runbook, fields,
        "보안 경보 검토용 Jira 티켓입니다. 티켓에서 담당자를 지정하고 확인 결과를 기록해 주세요.",
        "R1 · MEDIUM 검토 티켓 · 차단/격리 및 승인 버튼 없음",
    )
    payload["embeds"][0]["url"] = ticket["jira_url"]
    return payload


def _handle_ordinary_notification(finding):
    if any(key in finding for key in APPROVAL_INPUT_KEYS):
        raise ValueError("MEDIUM/CRITICAL notifications do not accept approval metadata")
    missing = [key for key in ORDINARY_REQUIRED
               if not isinstance(finding.get(key), str) or not finding[key].strip()]
    if missing:
        raise ValueError("Missing required fields: " + ", ".join(missing))
    if not isinstance(finding.get("details", {}), dict):
        raise ValueError("details must be an object")
    severity = finding["severity"]
    if severity == "CRITICAL":
        if (not isinstance(finding.get("runbook_id"), str)
                or finding["runbook_id"] not in CRITICAL_NOTIFICATION_RUNBOOKS):
            raise ValueError("Unsupported CRITICAL notification runbook")
        if finding["record_state"] != "ACTIVE" or finding["workflow_status"] != "NEW":
            return {"sent": False, "reason": "outside_critical_active_new_scope"}
        payload = _build_critical_notification(finding)
    else:
        ticket = _medium_ticket(finding)
        if ticket is None:
            return {"sent": False, "reason": "ticket_skipped"}
        payload = _build_medium_notification(finding, ticket)
    token, channel = _ordinary_bot_config(severity)
    result = _send_message(payload, token, channel)
    # These new Tasks have no silent-success branch for a failed Discord POST.
    if result.get("sent") is not True:
        raise RuntimeError("Discord notification was not confirmed")
    return dict(result, finding_id=finding["finding_id"], severity=severity, channel_id=channel)