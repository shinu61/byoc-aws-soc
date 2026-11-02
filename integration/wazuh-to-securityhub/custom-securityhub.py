#!/usr/bin/env python3
# Wazuh alert -> AWS Security Hub (ASFF) 변환·송고기
# 4-D: 같은 "규칙 + 서버 + 날짜(KST)"는 finding 하나로 묶고, 횟수·처음/마지막 시각만 갱신한다.
#      CloudTrail(IAM) 알림은 "규칙 + IAM 주체 + 날짜(KST)"로 묶는다.
#
#   --check   <alert.json>   한 줄 요약 + 형식 검사       (AWS 호출 없음, 메모장 안 바꿈)
#   --fields  <alert.json>   R2/R3 알림 필드만 뽑아서 출력 (AWS 호출 없음, 메모장 안 바꿈)
#   --dry-run <alert.json>   변환 결과 전체 출력          (AWS 호출 없음, 메모장 안 바꿈)
#   --send    <alert.json>   수동 송고
#   <alert.json> [key] [url] integratord 호출용 자동 송고
#
# 메모장(상태 파일) 위치는 환경변수 SHUB_STATE 로 바꿀 수 있다 (테스트용).
#
# EC2 정보(instance_id / Workload 계정 / 리전 / 이름)는 각 웹 서버 Agent 의
# /var/ossec/etc/ossec.conf 에 넣은 <labels> 에서 읽는다 (Agent 재시작 필요):
#   <labels>
#     <label key="aws.instance-id">i-0123456789abcdef0</label>
#     <label key="aws.account-id">111111111111</label>
#     <label key="aws.region">ap-northeast-2</label>   <!-- 생략하면 REGION -->
#     <label key="aws.name">Web-Private-A</label>      <!-- 생략하면 Agent 이름 -->
#   </labels>
# 라벨을 넣을 수 없는 Agent(예: Manager 자신 000)는 AGENT_RESOURCES 표에 적는다.
#
# CloudTrail 알림(data.integration == "aws")은 Manager(000)가 S3 로그를 직접 분석한 것이라
# 에이전트가 공격 대상이 아니다. 이 경우 리소스는 CloudTrail 의 IAM 주체(AwsIamAccessKey)로 만든다.
import datetime
import fcntl
import ipaddress
import json
import os
import sys

# ---- 고정값 -----------------------------------------------------------------
ACCOUNT_ID = "229251311221"          # Security 계정 (원고를 넣는 계정)
REGION = "ap-northeast-2"
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default"
KST = datetime.timezone(datetime.timedelta(hours=9))   # 하루의 경계 = 한국 자정
STATE_FILE = os.environ.get("SHUB_STATE", "/var/ossec/logs/securityhub-state.json")
STATE_KEEP_DAYS = 3                  # 메모장에 며칠치까지 남길지
LOG_FILE = os.environ.get("SHUB_LOG", "/var/ossec/logs/integrations.log")

# Wazuh 대시보드 주소 ("" 로 두면 SourceUrl 을 넣지 않는다)
DASHBOARD_URL = os.environ.get("SHUB_DASHBOARD", "https://10.1.10.10")
# 대시보드에서 해당 알림 1건을 여는 주소 형식 (Wazuh 버전에 따라 경로가 다르면 여기만 고친다)
SOURCE_URL_TEMPLATE = ("{base}/app/discover#/?_g=(time:(from:'{start}',to:'{end}'))"
                       "&_q=(query:(language:kuery,query:'id:{alert_id}'))")

# 라벨이 없는 Agent 용 예비 표 (Agent 이름 → EC2). 라벨이 있으면 라벨이 우선한다.
# CloudTrail 알림에서 "자격증명을 발급받은 EC2"의 이름을 찾을 때도 이 표를 쓴다.
AGENT_RESOURCES = {
    "Web-Private-A": {"instance_id": "i-0b030a28a071f1d0a", "account_id": "059865587057"},
    "Web-Private-B": {"instance_id": "i-0761763ebb3ade025", "account_id": "059865587057"},
}

WEB_SERVER_BY_IP = {
    "10.0.10.253": "Web-Private-A",
    "10.0.11.161": "Web-Private-B",
}

# 웹 로그·sshd 등 / Suricata / CloudTrail (IP 형식이 아닌 값, 예: lambda.amazonaws.com 은 버린다)
SOURCE_IP_PATHS = ["data.http.xff", "data.srcip", "data.src_ip", "data.aws.sourceIPAddress"]
URI_PATHS = ["data.url", "data.http.url"]            # 웹 로그 / Suricata
PAYLOAD_PATHS = ["data.payload_printable"]           # Suricata (없으면 full_log)

# Wazuh MITRE tactic → ASFF Types (네임스페이스/카테고리)
TACTIC_TO_TYPE = {
    "Initial Access":       "TTPs/Initial Access",
    "Execution":            "TTPs/Execution",
    "Persistence":          "TTPs/Persistence",
    "Privilege Escalation": "TTPs/Privilege Escalation",
    "Defense Evasion":      "TTPs/Defense Evasion",
    "Credential Access":    "TTPs/Credential Access",
    "Discovery":            "TTPs/Discovery",
    "Reconnaissance":       "TTPs/Discovery",          # GuardDuty Recon:*도 Discovery
    "Lateral Movement":     "TTPs/Lateral Movement",
    "Collection":           "TTPs/Collection",
    "Command and Control":  "TTPs/Command and Control",
    "Exfiltration":         "Effects/Data Exfiltration",  # ASFF엔 TTPs/Exfiltration 없음
    "Impact":               "Effects/Data Destruction",   # FIM 삭제(T1485) 기준
}

# tactic 보다 먼저 본다: 한 tactic 안에 성격이 다른 기법이 섞인 경우 (예: Impact = DoS / 데이터 파괴)
TECHNIQUE_TO_TYPE = {
    "T1498": "Effects/Denial of Service",      # Network Denial of Service
    "T1499": "Effects/Denial of Service",      # Endpoint Denial of Service
    "T1485": "Effects/Data Destruction",       # Data Destruction (FIM 삭제)
    "T1496": "Effects/Resource Consumption",   # Resource Hijacking (크립토마이닝 등)
}

# 룰에 <mitre> 가 없을 때 파서가 대신 붙이는 MITRE (룰 ID → 기법·전술).
# 룰에 MITRE 가 있으면 룰 쪽이 우선한다. 새 커스텀 룰을 만들면 여기에 한 줄 추가.
RULE_MITRE = {
    "100114": {"id": ["T1499.001"], "tactic": ["Impact"]},       # TCP SYN Flood
    "100120": {"id": ["T1190"], "tactic": ["Initial Access"]},   # SQLi 반복 (DVWA)
}

# MITRE가 없을 때: Wazuh 그룹으로 판단 (위에서부터 먼저 맞는 것)
GROUP_TO_TYPE = [
    ("privilege_escalation",    "TTPs/Privilege Escalation"),
    ("authentication_failed",   "TTPs/Credential Access"),
    ("authentication_failures", "TTPs/Credential Access"),
    ("sql_injection",           "TTPs/Initial Access"),
    ("web_scan",                "TTPs/Discovery"),
    ("recon",                   "TTPs/Discovery"),
    ("attack",                  "TTPs/Initial Access"),
    ("ids",                     "Unusual Behaviors/Network Flow"),
    ("syscheck",                "Unusual Behaviors/VM"),
    ("audit",                   "Unusual Behaviors/Process"),
]
DEFAULT_TYPE = "Unusual Behaviors/VM"

EXTRA_FIELDS = [
    "syscheck.path", "syscheck.event",                       # FIM
    "data.url", "data.protocol", "data.id",                  # 웹 접근 로그
    "data.audit.exe", "data.audit.command", "data.audit.cwd",
    "data.audit.uid", "data.audit.auid", "data.audit.key",   # auditd
    "data.dest_ip", "data.dest_port", "data.proto",          # Suricata
    "data.alert.signature", "data.alert.signature_id", "data.alert.category",
    "data.http.hostname", "data.http.http_method", "data.http.http_user_agent", "data.http.status",
]


# ---- 도우미 ------------------------------------------------------------------
def dig(d, path, default=None):
    cur = d
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def first_of(alert, paths):
    for path in paths:
        v = dig(alert, path)
        if v not in (None, "", []):
            return v
    return None


def level_to_label(level):
    if level >= 13: return "CRITICAL"
    if level >= 10: return "HIGH"
    if level >= 7:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFORMATIONAL"


def parse_time(ts):
    try:
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except (TypeError, ValueError):
        t = datetime.datetime.now(datetime.timezone.utc)
    return t.astimezone(datetime.timezone.utc)


def asff_time(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def source_ip(alert):
    """공격 출발지 IP. (ip, 4 또는 6) — 없으면 (None, None)."""
    for path in SOURCE_IP_PATHS:
        ip = dig(alert, path)
        if ip:
            try:
                return str(ip), ipaddress.ip_address(str(ip)).version
            except ValueError:
                pass
    return None, None


def is_ipv4(value):
    try:
        return ipaddress.ip_address(str(value)).version == 4
    except ValueError:
        return False


def agent_label(agent, key):
    """Agent 라벨. 'aws.instance-id' 는 중첩({"aws": {"instance-id": ..}})·평면 둘 다 읽는다."""
    labels = agent.get("labels") or {}
    v = labels.get(key)
    if v is None:
        v = dig(labels, key)
    return str(v) if v not in (None, "") else None


def ec2_info(agent):
    """Agent → EC2 정보. 모르는 값은 None."""
    name = str(agent.get("name", "unknown"))
    table = AGENT_RESOURCES.get(name, {})
    return {
        "instance_id": agent_label(agent, "aws.instance-id") or table.get("instance_id"),
        "account_id": agent_label(agent, "aws.account-id") or table.get("account_id"),
        "region": agent_label(agent, "aws.region") or table.get("region") or REGION,
        "name": agent_label(agent, "aws.name") or table.get("name") or name,
    }


def instance_name(instance_id):
    """AGENT_RESOURCES 에서 instance_id 로 서버 이름 찾기 (없으면 None)."""
    return next((n for n, v in AGENT_RESOURCES.items() if v.get("instance_id") == instance_id), None)


def _s(value):
    """비어 있지 않은 문자열이면 그대로, 아니면 None."""
    return str(value) if value not in (None, "", [], {}) else None


def cloudtrail_info(alert):
    """CloudTrail 기반 알림이면 IAM 주체·API 호출 정보(dict), 아니면 None.
    Wazuh 는 CloudTrail 레코드를 data.aws.* 로 풀어 준다."""
    if dig(alert, "data.integration") != "aws":
        return None
    aws = dig(alert, "data.aws") or {}
    uid = aws.get("userIdentity") if isinstance(aws, dict) else None
    if not isinstance(uid, dict) or not uid:
        return None
    issuer = dig(uid, "sessionContext.sessionIssuer") or {}
    attrs = dig(uid, "sessionContext.attributes") or {}

    principal_id = _s(uid.get("principalId"))
    session = principal_id.split(":", 1)[1] if principal_id and ":" in principal_id else None
    principal_type = _s(uid.get("type"))
    principal_name = (_s(issuer.get("userName")) or _s(uid.get("userName"))
                      or ("root" if principal_type == "Root" else None))

    # EC2 Role 자격증명이면 발급 대상 인스턴스 (arn:aws:ec2:<region>:<acct>:instance/i-...)
    issued_to = _s(dig(uid, "inScopeOf.credentialsIssuedTo"))
    issued_instance = issued_to.split("/")[-1] if issued_to and ":instance/" in issued_to else None

    params = aws.get("requestParameters")
    if isinstance(params, (dict, list)):
        params = json.dumps(params, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    bucket, key = _s(dig(aws, "log_info.s3bucket")), _s(dig(aws, "log_info.log_file"))
    mfa = _s(attrs.get("mfaAuthenticated"))
    return {
        "principal_type": principal_type,                    # AssumedRole / IAMUser / Root ...
        "principal_name": principal_name,                    # 역할 이름 또는 사용자 이름
        "principal_arn": _s(issuer.get("arn")) or _s(uid.get("arn")),
        "session_arn": _s(uid.get("arn")),
        "principal_id": principal_id,
        "session_name": session,
        "account_id": _s(uid.get("accountId")) or _s(aws.get("recipientAccountId")),
        "access_key_id": _s(uid.get("accessKeyId")),
        "mfa": mfa.lower() if mfa else None,
        "session_created": _s(attrs.get("creationDate")),
        "issuer_type": _s(issuer.get("type")),
        "issuer_principal_id": _s(issuer.get("principalId")),
        "issuer_account_id": _s(issuer.get("accountId")),
        "credentials_issued_to": issued_to,
        "credential_instance_id": issued_instance,
        "credential_instance_name": instance_name(issued_instance) if issued_instance else None,
        "event_source": _s(aws.get("eventSource")),
        "event_name": _s(aws.get("eventName")),
        "event_time": _s(aws.get("eventTime")),
        "aws_region": _s(aws.get("awsRegion")) or REGION,
        "source_ip": _s(aws.get("sourceIPAddress")),         # IP 또는 서비스 이름(lambda.amazonaws.com 등)
        "user_agent": _s(aws.get("userAgent")),
        "error_code": _s(aws.get("errorCode")),
        "error_message": _s(aws.get("errorMessage")),
        "request_parameters": _s(params),
        "cloudtrail_log": f"s3://{bucket}/{key}" if bucket and key else None,
    }


def cloudtrail_summary(ct):
    """Description·payload 용 한 줄 요약 (원본 JSON 은 1024자에서 잘리므로 요약으로 대체)."""
    service = (ct["event_source"] or "unknown").replace(".amazonaws.com", "")
    result = f"실패({ct['error_code']})" if ct["error_code"] else "성공"
    parts = [
        f"{ct['principal_type'] or 'unknown'} {ct['principal_name'] or 'unknown'}",
        f"→ {service}:{ct['event_name'] or 'unknown'}",
        f"· 결과 {result}",
        f"· 출발지 {ct['source_ip'] or 'unknown'}",
    ]
    if ct["credential_instance_id"]:
        name = ct["credential_instance_name"]
        parts.append(f"· EC2 Role 자격증명({name + ' ' if name else ''}{ct['credential_instance_id']})")
    if ct["request_parameters"]:
        parts.append(f"· 요청 {ct['request_parameters']}")
    return " ".join(parts)


def rule_mitre(rule):
    """(기법 ID 목록, 전술 목록, 출처). 룰의 MITRE 가 우선, 없으면 RULE_MITRE 표."""
    ids = [str(i) for i in (dig(rule, "mitre.id", []) or [])]
    tactics = [str(t) for t in (dig(rule, "mitre.tactic", []) or [])]
    if ids or tactics:
        return ids, tactics, "wazuh"
    fallback = RULE_MITRE.get(str(rule.get("id")))
    if fallback:
        return list(fallback.get("id", [])), list(fallback.get("tactic", [])), "parser"
    return [], [], None


def finding_types(rule):
    """네임스페이스/카테고리/finding type 형식. 첫 번째 값이 대표.
    기법(technique) → 전술(tactic) → Wazuh 그룹 → 기본값 순서로 정한다."""
    types = []
    ids, tactics, _ = rule_mitre(rule)
    for tid in ids:
        t = TECHNIQUE_TO_TYPE.get(tid.split(".")[0])          # T1498.001 → T1498
        if t and t not in types:
            types.append(t)
    for tactic in tactics:
        if tactic == "Impact" and any(x.startswith("Effects/") for x in types):
            continue                                          # 기법으로 이미 정해짐 (DoS 를 데이터 파괴로 오표기 방지)
        t = TACTIC_TO_TYPE.get(tactic)
        if t and t not in types:
            types.append(t)
    if not types:
        groups = rule.get("groups") or []
        types = [next((t for g, t in GROUP_TO_TYPE if g in groups), DEFAULT_TYPE)]
    classifier = f"Wazuh-Rule{rule.get('id', 'unknown')}"     # finding type (3번째 칸, '/' 금지)
    return [f"{t}/{classifier}" for t in types]


def category_of(types):
    return types[0].split("/")[1]


def finding_type_of(types):
    return types[0].split("/")[2]


def group_id(alert):
    """묶는 단위: 규칙 + 서버 + 날짜(KST). 같은 값이면 같은 finding.
    CloudTrail 알림은 서버가 늘 Manager(000)라서, 서버 대신 IAM 주체(계정+이름)로 묶는다.
    (그러지 않으면 그날 서로 다른 역할·사용자의 탐지가 전부 한 finding 으로 합쳐진다.)"""
    rule_id = str(dig(alert, "rule.id", "unknown"))
    day = parse_time(alert.get("timestamp")).astimezone(KST).strftime("%Y-%m-%d")
    ct = cloudtrail_info(alert)
    if ct and ct["principal_name"]:
        unit = f"principal-{ct['account_id'] or 'unknown'}-{ct['principal_name']}"
    else:
        unit = f"agent-{dig(alert, 'agent.id', '000')}"
    return f"wazuh/rule-{rule_id}/{unit}/{day}"[:512], day


def source_url(alert, day):
    """Wazuh 대시보드에서 이 알림 1건을 여는 링크 (해당 KST 하루 범위로 검색)."""
    if not DASHBOARD_URL or not alert.get("id"):
        return None
    start = datetime.datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=KST)
    end = start + datetime.timedelta(days=1)
    return SOURCE_URL_TEMPLATE.format(
        base=DASHBOARD_URL.rstrip("/"),
        start=asff_time(start.astimezone(datetime.timezone.utc)),
        end=asff_time(end.astimezone(datetime.timezone.utc)),
        alert_id=alert["id"],
    )


# ---- 메모장 (상태 파일) -------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state):
    cutoff = (datetime.datetime.now(KST) - datetime.timedelta(days=STATE_KEEP_DAYS)).strftime("%Y-%m-%d")
    state = {k: v for k, v in state.items() if v.get("seen", "9999") >= cutoff}  # 며칠간 안 쓴 칸 정리
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_FILE)                     # 쓰다가 끊겨도 원본이 깨지지 않게


def next_entry(state, fid, day, when):
    """이번 알림을 반영한 메모 한 줄 (저장은 송고 성공 후에)."""
    old = state.get(fid)
    seen = datetime.datetime.now(KST).strftime("%Y-%m-%d")      # 메모를 마지막으로 쓴 날
    if old:
        return {"day": day, "first": min(old["first"], asff_time(when)), "last": max(old["last"], asff_time(when)),
                "count": old["count"] + 1, "seen": seen}
    return {"day": day, "first": asff_time(when), "last": asff_time(when), "count": 1, "seen": seen}


# ---- 번역 담당 ---------------------------------------------------------------
def build_iam_resource(ct):
    """CloudTrail 의 IAM 주체 → AwsIamAccessKey 리소스 (GuardDuty IAM finding 과 같은 타입)."""
    details = {k: v for k, v in {
        "AccessKeyId": ct["access_key_id"],
        "PrincipalId": ct["principal_id"],
        "PrincipalType": ct["principal_type"],
        "PrincipalName": ct["principal_name"],
        "AccountId": ct["account_id"],
    }.items() if v}

    session = {}
    attributes = {}
    if ct["mfa"] in ("true", "false"):
        attributes["MfaAuthenticated"] = ct["mfa"] == "true"
    if ct["session_created"]:
        attributes["CreationDate"] = ct["session_created"]
    if attributes:
        session["Attributes"] = attributes
    issuer = {k: v for k, v in {
        "Type": ct["issuer_type"],
        "PrincipalId": ct["issuer_principal_id"],
        "Arn": ct["principal_arn"] if ct["issuer_type"] else None,
        "AccountId": ct["issuer_account_id"],
        "UserName": ct["principal_name"] if ct["issuer_type"] else None,
    }.items() if v}
    if issuer:
        session["SessionIssuer"] = issuer
    if session:
        details["SessionContext"] = session

    # 임시 키(ASIA…)든 영구 키(AKIA…)든 키가 있으면 GuardDuty 와 같은 Id 형식, 없으면 주체 ARN
    if ct["access_key_id"]:
        resource_id = f"AWS::IAM::AccessKey:{ct['access_key_id']}"
    else:
        resource_id = ct["principal_arn"] or f"iam-principal/{ct['account_id']}/{ct['principal_name']}"
    return {
        "Type": "AwsIamAccessKey",
        "Id": resource_id[:512],
        "Partition": "aws",
        "Region": ct["aws_region"],
        "Details": {"AwsIamAccessKey": details},
    }


def build_resource(agent, ec2):
    """EC2 를 알면 AwsEc2Instance(ARN), 모르면 기존처럼 Other."""
    agent_id = str(agent.get("id", "000"))
    agent_name = str(agent.get("name", "unknown"))
    agent_ip = str(agent.get("ip", "unknown"))
    if ec2["instance_id"] and ec2["account_id"]:
        resource = {
            "Type": "AwsEc2Instance",
            "Id": f"arn:aws:ec2:{ec2['region']}:{ec2['account_id']}:instance/{ec2['instance_id']}",
            "Partition": "aws",
            "Region": ec2["region"],
            "Tags": {"Name": ec2["name"][:256]},
        }
        if is_ipv4(agent_ip):
            resource["Details"] = {"AwsEc2Instance": {"IpV4Addresses": [agent_ip]}}
        return resource
    return {
        "Type": "Other",
        "Id": f"wazuh-agent/{agent_id}/{agent_name}"[:512],
        "Partition": "aws",
        "Region": ec2["region"],
        "Tags": {"Name": ec2["name"][:256]},
        "Details": {"Other": {"agent_ip": agent_ip}},
    }


def convert(alert, entry=None):
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "unknown"))
    level = int(rule.get("level", 0) or 0)
    when = parse_time(alert.get("timestamp"))
    fid, day = group_id(alert)
    if entry is None:
        entry = {"day": day, "first": asff_time(when), "last": asff_time(when), "count": 1}

    ct = cloudtrail_info(alert)
    title = " ".join(str(rule.get("description") or f"Wazuh rule {rule_id}").split())   # 공백 정리
    log = alert.get("full_log") or rule.get("description") or f"Wazuh rule {rule_id} alert"
    if ct:
        log = cloudtrail_summary(ct)          # 원본 CloudTrail JSON 은 잘리므로 요약으로 (원본은 cloudtrail_log)
    desc = f"[{day} KST 누적 {entry['count']}회, 최근 알림] {log}"
    agent_id = str(agent.get("id", "000"))
    agent_name = str(agent.get("name", "unknown"))

    types = finding_types(rule)
    mitre_ids, mitre_tactics, mitre_source = rule_mitre(rule)
    src_ip, src_ver = source_ip(alert)
    ec2 = ec2_info(agent)
    if "suricata" in (rule.get("groups") or []) and not ct:
        web = WEB_SERVER_BY_IP.get(dig(alert, "data.src_ip"))
        if web and web in AGENT_RESOURCES:
            t = AGENT_RESOURCES[web]
            ec2 = {"instance_id": t["instance_id"], "account_id": t["account_id"],
                   "region": REGION, "name": web}
    if ct:
        # 대상은 Manager 가 아니라 IAM 주체가 있는 Workload 계정
        ec2 = {"instance_id": None, "account_id": ct["account_id"],
               "region": ct["aws_region"], "name": ct["principal_name"] or "unknown"}
    severity = {"Label": level_to_label(level), "Original": str(level)}

    fields = {
        # ---- R2 알림용 (정규화 Lambda 가 바로 읽는 칸) ----
        "wazuh/category": category_of(types),
        "wazuh/finding_type": finding_type_of(types),
        "wazuh/source_ip": src_ip,
        "wazuh/instance_id": ec2["instance_id"],
        "wazuh/resource_name": ec2["name"],
        "wazuh/resource_account_id": ec2["account_id"],     # 리소스가 있는 Workload 계정
        "wazuh/region": ec2["region"],
        "wazuh/uri": first_of(alert, URI_PATHS),
        "wazuh/payload": (cloudtrail_summary(ct) if ct
                          else first_of(alert, PAYLOAD_PATHS) or alert.get("full_log")),
        # ---- 기존 ----
        "wazuh/count": entry["count"],
        "wazuh/last_alert_id": alert.get("id"),          # Wazuh 대시보드에서 찾아갈 단서
        "wazuh/rule_id": rule_id,
        "wazuh/rule_level": level,
        "wazuh/rule_groups": ",".join(rule.get("groups") or []),
        "wazuh/mitre_ids": ",".join(mitre_ids),
        "wazuh/mitre_tactics": ",".join(mitre_tactics),
        "wazuh/mitre_source": mitre_source,              # wazuh = 룰에 있던 값, parser = RULE_MITRE 표
        "wazuh/agent_id": agent_id,
        "wazuh/agent_name": agent_name,
        "wazuh/agent_ip": agent.get("ip"),
        "wazuh/location": alert.get("location"),
    }
    if ct:
        # ---- R3 알림용 (CloudTrail IAM 주체·API 호출) ----
        fields.update({
            "wazuh/principal_type": ct["principal_type"],
            "wazuh/principal_name": ct["principal_name"],
            "wazuh/principal_arn": ct["principal_arn"],
            "wazuh/principal_account_id": ct["account_id"],
            "wazuh/session_name": ct["session_name"],
            "wazuh/access_key_id": ct["access_key_id"],
            "wazuh/mfa_authenticated": ct["mfa"],
            "wazuh/session_created_at": ct["session_created"],
            "wazuh/credential_instance_id": ct["credential_instance_id"],
            "wazuh/credential_instance_name": ct["credential_instance_name"],
            "wazuh/event_source": ct["event_source"],
            "wazuh/event_name": ct["event_name"],
            "wazuh/event_time": ct["event_time"],
            "wazuh/aws_source": ct["source_ip"],          # IP 가 아닐 수도 있는 원본 값
            "wazuh/user_agent": ct["user_agent"],
            "wazuh/error_code": ct["error_code"],
            "wazuh/error_message": ct["error_message"],
            "wazuh/request_parameters": ct["request_parameters"],
            "wazuh/cloudtrail_log": ct["cloudtrail_log"],
        })
    for path in EXTRA_FIELDS:
        fields["wazuh/" + path] = dig(alert, path)
    fields = {k: str(v)[:1000] for k, v in fields.items() if v not in (None, "", [])}

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": fid,
        "ProductArn": PRODUCT_ARN,
        "GeneratorId": f"wazuh-rule-{rule_id}",
        "AwsAccountId": ACCOUNT_ID,                                    # 송고하는 계정(Security) 고정
        "Types": types,
        "CreatedAt": entry["first"],                                   # 처음 만든 시각 유지
        "UpdatedAt": asff_time(datetime.datetime.now(datetime.timezone.utc)),  # 갱신마다 새로
        "FirstObservedAt": entry["first"],
        "LastObservedAt": entry["last"],
        "Severity": severity,
        "FindingProviderFields": {"Types": types, "Severity": severity},   # 같은 Id 재송고 때도 확실히 반영
        "Title": ("[Wazuh] " + title)[:256],
        "Description": desc[:1024],
        "Resources": [build_iam_resource(ct) if ct else build_resource(agent, ec2)],
        "ProductFields": fields,
    }
    url = source_url(alert, day)
    if url:
        finding["SourceUrl"] = url
    if src_ip:
        finding["Network"] = {"SourceIpV4" if src_ver == 4 else "SourceIpV6": src_ip}
    return finding


def r2_view(f):
    """R2 알림 필드만 뽑은 모습 (정규화 Lambda 가 만들 결과와 같은 기준)."""
    pf = f.get("ProductFields", {})
    return {
        "finding_id": f["Id"],
        "title": f["Title"],
        "severity": f["Severity"]["Label"],
        "Types": f["Types"],
        "category": pf.get("wazuh/category"),
        "finding_type": pf.get("wazuh/finding_type"),
        "source_ip": pf.get("wazuh/source_ip"),
        "resource_id": f["Resources"][0]["Id"],
        "instance_id": pf.get("wazuh/instance_id"),
        "resource_name": pf.get("wazuh/resource_name"),
        "account_id": pf.get("wazuh/resource_account_id"),
        "region": pf.get("wazuh/region"),
        "uri": pf.get("wazuh/uri"),
        "payload": pf.get("wazuh/payload"),
        "source_url": f.get("SourceUrl"),
        "first_observed_at": f.get("FirstObservedAt"),
    }


def r3_view(f):
    """R3 알림 필드만 뽑은 모습 (CloudTrail IAM finding)."""
    pf = f.get("ProductFields", {})
    keys = ("principal_type", "principal_name", "principal_arn", "principal_account_id", "session_name",
            "access_key_id", "mfa_authenticated", "session_created_at", "credential_instance_id",
            "credential_instance_name", "event_source", "event_name", "event_time", "aws_source",
            "user_agent", "error_code", "error_message", "request_parameters", "cloudtrail_log")
    view = {
        "finding_id": f["Id"],
        "title": f["Title"],
        "severity": f["Severity"]["Label"],
        "Types": f["Types"],
        "category": pf.get("wazuh/category"),
        "finding_type": pf.get("wazuh/finding_type"),
        "resource_type": f["Resources"][0]["Type"],
        "resource_id": f["Resources"][0]["Id"],
        "region": pf.get("wazuh/region"),
        "source_ip": pf.get("wazuh/source_ip"),
    }
    view.update({k: pf.get("wazuh/" + k) for k in keys})
    view.update(source_url=f.get("SourceUrl"), first_observed_at=f.get("FirstObservedAt"))
    return view


# ---- 형식 검사 ---------------------------------------------------------------
REQUIRED = ["SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types",
            "CreatedAt", "UpdatedAt", "Severity", "Title", "Description", "Resources"]


def validate(f):
    problems = [f"필수 칸 없음: {k}" for k in REQUIRED if not f.get(k)]
    if len(f.get("Title", "")) > 256: problems.append("Title 256자 초과")
    if len(f.get("Description", "")) > 1024: problems.append("Description 1024자 초과")
    if f.get("AwsAccountId") != ACCOUNT_ID: problems.append("AwsAccountId가 Security 계정이 아님")
    if not all(isinstance(v, str) for v in f.get("ProductFields", {}).values()):
        problems.append("ProductFields에 문자열 아닌 값")
    if len(f.get("ProductFields", {})) > 50: problems.append("ProductFields 50개 초과")
    if any(len(t.split("/")) != 3 for t in f.get("Types", [])):
        problems.append("Types가 네임스페이스/카테고리/finding type 3단이 아님")
    for r in f.get("Resources", []):
        if r.get("Type") == "AwsEc2Instance" and not r.get("Id", "").startswith("arn:aws:ec2:"):
            problems.append("AwsEc2Instance Id가 EC2 ARN이 아님")
        if r.get("Type") == "AwsIamAccessKey" and not dig(r, "Details.AwsIamAccessKey.PrincipalName"):
            problems.append("AwsIamAccessKey에 PrincipalName 없음")
    return problems


# ---- 송고 담당 ---------------------------------------------------------------
def log(msg):
    line = f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} custom-securityhub: {msg}\n"
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def send(finding):
    import boto3
    client = boto3.client("securityhub", region_name=REGION)
    r = client.batch_import_findings(Findings=[finding])
    return r["SuccessCount"], r["FailedCount"], r.get("FailedFindings", [])


# ---- 지휘 --------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    mode = "auto"
    if args and args[0] in ("--dry-run", "--check", "--fields", "--send"):
        mode, args = args[0][2:], args[1:]
    if not args:
        print("usage: [--dry-run|--check|--fields|--send] <alert.json>")
        sys.exit(2)
    with open(args[0]) as fh:
        alert = json.load(fh)
    fid, day = group_id(alert)
    when = parse_time(alert.get("timestamp"))

    if mode in ("dry-run", "check", "fields"):       # 메모장은 읽기만
        f = convert(alert, next_entry(load_state(), fid, day, when))
        if mode == "dry-run":
            print(json.dumps(f, indent=2, ensure_ascii=False))
        elif mode == "fields":
            view = r3_view(f) if f["Resources"][0]["Type"] == "AwsIamAccessKey" else r2_view(f)
            print(json.dumps(view, indent=2, ensure_ascii=False))
        else:
            p = validate(f)
            pf = f["ProductFields"]
            target = pf.get("wazuh/instance_id") or pf.get("wazuh/principal_name") or "-"
            print(f"{f['Id']:<42} | {f['Severity']['Label']:<13} | {f['Types'][0]:<45} | "
                  f"ip={pf.get('wazuh/source_ip', '-'):<15} | target={target:<19} | "
                  f"count={pf['wazuh/count']:<3} | {'OK' if not p else 'FAIL ' + '; '.join(p)}")
        return

    # 송고: 메모장 잠금 → 읽기 → 번역 → 송고 → 성공하면 메모 저장 → 잠금 해제
    with open(STATE_FILE + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)             # 알림이 동시에 와도 한 번에 하나씩
        state = load_state()
        entry = next_entry(state, fid, day, when)
        f = convert(alert, entry)
        p = validate(f)
        if p:
            log(f"skip {fid}: {'; '.join(p)}")
            sys.exit(1)
        try:
            ok, bad, detail = send(f)
        except Exception as e:                       # 권한·네트워크 문제 등
            log(f"error {fid}: {e}")
            sys.exit(1)
        if bad:
            log(f"failed {fid}: {detail}")
            sys.exit(1)
        state[fid] = entry
        save_state(state)
        log(f"imported {fid} count={entry['count']} severity={f['Severity']['Label']} alert={alert.get('id')}")
    if mode == "send":
        print(f"success: {ok} failed: {bad} id: {fid} count: {entry['count']}")


if __name__ == "__main__":
    main()
