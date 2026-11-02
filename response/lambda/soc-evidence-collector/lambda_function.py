"""
SOC 증거 수집 Lambda (Security 계정)

입력: Step Functions enrich 단계의 출력 JSON (runbook_id 포함)
출력: 입력 JSON + "evidence" 요약 (S3 경로, manifest, 오류 목록 등)

RunBook별 수집
  공통 : Finding 원본(정규화본 + Security Hub ASFF 원본), 대상 인스턴스 정보, 보안 그룹,
         CloudTrail(인스턴스 기준)
  R2   : WAF 로그, VPC Flow Logs(공격 IP), ALB 액세스 로그, Security Hub 연관 Finding,
         공격 IP가 VPC 내부 IP면 출발지 인스턴스 정보
  R3   : [자격증명] 액세스 키·IAM 사용자 기준 CloudTrail(여러 리전)과 사용 요약,
         사용자/역할의 IAM 상태(키·정책·MFA·콘솔 로그인), 같은 키의 Security Hub Finding
         [호스트] 공격 IP Flow Logs, SSM 인증 정보(로그인 기록·sshd·sudo·계정·SSH 키)
  R4   : VPC Flow Logs(인스턴스 IP), SSM 휘발성 정보, EBS 스냅샷
  R5   : [인스턴스] SSM 휘발성 정보, EBS 스냅샷, 송수신 트래픽 집계(Flow Logs),
         원격 IP Flow Logs, 대상 그룹 상태, EC2·ALB 지표
         [S3] 버킷 설정(정책·퍼블릭 차단·ACL·버전 관리·로깅·암호화), 버킷 기준 CloudTrail
  R7   : 공통만

SSM 명령과 EBS 스냅샷은 IR-Automation=enabled 태그가 있는 인스턴스에만 실행한다.
수집 단계 하나가 실패해도 나머지는 계속 진행하고, 실패 내용은 manifest에 기록한다.
"""

import os
import re
import json
import time
import gzip
import hashlib
import ipaddress
import datetime as dt
from collections import Counter

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# ------------------------------------------------------------------
# 설정 (환경 변수로 덮어쓸 수 있음)
# ------------------------------------------------------------------
REGION = os.environ.get("AWS_REGION", "ap-northeast-2")
BUCKET = os.environ["EVIDENCE_BUCKET"]
COLLECTOR_ROLE_ARN = os.environ["COLLECTOR_ROLE_ARN"]
WORKLOAD_ACCOUNT_ID = COLLECTOR_ROLE_ARN.split(":")[4]

WAF_LOG_GROUP = os.environ.get("WAF_LOG_GROUP", "aws-waf-logs-web-alb-demo")
FLOW_LOG_GROUP = os.environ.get("FLOW_LOG_GROUP", "/vpc/flowlogs/web-alb-demo")
ALB_LOG_BUCKET = os.environ.get("ALB_LOG_BUCKET", "workload-access-logs-byos")

IR_TAG_KEY = os.environ.get("IR_TAG_KEY", "IR-Automation")
IR_TAG_VALUE = os.environ.get("IR_TAG_VALUE", "enabled")

WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "60"))
SSM_WAIT_SECONDS = int(os.environ.get("SSM_WAIT_SECONDS", "150"))
SECURITYHUB_LOOKBACK_DAYS = int(os.environ.get("SECURITYHUB_LOOKBACK_DAYS", "7"))

# R3/R5: CloudTrail 조회
#  - IAM 같은 글로벌 서비스 API 호출(CreateAccessKey 등)은 us-east-1에 기록되므로 기본 포함
#  - 키는 탐지 시점보다 먼저 쓰였을 수 있어 탐지 전 24시간까지 거슬러 조회
CLOUDTRAIL_REGIONS = list(dict.fromkeys(
    r.strip()
    for r in os.environ.get("CLOUDTRAIL_REGIONS", f"{REGION},us-east-1").split(",")
    if r.strip()
))
CLOUDTRAIL_LOOKBACK_HOURS = int(os.environ.get("CLOUDTRAIL_LOOKBACK_HOURS", "24"))
CLOUDTRAIL_MAX_EVENTS = int(os.environ.get("CLOUDTRAIL_MAX_EVENTS", "1000"))

# R5: CloudWatch 지표 (평소 수준과 비교할 수 있게 앞쪽 6시간을 함께 가져옴)
METRIC_BASELINE_HOURS = int(os.environ.get("METRIC_BASELINE_HOURS", "6"))
METRIC_PERIOD = int(os.environ.get("METRIC_PERIOD", "300"))

# CloudTrail LookupEvents는 계정·리전당 초당 2회 제한이 있어 재시도를 넉넉히 둔다
CT_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
INSTANCE_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")

# SSM 에이전트 등이 주기적으로 발생시키는 CloudTrail 노이즈
CLOUDTRAIL_NOISE = {
    "UpdateInstanceInformation",
    "ListInstanceAssociations",
    "DescribeInstanceProperties",
    "DescribeAssociation",
    "UpdateInstanceAssociationStatus",
    "GetDeployablePatchSnapshotForInstance",
    "PutInventory",
    "PutComplianceItems",
}

# R3: 탈취된 자격증명으로 실행됐다면 바로 확인해야 하는 API
SENSITIVE_EVENTS = {
    # 지속성 확보·권한 상승
    "CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "AttachUserPolicy", "PutUserPolicy", "AddUserToGroup",
    "CreateRole", "AttachRolePolicy", "PutRolePolicy", "UpdateAssumeRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    # 탐지·로깅 회피
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteDetector", "UpdateDetector", "DisableSecurityHub", "DeleteFlowLogs",
    # 자원 남용·노출
    "RunInstances", "AuthorizeSecurityGroupIngress", "ModifyInstanceAttribute",
    "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPublicAccessBlock",
    "GetSecretValue",
}

PROFILES = {
    "R2": ["common", "r2"],
    "R3": ["common", "r3"],
    "R4": ["common", "r4"],
    "R5": ["common", "r5"],
    "R7": ["common"],
}

# Amazon Linux 2023 기준 휘발성 정보 수집 스크립트 (R4, R5)
VOLATILE_SCRIPT = r"""
section() { echo; echo "===== $1 ====="; }
section "date (UTC)"; date -u
section "hostname"; hostname
section "uptime"; uptime
section "logged in users"; who -a
section "last logins"; last -n 30 2>/dev/null || echo "last not available"
section "processes (by cpu)"; ps auxww --sort=-%cpu
section "process tree"; ps -ejH
section "network connections"; ss -tunap
section "listening ports"; ss -tlnp
section "interfaces"; ip addr
section "routes"; ip route
section "neighbors (arp)"; ip neigh
section "dns config"; cat /etc/resolv.conf
section "deleted executables still running"; ls -l /proc/[0-9]*/exe 2>/dev/null | grep deleted
section "crontab (all users)"; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "--- $u ---" && echo "$c"; done
section "cron dirs"; ls -la /etc/cron* 2>/dev/null
section "systemd timers"; systemctl list-timers --all --no-pager
section "running services"; systemctl list-units --type=service --state=running --no-pager
section "tmp dirs"; ls -la --time-style=full-iso /tmp /var/tmp /dev/shm
section "files modified in tmp (24h)"; find /tmp /var/tmp /dev/shm -type f -mmin -1440 -exec ls -la --time-style=full-iso {} \; 2>/dev/null
section "authorized_keys"; for h in /root /home/*; do [ -f "$h/.ssh/authorized_keys" ] && echo "--- $h ---" && cat "$h/.ssh/authorized_keys"; done
section "sshd journal"; journalctl _COMM=sshd -n 100 --no-pager 2>/dev/null
section "root shell history"; tail -n 100 /root/.bash_history 2>/dev/null
exit 0
"""

# Amazon Linux 2023 기준 인증 정보 수집 스크립트 (R3 호스트)
# 자격증명 파일은 내용 대신 목록과 수정 시각만 남긴다
AUTH_SCRIPT = r"""
section() { echo; echo "===== $1 ====="; }
section "date (UTC)"; date -u
section "hostname"; hostname
section "logged in users"; who -a
section "last logins"; last -n 50 -F 2>/dev/null || echo "last not available"
section "failed logins"; lastb -n 50 -F 2>/dev/null || echo "lastb not available"
section "sshd journal (24h)"; journalctl _COMM=sshd --since "-24h" --no-pager 2>/dev/null | tail -n 500
section "sudo journal (24h)"; journalctl _COMM=sudo --since "-24h" --no-pager 2>/dev/null | tail -n 200
section "secure log"; tail -n 300 /var/log/secure 2>/dev/null || echo "no /var/log/secure"
section "accounts with login shell"; grep -Ev '(/nologin|/false)$' /etc/passwd
section "account files (mtime)"; ls -la --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null; ls -la --time-style=full-iso /etc/sudoers.d 2>/dev/null
section "authorized_keys"; for h in /root /home/*; do f="$h/.ssh/authorized_keys"; [ -f "$f" ] && echo "--- $f ---" && ls -la --time-style=full-iso "$f" && cat "$f"; done
section "sshd effective config"; sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|permitrootlogin|pubkeyauthentication|authorizedkeysfile) '
section "aws credential files (list only)"; for h in /root /home/*; do [ -d "$h/.aws" ] && echo "--- $h/.aws ---" && ls -la --time-style=full-iso "$h/.aws"; done
exit 0
"""

WAF_QUERY = (
    "fields @timestamp, action, terminatingRuleId, httpRequest.clientIp, "
    "httpRequest.country, httpRequest.httpMethod, httpRequest.uri, httpRequest.args "
    '| filter httpRequest.clientIp = "{ip}" '
    "| sort @timestamp desc | limit 500"
)

FLOW_QUERY = (
    "fields @timestamp, interfaceId, srcAddr, srcPort, dstAddr, dstPort, "
    "protocol, packets, bytes, action "
    '| filter srcAddr = "{ip}" or dstAddr = "{ip}" '
    "| sort @timestamp desc | limit 500"
)

# R5: 인스턴스가 어디로 얼마나 보냈는지 / 어디서 얼마나 받았는지
FLOW_OUT_QUERY = (
    'filter srcAddr = "{ip}" '
    "| stats sum(bytes) as totalBytes, sum(packets) as totalPackets, count(*) as flows "
    "by dstAddr, dstPort, protocol, action "
    "| sort totalBytes desc | limit 100"
)

FLOW_IN_QUERY = (
    'filter dstAddr = "{ip}" '
    "| stats sum(bytes) as totalBytes, sum(packets) as totalPackets, count(*) as flows "
    "by srcAddr, dstPort, protocol, action "
    "| sort totalBytes desc | limit 100"
)


# ------------------------------------------------------------------
# 공용 유틸
# ------------------------------------------------------------------
def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value):
    if not value:
        return None
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def valid_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except (ValueError, TypeError):
        return None


def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private


def time_window(event):
    now = utcnow()
    first = parse_time(event.get("first_observed_at")) or now
    last = parse_time(event.get("last_observed_at")) or first
    start = first - dt.timedelta(minutes=WINDOW_MINUTES)
    end = min(last + dt.timedelta(minutes=WINDOW_MINUTES), now)
    if end <= start:
        end = start + dt.timedelta(minutes=1)
    return start, end


def to_json_safe(obj):
    return json.loads(json.dumps(obj, default=str))


def error_code(exc):
    return exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else None


class Evidence:
    """증거 파일을 S3에 저장하고 SHA-256 manifest를 관리한다."""

    def __init__(self, s3, finding_id, runbook):
        now = utcnow()
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", finding_id)[:120]
        self.rel = f"{now:%Y/%m/%d}/{safe_id}/{runbook}-{now:%Y%m%dT%H%M%SZ}"
        self.prefix = f"evidence/{self.rel}"
        self.s3 = s3
        self.items = []
        self.errors = []
        self.notes = []

    def put(self, name, data):
        body = json.dumps(data, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        key = f"{self.prefix}/{name}.json"
        self.s3.put_object(Bucket=BUCKET, Key=key, Body=body, ContentType="application/json")
        self.items.append({
            "name": name,
            "key": key,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
        })

    def register(self, name, key):
        """다른 주체(SSM 등)가 올린 객체를 manifest에 해시와 함께 등록"""
        body = self.s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
        self.items.append({
            "name": name,
            "key": key,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
        })

    def run(self, name, fn):
        """수집 단계 실행. 결과는 저장하고, 실패해도 예외를 밖으로 던지지 않는다."""
        try:
            data = fn()
            if data is not None:
                self.put(name, data)
            return data
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"step": name, "error": f"{type(exc).__name__}: {exc}"})
            return None

    def write_manifest(self, header):
        manifest = dict(header, items=self.items, errors=self.errors, notes=self.notes)
        body = json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        key = f"{self.prefix}/manifest.json"
        self.s3.put_object(Bucket=BUCKET, Key=key, Body=body, ContentType="application/json")
        return key


# ------------------------------------------------------------------
# AWS 접근 / 대상 식별
# ------------------------------------------------------------------
def workload_session():
    creds = boto3.client("sts").assume_role(
        RoleArn=COLLECTOR_ROLE_ARN,
        RoleSessionName="soc-evidence-collector",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )


def first_instance(reservations):
    for r in reservations:
        for i in r.get("Instances", []):
            return i
    return None


def resolve_target(ec2, event):
    """instance_id가 있으면 그대로, 없으면(Wazuh 등) agent_ip / private_ip로 역조회"""
    instance_id = event.get("instance_id")
    if instance_id:
        try:
            res = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as e:
            if error_code(e) == "InvalidInstanceID.NotFound":
                return None, "instance_id_not_found"
            raise
        return first_instance(res), "instance_id"

    ip = valid_ip(event.get("private_ip") or (event.get("details") or {}).get("agent_ip"))
    if ip:
        res = ec2.describe_instances(
            Filters=[{"Name": "private-ip-address", "Values": [ip]}]
        )["Reservations"]
        inst = first_instance(res)
        return inst, "private_ip" if inst else "private_ip_not_found"

    return None, "no_identifier"


def instance_by_ip(ec2, ip):
    """VPC 내부 IP의 주인 인스턴스 요약 (R2 내부 출발지 확인용)"""
    res = ec2.describe_instances(
        Filters=[{"Name": "private-ip-address", "Values": [ip]}]
    )["Reservations"]
    inst = first_instance(res)
    if not inst:
        return {"ip": ip, "found": False}
    tags = {t["Key"]: t.get("Value") for t in inst.get("Tags", [])}
    return {
        "ip": ip,
        "found": True,
        "instance_id": inst["InstanceId"],
        "name": tags.get("Name"),
        "state": (inst.get("State") or {}).get("Name"),
        "launch_time": inst.get("LaunchTime"),
        "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
        "security_groups": inst.get("SecurityGroups"),
        "subnet_id": inst.get("SubnetId"),
        "tags": tags,
    }


def ir_enabled(instance):
    tags = {t["Key"]: t.get("Value") for t in instance.get("Tags", [])}
    return (tags.get(IR_TAG_KEY) or "").strip().lower() == IR_TAG_VALUE


# ------------------------------------------------------------------
# CloudWatch Logs Insights
# ------------------------------------------------------------------
def insights(logs, group, query, start, end, limit=500, wait_seconds=60):
    qid = logs.start_query(
        logGroupName=group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=query,
        limit=limit,
    )["queryId"]

    deadline = time.time() + wait_seconds
    result = {"status": "Unknown", "results": []}
    while time.time() < deadline:
        time.sleep(1)
        result = logs.get_query_results(queryId=qid)
        if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
    else:
        try:
            logs.stop_query(queryId=qid)
        except ClientError:
            pass

    rows = [
        {f["field"]: f["value"] for f in row if not f["field"].startswith("@ptr")}
        for row in result.get("results", [])
    ]
    return {
        "log_group": group,
        "query": query,
        "window": [start, end],
        "status": result["status"],
        "count": len(rows),
        "rows": rows,
    }


# ------------------------------------------------------------------
# CloudTrail
# ------------------------------------------------------------------
def slim_event(e, region=None):
    detail = json.loads(e.get("CloudTrailEvent") or "{}")
    identity = detail.get("userIdentity") or {}
    return {
        "eventTime": detail.get("eventTime"),
        "eventName": e.get("EventName"),
        "eventSource": detail.get("eventSource"),
        "awsRegion": detail.get("awsRegion") or region,
        "userArn": identity.get("arn"),
        "accessKeyId": identity.get("accessKeyId"),
        "sourceIPAddress": detail.get("sourceIPAddress"),
        "userAgent": detail.get("userAgent"),
        "readOnly": detail.get("readOnly"),
        "errorCode": detail.get("errorCode"),
        "errorMessage": detail.get("errorMessage"),
        "requestParameters": detail.get("requestParameters"),
    }


def cloudtrail_by_resource(ct, resource_name, start, end, max_items=300):
    events, skipped = [], 0
    pages = ct.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_name}],
        StartTime=start,
        EndTime=end,
        PaginationConfig={"MaxItems": max_items},
    )
    for page in pages:
        for e in page.get("Events", []):
            if e.get("EventName") in CLOUDTRAIL_NOISE:
                skipped += 1
                continue
            events.append(slim_event(e))
    return {
        "resource": resource_name,
        "window": [start, end],
        "noise_skipped": skipped,
        "count": len(events),
        "events": events,
    }


def summarize_activity(events):
    """자격증명이 무엇에 쓰였는지 한눈에 보기 위한 요약"""
    def top(field, n=20):
        return Counter(e.get(field) for e in events if e.get(field)).most_common(n)

    times = sorted(e["eventTime"] for e in events if e.get("eventTime"))
    sensitive = [e for e in events if e.get("eventName") in SENSITIVE_EVENTS]
    return {
        "total": len(events),
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "source_ips": top("sourceIPAddress"),
        "user_agents": top("userAgent", 10),
        "regions": top("awsRegion"),
        "event_names": top("eventName", 30),
        "error_codes": top("errorCode", 10),  # AccessDenied가 많으면 권한 탐색(정찰) 흔적
        "write_event_count": sum(1 for e in events if e.get("readOnly") is False),
        "sensitive_event_count": len(sensitive),
        "sensitive_events": sensitive[:100],
    }


def cloudtrail_lookup(session, attr_key, attr_value, start, end, regions):
    """여러 리전에서 LookupEvents를 조회해 합친다. 리전 하나가 실패해도 나머지는 계속한다."""
    events, per_region, region_errors = [], {}, {}
    for region in regions:
        try:
            ct = session.client("cloudtrail", region_name=region, config=CT_CONFIG)
            pages = ct.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": attr_key, "AttributeValue": attr_value}],
                StartTime=start,
                EndTime=end,
                PaginationConfig={"MaxItems": CLOUDTRAIL_MAX_EVENTS},
            )
            count = 0
            for page in pages:
                for e in page.get("Events", []):
                    events.append(slim_event(e, region))
                    count += 1
            per_region[region] = count
        except Exception as exc:  # noqa: BLE001
            region_errors[region] = f"{type(exc).__name__}: {exc}"

    events.sort(key=lambda x: x.get("eventTime") or "")
    return {
        "attribute": {attr_key: attr_value},
        "window": [start, end],
        "regions": per_region,
        "region_errors": region_errors,
        "count": len(events),
        "summary": summarize_activity(events),
        "events": events,
    }


# ------------------------------------------------------------------
# ALB 액세스 로그
# ------------------------------------------------------------------
def alb_logs(s3w, ip, start, end, max_files=200, max_lines=500):
    base = f"AWSLogs/{WORKLOAD_ACCOUNT_ID}/elasticloadbalancing/{REGION}/"
    file_end = min(end + dt.timedelta(minutes=10), utcnow())  # ALB 로그는 5분 단위로 늦게 쌓임

    keys = []
    day = start.date()
    while day <= file_end.date():
        paginator = s3w.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=ALB_LOG_BUCKET, Prefix=f"{base}{day:%Y/%m/%d}/"):
            for obj in page.get("Contents", []):
                if start <= obj["LastModified"] <= file_end:
                    keys.append(obj["Key"])
        day += dt.timedelta(days=1)

    keys = sorted(keys)[:max_files]
    needle = f" {ip}:"  # ALB 로그의 client:port 필드
    matches = []
    for key in keys:
        raw = s3w.get_object(Bucket=ALB_LOG_BUCKET, Key=key)["Body"].read()
        text = gzip.decompress(raw).decode("utf-8", "replace")
        for line in text.splitlines():
            if needle in line:
                matches.append(line)
                if len(matches) >= max_lines:
                    break
        if len(matches) >= max_lines:
            break

    return {
        "bucket": ALB_LOG_BUCKET,
        "ip": ip,
        "window": [start, file_end],
        "files_scanned": len(keys),
        "count": len(matches),
        "lines": matches,
    }


# ------------------------------------------------------------------
# Security Hub (Security 계정, Lambda 자체 권한으로 조회)
# ------------------------------------------------------------------
def securityhub():
    return boto3.client("securityhub", region_name=REGION)


def lookback_filter():
    return [{"DateRange": {"Value": SECURITYHUB_LOOKBACK_DAYS, "Unit": "DAYS"}}]


def finding_brief(f):
    return {
        "id": f["Id"],
        "product": f.get("ProductName"),
        "title": f.get("Title"),
        "severity": (f.get("Severity") or {}).get("Label"),
        "types": f.get("Types"),
        "resource": ((f.get("Resources") or [{}])[0]).get("Id"),
        "created_at": f.get("CreatedAt"),
        "updated_at": f.get("UpdatedAt"),
        "workflow_status": (f.get("Workflow") or {}).get("Status"),
    }


def securityhub_search(queries, limit=200):
    sh = securityhub()
    found = {}
    for filters in queries:
        pages = sh.get_paginator("get_findings").paginate(
            Filters=filters,
            PaginationConfig={"MaxItems": limit, "PageSize": 100},
        )
        for page in pages:
            for f in page.get("Findings", []):
                found[f["Id"]] = finding_brief(f)
    return sorted(found.values(), key=lambda x: x.get("created_at") or "", reverse=True)


def securityhub_related(ip):
    queries = [{"Title": [{"Value": ip, "Comparison": "CONTAINS"}], "UpdatedAt": lookback_filter()}]
    if ipaddress.ip_address(ip).version == 4:
        queries.append({"NetworkSourceIpV4": [{"Cidr": f"{ip}/32"}], "UpdatedAt": lookback_filter()})
    findings = securityhub_search(queries)
    return {"ip": ip, "lookback_days": SECURITYHUB_LOOKBACK_DAYS, "count": len(findings), "findings": findings}


def securityhub_by_resource(value):
    findings = securityhub_search([
        {"ResourceId": [{"Value": value, "Comparison": "CONTAINS"}], "UpdatedAt": lookback_filter()}
    ])
    return {
        "resource_contains": value,
        "lookback_days": SECURITYHUB_LOOKBACK_DAYS,
        "count": len(findings),
        "findings": findings,
    }


def fetch_asff(ctx):
    """Security Hub에 저장된 원본 Finding(ASFF). 정규화 과정에서 빠진 필드를 R3·R5가 다시 꺼내 쓴다."""
    if "asff" in ctx:
        return ctx["asff"]
    ctx["asff"] = None
    fid = ctx["finding_id"]
    if not fid or fid == "unknown":
        return None
    items = securityhub().get_findings(
        Filters={"Id": [{"Value": fid, "Comparison": "EQUALS"}]},
        MaxResults=1,
    ).get("Findings", [])
    ctx["asff"] = items[0] if items else None
    return ctx["asff"]


# ------------------------------------------------------------------
# IAM (R3)
# ------------------------------------------------------------------
def iam_user_state(iam, user_name):
    out = {"user": iam.get_user(UserName=user_name)["User"]}

    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    for k in keys:
        try:
            k["LastUsed"] = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed")
        except ClientError as e:
            k["LastUsed"] = {"error": error_code(e)}
    out["access_keys"] = keys

    out["attached_policies"] = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    inline = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    out["inline_policies"] = {
        n: iam.get_user_policy(UserName=user_name, PolicyName=n)["PolicyDocument"] for n in inline
    }
    out["groups"] = [g["GroupName"] for g in iam.list_groups_for_user(UserName=user_name)["Groups"]]
    out["mfa_devices"] = iam.list_mfa_devices(UserName=user_name)["MFADevices"]

    try:
        out["login_profile"] = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    except ClientError as e:
        if error_code(e) != "NoSuchEntity":
            raise
        out["login_profile"] = None  # 콘솔 비밀번호 없음
    return out


def iam_role_state(iam, role_name):
    role = iam.get_role(RoleName=role_name)["Role"]  # 신뢰 정책, RoleLastUsed 포함
    inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    profiles = iam.list_instance_profiles_for_role(RoleName=role_name)["InstanceProfiles"]
    return {
        "role": role,
        "attached_policies": iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        "inline_policies": {
            n: iam.get_role_policy(RoleName=role_name, PolicyName=n)["PolicyDocument"] for n in inline
        },
        "instance_profiles": [{"name": p["InstanceProfileName"], "arn": p["Arn"]} for p in profiles],
    }


def credential_account(ctx, key_details):
    """자격증명 소속 계정. Wazuh·Suricata Finding은 Security 계정으로 송고되므로 account_id를 그대로 믿지 않는다."""
    if key_details.get("AccountId"):
        return key_details["AccountId"]
    asff = ctx.get("asff") or {}
    product = str(ctx["event"].get("product") or asff.get("ProductName") or "").lower()
    if "wazuh" in product or "suricata" in product:
        return WORKLOAD_ACCOUNT_ID
    return asff.get("AwsAccountId") or ctx["event"].get("account_id") or WORKLOAD_ACCOUNT_ID


def credential_identity(ctx):
    """enrich 출력에서 먼저 찾고, 없으면 ASFF 원본의 AwsIamAccessKey 리소스에서 찾는다."""
    event = ctx["event"]
    details = event.get("details") or {}
    asff = ctx.get("asff") or {}

    def pick(*names):
        for n in names:
            v = event.get(n) or details.get(n)
            if v:
                return v
        return None

    ident = {
        "access_key_id": pick("access_key_id", "AccessKeyId"),
        "principal_type": pick("principal_type", "PrincipalType"),
        "user_name": pick("iam_user_name"),
        "role_name": pick("iam_role_name"),
        "session_instance_id": None,
    }

    key_details = {}
    for res in asff.get("Resources") or []:
        d = (res.get("Details") or {}).get("AwsIamAccessKey")
        if d:
            key_details = d
            break

    if key_details:
        ptype = key_details.get("PrincipalType")
        ident["access_key_id"] = ident["access_key_id"] or key_details.get("AccessKeyId")
        ident["principal_type"] = ident["principal_type"] or ptype
        if ptype == "AssumedRole":
            issuer = (key_details.get("SessionContext") or {}).get("SessionIssuer") or {}
            ident["role_name"] = ident["role_name"] or issuer.get("UserName")
            # 인스턴스 역할 자격증명이면 세션 이름이 인스턴스 ID (자격증명 탈취 출처)
            m = INSTANCE_ID_RE.search(json.dumps(key_details, default=str))
            ident["session_instance_id"] = m.group(0) if m else None
        elif ptype == "IAMUser":
            ident["user_name"] = ident["user_name"] or key_details.get("PrincipalName") or key_details.get("UserName")

    if not ident["access_key_id"]:
        text = " ".join([str(event.get("resource_id") or ""), json.dumps(asff.get("Resources") or [], default=str)])
        m = ACCESS_KEY_RE.search(text)
        ident["access_key_id"] = m.group(0) if m else None

    if not ident["principal_type"]:
        if ident["user_name"]:
            ident["principal_type"] = "IAMUser"
        elif ident["role_name"]:
            ident["principal_type"] = "AssumedRole"

    ident["account_id"] = credential_account(ctx, key_details)
    return ident


# ------------------------------------------------------------------
# S3 버킷 (R5)
# ------------------------------------------------------------------
def r5_bucket_name(ctx):
    event = ctx["event"]
    rid = str(event.get("resource_id") or "")
    if rid.startswith("arn:aws:s3:::"):
        return rid.split(":::", 1)[1].split("/", 1)[0]
    if event.get("resource_type") == "AwsS3Bucket" and rid and ":" not in rid:
        return rid
    for res in (ctx.get("asff") or {}).get("Resources") or []:
        rid = str(res.get("Id") or "")
        if res.get("Type") == "AwsS3Bucket" and rid.startswith("arn:aws:s3:::"):
            return rid.split(":::", 1)[1].split("/", 1)[0]
    return None


def s3_bucket_state(session, bucket):
    s3 = session.client("s3", region_name=REGION)
    region = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
    s3 = session.client("s3", region_name=region)

    def strip(resp):
        return {k: v for k, v in resp.items() if k != "ResponseMetadata"}

    calls = {
        "policy": lambda: json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"]),
        "public_access_block": lambda: s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"],
        "acl": lambda: strip(s3.get_bucket_acl(Bucket=bucket)),
        "versioning": lambda: strip(s3.get_bucket_versioning(Bucket=bucket)),
        "logging": lambda: s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"),
        "encryption": lambda: s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"],
    }
    # 설정 자체가 없을 때 나는 오류는 "없음(None)"으로 기록
    not_configured = {
        "NoSuchBucketPolicy",
        "NoSuchPublicAccessBlockConfiguration",
        "ServerSideEncryptionConfigurationNotFoundError",
    }

    out = {"bucket": bucket, "region": region}
    for name, fn in calls.items():
        try:
            out[name] = fn()
        except ClientError as e:
            code = error_code(e)
            out[name] = None if code in not_configured else {"error": code}
    return out


# ------------------------------------------------------------------
# 서비스 영향 (R5)
# ------------------------------------------------------------------
def target_groups_for_instance(elb, instance_id):
    matched = []
    for page in elb.get_paginator("describe_target_groups").paginate():
        for tg in page.get("TargetGroups", []):
            if tg.get("TargetType") != "instance":
                continue
            health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", [])
            if not any((h.get("Target") or {}).get("Id") == instance_id for h in health):
                continue
            matched.append({
                "target_group_name": tg.get("TargetGroupName"),
                "target_group_arn": tg["TargetGroupArn"],
                "load_balancer_arns": tg.get("LoadBalancerArns", []),
                "health_check": {
                    k: tg.get(k) for k in ("HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath")
                },
                "targets": [
                    {
                        "id": (h.get("Target") or {}).get("Id"),
                        "port": (h.get("Target") or {}).get("Port"),
                        "state": (h.get("TargetHealth") or {}).get("State"),
                        "reason": (h.get("TargetHealth") or {}).get("Reason"),
                        "description": (h.get("TargetHealth") or {}).get("Description"),
                    }
                    for h in health
                ],
            })
    return matched


def metric_query(qid, namespace, metric, dims, stat, label=None):
    return {
        "Id": qid,
        "Label": label or metric,
        "MetricStat": {
            "Metric": {
                "Namespace": namespace,
                "MetricName": metric,
                "Dimensions": [{"Name": k, "Value": v} for k, v in dims.items()],
            },
            "Period": METRIC_PERIOD,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def impact_metrics(cw, instance_id, target_groups, start, end):
    dims = {"InstanceId": instance_id}
    queries = [
        metric_query("ec2_net_out", "AWS/EC2", "NetworkOut", dims, "Sum"),
        metric_query("ec2_net_in", "AWS/EC2", "NetworkIn", dims, "Sum"),
        metric_query("ec2_pkts_out", "AWS/EC2", "NetworkPacketsOut", dims, "Sum"),
        metric_query("ec2_cpu", "AWS/EC2", "CPUUtilization", dims, "Average"),
    ]

    seen_lb = []
    for i, tg in enumerate(target_groups):
        tg_dim = tg["target_group_arn"].split(":")[-1]  # targetgroup/name/id
        for j, lb_arn in enumerate(tg.get("load_balancer_arns", [])):
            lb_dim = lb_arn.split(":loadbalancer/")[-1]  # app/name/id
            queries.append(metric_query(
                f"tg{i}_{j}_unhealthy", "AWS/ApplicationELB", "UnHealthyHostCount",
                {"TargetGroup": tg_dim, "LoadBalancer": lb_dim}, "Maximum",
                f"{tg['target_group_name']} UnHealthyHostCount",
            ))
            if lb_dim in seen_lb:
                continue
            seen_lb.append(lb_dim)
            n = len(seen_lb)
            for mid, name, stat in (
                ("requests", "RequestCount", "Sum"),
                ("elb5xx", "HTTPCode_ELB_5XX_Count", "Sum"),
                ("target5xx", "HTTPCode_Target_5XX_Count", "Sum"),
                ("latency", "TargetResponseTime", "Average"),
            ):
                queries.append(metric_query(
                    f"lb{n}_{mid}", "AWS/ApplicationELB", name, {"LoadBalancer": lb_dim}, stat, f"{lb_dim} {name}",
                ))

    series = {}
    pages = cw.get_paginator("get_metric_data").paginate(
        MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )
    for page in pages:
        for r in page.get("MetricDataResults", []):
            s = series.setdefault(r["Id"], {"id": r["Id"], "label": r.get("Label"), "points": []})
            s["status"] = r.get("StatusCode")
            s["points"].extend(zip(r.get("Timestamps", []), r.get("Values", [])))

    out = []
    for s in series.values():
        values = [v for _, v in s["points"]]
        peak = max(s["points"], key=lambda p: p[1]) if s["points"] else None
        out.append(dict(
            s,
            max=peak[1] if peak else None,
            max_at=peak[0] if peak else None,
            avg=(sum(values) / len(values)) if values else None,
        ))
    return {"window": [start, end], "period_seconds": METRIC_PERIOD, "series": out}


# ------------------------------------------------------------------
# SSM / 스냅샷
# ------------------------------------------------------------------
def ssm_collect(ctx, instance_id, script, label):
    """SSM Run Command로 스크립트를 실행하고, 결과는 인스턴스가 증거 버킷 ssm-output/ 아래로 올린다."""
    ssm = ctx["ssm"]
    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    ).get("InstanceInformationList", [])
    if not info or info[0].get("PingStatus") != "Online":
        return {
            "status": "ssm_unavailable",
            "label": label,
            "reason": "SSM 에이전트가 온라인이 아니거나 인스턴스에 SSM용 IAM 역할이 없음",
            "ping_status": info[0].get("PingStatus") if info else None,
        }

    out_prefix = f"ssm-output/{ctx['ev'].rel}/{label}"
    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script], "executionTimeout": ["120"]},
        OutputS3BucketName=BUCKET,
        OutputS3KeyPrefix=out_prefix,
        Comment=f"SOC evidence collection ({label})",
    )["Command"]["CommandId"]

    invocation = None
    deadline = time.time() + SSM_WAIT_SECONDS
    while time.time() < deadline:
        time.sleep(3)
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as e:
            if error_code(e) == "InvocationDoesNotExist":
                continue
            raise
        if invocation["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break

    status = invocation["Status"] if invocation else "Unknown"

    # 인스턴스가 S3에 올린 결과 파일 목록 (업로드 지연 대비 몇 번 재시도)
    s3_keys = []
    for _ in range(5):
        resp = ctx["s3"].list_objects_v2(Bucket=BUCKET, Prefix=f"{out_prefix}/{command_id}/")
        s3_keys = [o["Key"] for o in resp.get("Contents", [])]
        if s3_keys or status != "Success":
            break
        time.sleep(2)

    return {
        "status": status,
        "label": label,
        "command_id": command_id,
        "instance_id": instance_id,
        "s3_output_prefix": f"s3://{BUCKET}/{out_prefix}/{command_id}/",
        "s3_keys": s3_keys,
        "stdout_preview": (invocation or {}).get("StandardOutputContent", "")[:3000],
        "stderr_preview": (invocation or {}).get("StandardErrorContent", "")[:1000],
    }


def register_ssm_outputs(ctx, result, name_prefix):
    ev = ctx["ev"]
    for key in result.get("s3_keys", []):
        parts = key.rsplit("/", 2)
        try:
            ev.register(f"{name_prefix}/{parts[-2]}/{parts[-1]}", key)
        except Exception as exc:  # noqa: BLE001
            ev.errors.append({"step": f"{name_prefix}_register", "error": f"{type(exc).__name__}: {exc}"})


def create_snapshots(ec2, instance, finding_id):
    snapshots = []
    for bdm in instance.get("BlockDeviceMappings", []):
        volume_id = (bdm.get("Ebs") or {}).get("VolumeId")
        if not volume_id:
            continue
        snap = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"SOC evidence {finding_id}"[:255],
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "Purpose", "Value": "soc-evidence"},
                    {"Key": "FindingId", "Value": finding_id[:256]},
                    {"Key": "SourceInstance", "Value": instance["InstanceId"]},
                    {"Key": "DeviceName", "Value": bdm.get("DeviceName", "")},
                ],
            }],
        )
        snapshots.append({
            "device": bdm.get("DeviceName"),
            "volume_id": volume_id,
            "snapshot_id": snap["SnapshotId"],
            "state": snap.get("State"),
            "start_time": snap.get("StartTime"),
        })
    return {"instance_id": instance["InstanceId"], "count": len(snapshots), "snapshots": snapshots}


def capture_host(ctx, inst):
    """격리·원복 같은 파괴적 조치 전에 호스트 상태를 남긴다. 휘발성 정보 → EBS 스냅샷 순서."""
    ev, summary = ctx["ev"], ctx["summary"]

    ssm_result = ev.run("ssm_volatile", lambda: ssm_collect(ctx, inst["InstanceId"], VOLATILE_SCRIPT, "volatile"))
    if ssm_result:
        summary["ssm"] = {
            "status": ssm_result.get("status"),
            "command_id": ssm_result.get("command_id"),
            "output": ssm_result.get("s3_output_prefix"),
        }
        register_ssm_outputs(ctx, ssm_result, "ssm")

    # 스냅샷은 시작만 하고 완료는 기다리지 않음
    snap_result = ev.run("ebs_snapshots", lambda: create_snapshots(ctx["ec2"], inst, ctx["finding_id"]))
    if snap_result:
        summary["snapshots"] = [s["snapshot_id"] for s in snap_result["snapshots"]]


# ------------------------------------------------------------------
# RunBook별 수집
# ------------------------------------------------------------------
def collect_common(ctx):
    ev, inst = ctx["ev"], ctx["instance"]
    ev.put("finding", ctx["event"])
    ev.run("finding_asff", lambda: fetch_asff(ctx) or {"found": False, "finding_id": ctx["finding_id"]})

    if not inst:
        ev.notes.append(f"대상 인스턴스를 찾지 못함 ({ctx['resolve_method']})")
        return

    ev.run("target_instance", lambda: inst)

    sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    if sg_ids:
        ev.run("security_groups", lambda: ctx["ec2"].describe_security_groups(GroupIds=sg_ids)["SecurityGroups"])

    ev.run("cloudtrail_instance", lambda: cloudtrail_by_resource(
        ctx["ct"], inst["InstanceId"], ctx["start"], ctx["end"]))


def collect_r2(ctx):
    ev = ctx["ev"]
    ip = valid_ip(ctx["event"].get("source_ip"))
    if not ip:
        ev.notes.append("R2: source_ip가 없거나 형식이 잘못되어 로그 검색을 건너뜀")
        return

    ev.run("waf_logs", lambda: insights(
        ctx["logs"], WAF_LOG_GROUP, WAF_QUERY.format(ip=ip), ctx["start"], ctx["end"]))
    ev.run("flow_logs_source_ip", lambda: insights(
        ctx["logs"], FLOW_LOG_GROUP, FLOW_QUERY.format(ip=ip), ctx["start"], ctx["end"]))
    ev.run("alb_access_logs", lambda: alb_logs(ctx["s3w"], ip, ctx["start"], ctx["end"]))
    ev.run("securityhub_related", lambda: securityhub_related(ip))

    # 내부 IP에서 시작된 정찰·공격이면 출발지 호스트도 조사 대상
    if is_private_ip(ip):
        ev.run("source_instance", lambda: instance_by_ip(ctx["ec2"], ip))


def collect_r3(ctx):
    ev, summary = ctx["ev"], ctx["summary"]
    ident = credential_identity(ctx)
    ev.run("credential_identity", lambda: ident)
    summary["credential"] = {k: v for k, v in ident.items() if v}

    if not any(ident.get(k) for k in ("access_key_id", "user_name", "role_name")):
        ev.notes.append("R3: 액세스 키·IAM 사용자·역할 정보를 찾지 못해 자격증명 수집을 건너뜀")
    elif ident.get("account_id") != WORKLOAD_ACCOUNT_ID:
        ev.notes.append(
            f"R3: 자격증명 소속 계정({ident.get('account_id')})이 Workload 계정이 아니라 IAM·CloudTrail 수집을 건너뜀"
        )
    else:
        collect_credential(ctx, ident)

    # 인스턴스 역할 자격증명이 탈취된 경우, 출처 인스턴스를 대상으로 잡는다
    if not ctx["instance"] and ident.get("session_instance_id"):
        try:
            inst, _ = resolve_target(ctx["ec2"], {"instance_id": ident["session_instance_id"]})
        except Exception as exc:  # noqa: BLE001
            inst = None
            ev.errors.append({"step": "credential_source_instance", "error": f"{type(exc).__name__}: {exc}"})
        if inst:
            ctx["instance"], ctx["resolve_method"] = inst, "role_session_name"
            ev.run("target_instance", lambda: inst)

    collect_host_auth(ctx)


def collect_credential(ctx, ident):
    ev, session, summary = ctx["ev"], ctx["session"], ctx["summary"]
    start = ctx["start"] - dt.timedelta(hours=CLOUDTRAIL_LOOKBACK_HOURS)
    end = ctx["end"]

    def trail(name, attr_key, value):
        result = ev.run(name, lambda: cloudtrail_lookup(session, attr_key, value, start, end, CLOUDTRAIL_REGIONS))
        if result and result.get("region_errors"):
            ev.errors.append({"step": name, "error": f"일부 리전 조회 실패: {result['region_errors']}"})
        return result

    key = ident.get("access_key_id")
    if key:
        result = trail("cloudtrail_access_key", "AccessKeyId", key)
        if result:
            s = result["summary"]
            summary["credential_activity"] = {
                "total": s["total"],
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
                "top_source_ips": s["source_ips"][:5],
                "sensitive_event_count": s["sensitive_event_count"],
            }
        ev.run("securityhub_related_key", lambda: securityhub_by_resource(key))

    iam = session.client("iam")
    if ident.get("principal_type") == "Root":
        ev.notes.append("R3: 루트 자격증명이라 IAM 상태 조회를 건너뜀")
    elif ident.get("user_name"):
        # 사용자 기준 조회는 공격자가 새로 만든 키·콘솔 로그인까지 잡아낸다
        trail("cloudtrail_user", "Username", ident["user_name"])
        ev.run("iam_user_state", lambda: iam_user_state(iam, ident["user_name"]))

    if ident.get("role_name"):
        ev.run("iam_role_state", lambda: iam_role_state(iam, ident["role_name"]))


def collect_host_auth(ctx):
    ev, inst, summary = ctx["ev"], ctx["instance"], ctx["summary"]
    ip = valid_ip(ctx["event"].get("source_ip"))
    if ip:
        ev.run("securityhub_related", lambda: securityhub_related(ip))

    if not inst:
        return

    if ip:
        ev.run("flow_logs_source_ip", lambda: insights(
            ctx["logs"], FLOW_LOG_GROUP, FLOW_QUERY.format(ip=ip), ctx["start"], ctx["end"]))

    if not ir_enabled(inst):
        ev.notes.append(f"R3: {IR_TAG_KEY}={IR_TAG_VALUE} 태그가 없어 SSM 인증 정보 수집을 건너뜀")
        return

    result = ev.run("ssm_auth", lambda: ssm_collect(ctx, inst["InstanceId"], AUTH_SCRIPT, "auth"))
    if result:
        summary["ssm_auth"] = {
            "status": result.get("status"),
            "command_id": result.get("command_id"),
            "output": result.get("s3_output_prefix"),
        }
        register_ssm_outputs(ctx, result, "ssm_auth")


def collect_r4(ctx):
    ev, inst, summary = ctx["ev"], ctx["instance"], ctx["summary"]
    if not inst:
        ev.notes.append("R4: 대상 인스턴스가 없어 스냅샷/SSM 수집을 건너뜀")
        return

    private_ip = inst.get("PrivateIpAddress")
    if private_ip:
        ev.run("flow_logs_instance", lambda: insights(
            ctx["logs"], FLOW_LOG_GROUP, FLOW_QUERY.format(ip=private_ip), ctx["start"], ctx["end"]))

    if not ir_enabled(inst):
        ev.notes.append(f"R4: {IR_TAG_KEY}={IR_TAG_VALUE} 태그가 없어 스냅샷/SSM 수집을 건너뜀")
        summary["r4_actions"] = "skipped"
        return

    capture_host(ctx, inst)
    summary["r4_actions"] = "done"


def collect_r5(ctx):
    ev, inst, event, summary = ctx["ev"], ctx["instance"], ctx["event"], ctx["summary"]
    bucket = r5_bucket_name(ctx)

    # 데이터가 나간 곳(원격 IP). 없으면 외부 source_ip를 대신 사용
    remote_ip = valid_ip(event.get("remote_ip"))
    if not remote_ip:
        src = valid_ip(event.get("source_ip"))
        remote_ip = src if src and not is_private_ip(src) else None

    if inst:
        collect_r5_instance(ctx, inst, remote_ip)
    if bucket:
        collect_r5_bucket(ctx, bucket)
    if not inst and not bucket:
        ev.notes.append("R5: 대상 인스턴스나 S3 버킷을 찾지 못해 영향 범위 수집을 건너뜀")

    summary["r5_targets"] = {
        "instance_id": inst.get("InstanceId") if inst else None,
        "bucket": bucket,
        "remote_ip": remote_ip,
    }


def collect_r5_instance(ctx, inst, remote_ip):
    ev, summary = ctx["ev"], ctx["summary"]

    # 1) 원복·복구 전에 호스트 상태부터 확보 (어떤 프로세스가 데이터를 보내는지 등)
    if ir_enabled(inst):
        capture_host(ctx, inst)
        summary["r5_actions"] = "done"
    else:
        ev.notes.append(f"R5: {IR_TAG_KEY}={IR_TAG_VALUE} 태그가 없어 스냅샷/SSM 수집을 건너뜀")
        summary["r5_actions"] = "skipped"

    # 2) 트래픽 규모 (유출량·DoS 규모)
    private_ip = inst.get("PrivateIpAddress")
    if private_ip:
        ev.run("flow_out_top_destinations", lambda: insights(
            ctx["logs"], FLOW_LOG_GROUP, FLOW_OUT_QUERY.format(ip=private_ip), ctx["start"], ctx["end"], limit=100))
        ev.run("flow_in_top_sources", lambda: insights(
            ctx["logs"], FLOW_LOG_GROUP, FLOW_IN_QUERY.format(ip=private_ip), ctx["start"], ctx["end"], limit=100))
    if remote_ip:
        ev.run("flow_logs_remote_ip", lambda: insights(
            ctx["logs"], FLOW_LOG_GROUP, FLOW_QUERY.format(ip=remote_ip), ctx["start"], ctx["end"]))

    # 3) 서비스 영향 (대상 그룹 상태, 지표)
    session = ctx["session"]
    tgs = ev.run("target_group_health", lambda: target_groups_for_instance(
        session.client("elbv2"), inst["InstanceId"]))
    metric_start = ctx["start"] - dt.timedelta(hours=METRIC_BASELINE_HOURS)
    ev.run("cloudwatch_metrics", lambda: impact_metrics(
        session.client("cloudwatch"), inst["InstanceId"], tgs or [], metric_start, ctx["end"]))


def collect_r5_bucket(ctx, bucket):
    ev, session = ctx["ev"], ctx["session"]

    state = ev.run("s3_bucket_state", lambda: s3_bucket_state(session, bucket))
    region = (state or {}).get("region") or REGION

    start = ctx["start"] - dt.timedelta(hours=CLOUDTRAIL_LOOKBACK_HOURS)
    result = ev.run("cloudtrail_bucket", lambda: cloudtrail_lookup(
        session, "ResourceName", bucket, start, ctx["end"], [region]))
    if result and result.get("region_errors"):
        ev.errors.append({"step": "cloudtrail_bucket", "error": f"조회 실패: {result['region_errors']}"})

    ev.notes.append(
        "R5: CloudTrail 이벤트 기록에는 S3 객체 단위 이벤트(GetObject·DeleteObject 등)가 없음. "
        "다운로드·삭제 내역은 Org Trail에 S3 데이터 이벤트가 켜져 있다면 중앙 로그 버킷에서 확인"
    )
    ev.run("securityhub_related_bucket", lambda: securityhub_by_resource(bucket))


STEPS = {
    "common": collect_common,
    "r2": collect_r2,
    "r3": collect_r3,
    "r4": collect_r4,
    "r5": collect_r5,
}


# ------------------------------------------------------------------
# Handler
# ------------------------------------------------------------------
def lambda_handler(event, context):
    runbook = event.get("runbook_id") or "R7"
    finding_id = event.get("finding_id") or event.get("event_id") or "unknown"
    start, end = time_window(event)

    s3 = boto3.client("s3", region_name=REGION)
    ev = Evidence(s3, finding_id, runbook)
    summary = {}

    ctx = {
        "event": event,
        "finding_id": finding_id,
        "runbook": runbook,
        "start": start,
        "end": end,
        "ev": ev,
        "s3": s3,
        "summary": summary,
        "session": None,
        "instance": None,
        "resolve_method": "not_attempted",
    }

    try:
        session = workload_session()
        ctx["session"] = session
        ctx.update({
            "ec2": session.client("ec2"),
            "ct": session.client("cloudtrail"),
            "ssm": session.client("ssm"),
            "logs": session.client("logs"),
            "s3w": session.client("s3"),
        })
        try:
            ctx["instance"], ctx["resolve_method"] = resolve_target(ctx["ec2"], event)
        except Exception as exc:  # noqa: BLE001
            ev.errors.append({"step": "resolve_target", "error": f"{type(exc).__name__}: {exc}"})
    except Exception as exc:  # noqa: BLE001
        ev.errors.append({"step": "assume_role", "error": f"{type(exc).__name__}: {exc}"})

    steps = PROFILES.get(runbook, ["common"])
    for step in steps:
        if step != "common" and ctx["session"] is None:
            continue
        try:
            STEPS[step](ctx)
        except Exception as exc:  # noqa: BLE001
            ev.errors.append({"step": step, "error": f"{type(exc).__name__}: {exc}"})

    inst = ctx["instance"] or {}
    manifest_key = ev.write_manifest({
        "finding_id": finding_id,
        "runbook_id": runbook,
        "collected_at": utcnow(),
        "window": [start, end],
        "target_instance_id": inst.get("InstanceId"),
        "target_resolved_by": ctx["resolve_method"],
        "profile": steps,
        "summary": summary,
    })

    evidence = {
        "status": "complete" if not ev.errors else "partial",
        "location": f"s3://{BUCKET}/{ev.prefix}/",
        "manifest": f"s3://{BUCKET}/{manifest_key}",
        "target_instance_id": inst.get("InstanceId"),
        "items": [i["name"] for i in ev.items],
        "errors": ev.errors,
        "notes": ev.notes,
        **summary,
    }
    return to_json_safe(dict(event, evidence=evidence))