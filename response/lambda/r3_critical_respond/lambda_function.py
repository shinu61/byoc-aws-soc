"""R3 CRITICAL 대응 Lambda (승인 후 강제 격리)

흐름
  R3 CRITICAL 승인 요청 Lambda (Discord 버튼) → [강제 격리 승인] → 증거 수집 → 이 Lambda

HIGH(r3_high_response)와 다른 점: 세션 무효화에 더해 주체 자체를 격리한다.
  1. 영구 Access Key(AKIA)                → 키 비활성화 (Inactive)
  2. 대상 역할/사용자 기존 세션 무효화     → 인라인 SOC-R3-RevokeOlderSessions (aws:TokenIssueTime 이전 Deny)
  3. 대상 역할/사용자 격리                 → 인라인 SOC-R3-Quarantine (Deny * on *, 새 세션도 전부 차단)
  4. 권한 상승으로 생성된 Lambda (성공 시) → 예약 동시성 0 (함수 삭제 없이 실행 중지)
  5. PassRole 로 전달된 역할              → 기존 세션 무효화 (생성된 함수가 이미 받은 자격증명 차단)
  모든 조치는 되돌릴 수 있고, 결과에 원복 명령을 담는다.
  자격증명 발급 EC2 는 건드리지 않는다 (필요하면 R4 격리).

입력: 정규화 Finding + 승인 결과
  - Step Functions 에서 ResultPath "$.approval" 로 받은 그대로 넘기면 됨 ({..., "approval": {"decision": "APPROVED", ...}})
  - 또는 최상위 decision 도 읽는다

환경변수
  RESPONDER_ROLE_NAME    Workload 계정 대응 역할 (기본 soc-r3-responder)
  RESPONDER_EXTERNAL_ID  AssumeRole ExternalId (선택)
  ALLOWED_ACCOUNT_IDS    조치 허용 계정, 쉼표 구분 (기본 059865587057)
  PROTECTED_PRINCIPALS   절대 조치하지 않을 역할/사용자 이름, 쉼표 구분 (선택)
  DRY_RUN                true 면 IAM/Lambda 변경 없이 계획만 반환
"""

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

RESPONDER_ROLE_NAME = os.environ.get("RESPONDER_ROLE_NAME", "soc-r3-responder")
EXTERNAL_ID = os.environ.get("RESPONDER_EXTERNAL_ID") or None
REVOKE_POLICY = "SOC-R3-RevokeOlderSessions"
QUARANTINE_POLICY = "SOC-R3-Quarantine"

NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
FUNCTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")

APPROVE = {"approve", "approved"}
SKIP = {"allowed_activity", "false_positive", "reject", "rejected", "deny", "denied"}
PROTECTED_PREFIXES = ("AWSServiceRole", "AWSReservedSSO_", "soc-")
BUILTIN_PROTECTED = {"OrganizationAccountAccessRole"}


class R3InputError(Exception):
    """입력이 R3 CRITICAL 조치 조건에 맞지 않음 (재시도 무의미)."""


class R3ProtectedPrincipal(Exception):
    """보호 대상 주체 → 자동 조치 금지, 수동 처리."""


class R3PartialFailure(Exception):
    """일부 조치 실패. 메시지에 완료/실패 단계와 원복 명령(JSON)이 들어 있다."""


# ---- 입력 해석 -------------------------------------------------------------------
def _env_set(name, default=""):
    return {v.strip() for v in os.environ.get(name, default).split(",") if v.strip()}


def _dry_run(event):
    return os.environ.get("DRY_RUN", "").strip().lower() == "true" or event.get("sample") is True


def _decision(event):
    approval = event.get("approval") if isinstance(event.get("approval"), dict) else {}
    value = approval.get("decision") or event.get("decision")
    by = approval.get("approver_user_id") or event.get("approver_user_id") or event.get("decided_by")
    return (str(value).strip().lower() if value else None), (str(by) if by else None)


def _is_protected(name):
    if not name:
        return True
    return (name in BUILTIN_PROTECTED or name == RESPONDER_ROLE_NAME
            or name in _env_set("PROTECTED_PRINCIPALS")
            or any(name.startswith(p) for p in PROTECTED_PREFIXES))


def _request(event):
    """CloudTrail requestParameters (정규화 필드 → description '요청 {...}' 순)."""
    raw = event.get("request_parameters")
    if isinstance(raw, dict):
        return raw
    text = raw if isinstance(raw, str) else None
    if text is None:
        description = str(event.get("description") or "")
        index = description.find("요청 {")
        text = description[index + 3:] if index >= 0 else None
    if not text:
        return {}
    try:
        parsed, _ = json.JSONDecoder().raw_decode(text.strip())
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
    found = {}
    for key in ("functionName", "role"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', text)
        if match:
            found[key] = match.group(1)
    return found


def _succeeded(event):
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    if event.get("error_code") or details.get("error_code"):
        return False
    return bool(re.search(r"결과\s*성공", str(event.get("description") or "")))


def build_plan(event):
    if event.get("runbook_id") != "R3" or event.get("severity") != "CRITICAL":
        raise R3InputError("This function handles only CRITICAL R3 findings")
    if event.get("resource_type") != "AwsIamAccessKey":
        raise R3InputError("resource_type must be AwsIamAccessKey")

    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    account = details.get("resource_account_id") or details.get("principal_account_id")
    if not isinstance(account, str) or not ACCOUNT_RE.match(account):
        raise R3InputError("details.resource_account_id is required")
    allowed = _env_set("ALLOWED_ACCOUNT_IDS", "059865587057")
    if account not in allowed:
        raise R3InputError(f"Account {account} is not in ALLOWED_ACCOUNT_IDS")
    region = event.get("region") if REGION_RE.match(str(event.get("region") or "")) else "ap-northeast-2"

    principal_type = event.get("principal_type")
    if principal_type == "Root":
        raise R3ProtectedPrincipal("Root principal cannot be handled automatically")
    if event.get("role_name") and principal_type in (None, "AssumedRole", "Role"):
        kind, name = "role", event["role_name"]
    elif event.get("user_name"):
        kind, name = "user", event["user_name"]
    elif event.get("role_name"):
        kind, name = "role", event["role_name"]
    else:
        raise R3InputError("role_name or user_name is required")
    if not NAME_RE.match(str(name)):
        raise R3InputError("Invalid principal name")
    if _is_protected(name):
        raise R3ProtectedPrincipal(f"Protected principal: {name}")

    key = event.get("access_key_id")
    if key is not None and not KEY_RE.match(str(key)):
        raise R3InputError("Invalid access_key_id")

    steps = []
    if isinstance(key, str) and key.startswith("AKIA"):
        steps.append({"action": "deactivate_access_key", "access_key_id": key, "user_name": None})
    steps.append({"action": "revoke_sessions", "kind": kind, "name": name})
    steps.append({"action": "quarantine", "kind": kind, "name": name})

    params = _request(event)
    function_name = params.get("functionName")
    if isinstance(function_name, str) and ":function:" in function_name:
        function_name = function_name.split(":function:", 1)[1].split(":", 1)[0]
    if _succeeded(event) and isinstance(function_name, str) and FUNCTION_RE.match(function_name):
        steps.append({"action": "stop_function", "function_name": function_name, "region": region})

    passed_role = params.get("role")
    if isinstance(passed_role, str) and ":role/" in passed_role:
        role_account = passed_role.split(":")[4] if passed_role.count(":") >= 5 else None
        passed_name = passed_role.rsplit("/", 1)[-1]
        if (role_account == account and passed_name != name and NAME_RE.match(passed_name)
                and not _is_protected(passed_name)):
            steps.append({"action": "revoke_sessions", "kind": "role", "name": passed_name,
                          "reason": "passed_role"})

    return {"account_id": account, "region": region, "principal_kind": kind, "principal_name": name,
            "principal_type": principal_type, "access_key_id": key,
            "credential_instance_id": event.get("credential_instance_id") or details.get("credential_instance_id"),
            "steps": steps}


# ---- 정책 문서 -------------------------------------------------------------------
def revoke_document(cutoff):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "SocR3RevokeOlderSessions", "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}}]}


def quarantine_document():
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "SocR3Quarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}]}


# ---- AWS 클라이언트 --------------------------------------------------------------
def _session(account, finding_id):
    sts = boto3.client("sts")
    params = {"RoleArn": f"arn:aws:iam::{account}:role/{RESPONDER_ROLE_NAME}",
              "RoleSessionName": f"soc-r3-critical-{uuid.uuid4().hex[:12]}", "DurationSeconds": 900}
    if EXTERNAL_ID:
        params["ExternalId"] = EXTERNAL_ID
    creds = sts.assume_role(**params)["Credentials"]
    LOG.info(json.dumps({"assumed": params["RoleArn"], "finding_id": finding_id}))
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                         aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"])


def _clients(account, region, finding_id):
    session = _session(account, finding_id)
    return session.client("iam"), session.client("lambda", region_name=region)


# ---- 조치 ------------------------------------------------------------------------
def _put_policy(iam, kind, name, policy_name, document):
    body = json.dumps(document)
    if kind == "role":
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=body)
        got = iam.get_role_policy(RoleName=name, PolicyName=policy_name)["PolicyDocument"]
    else:
        iam.put_user_policy(UserName=name, PolicyName=policy_name, PolicyDocument=body)
        got = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
    if isinstance(got, str):
        from urllib.parse import unquote
        got = json.loads(unquote(got))
    if got != document:
        raise RuntimeError(f"{policy_name} verification failed on {kind} {name}")


def _rollback_policy(kind, name, policy_name):
    if kind == "role":
        return f"aws iam delete-role-policy --role-name {name} --policy-name {policy_name}"
    return f"aws iam delete-user-policy --user-name {name} --policy-name {policy_name}"


def _key_owner(iam, key):
    owner = iam.get_access_key_last_used(AccessKeyId=key).get("UserName")
    if not owner or not NAME_RE.match(owner):
        raise RuntimeError("Cannot resolve access key owner")
    if _is_protected(owner):
        raise R3ProtectedPrincipal(f"Protected key owner: {owner}")
    return owner


def run_step(step, iam, lam, cutoff):
    action = step["action"]
    if action == "deactivate_access_key":
        owner = _key_owner(iam, step["access_key_id"])
        iam.update_access_key(UserName=owner, AccessKeyId=step["access_key_id"], Status="Inactive")
        keys = iam.list_access_keys(UserName=owner)["AccessKeyMetadata"]
        if not any(k["AccessKeyId"] == step["access_key_id"] and k["Status"] == "Inactive" for k in keys):
            raise RuntimeError("Access key deactivation verification failed")
        return {"user_name": owner,
                "rollback": f"aws iam update-access-key --user-name {owner} "
                            f"--access-key-id {step['access_key_id']} --status Active"}
    if action == "revoke_sessions":
        _put_policy(iam, step["kind"], step["name"], REVOKE_POLICY, revoke_document(cutoff))
        return {"policy_name": REVOKE_POLICY, "revoke_before": cutoff,
                "rollback": _rollback_policy(step["kind"], step["name"], REVOKE_POLICY)}
    if action == "quarantine":
        _put_policy(iam, step["kind"], step["name"], QUARANTINE_POLICY, quarantine_document())
        return {"policy_name": QUARANTINE_POLICY,
                "rollback": _rollback_policy(step["kind"], step["name"], QUARANTINE_POLICY)}
    if action == "stop_function":
        name = step["function_name"]
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
        got = lam.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
        if got != 0:
            raise RuntimeError("Function concurrency verification failed")
        return {"rollback": f"aws lambda delete-function-concurrency --function-name {name} "
                            f"--region {step['region']}"}
    raise R3InputError(f"Unknown action {action}")


def _describe(step):
    a = step["action"]
    if a == "deactivate_access_key":
        return f"Access Key {step['access_key_id']} 비활성화"
    if a == "revoke_sessions":
        who = "전달된 역할" if step.get("reason") == "passed_role" else step["kind"]
        return f"{who} {step['name']} 기존 세션 무효화 ({REVOKE_POLICY})"
    if a == "quarantine":
        return f"{step['kind']} {step['name']} 전체 차단 ({QUARANTINE_POLICY})"
    if a == "stop_function":
        return f"Lambda {step['function_name']} 동시성 0"
    return a


# ---- 진입점 ---------------------------------------------------------------------
def lambda_handler(event, context):
    if not isinstance(event, dict):
        raise R3InputError("Input must be an object")
    decision, decided_by = _decision(event)
    base = {"runbook_id": "R3", "severity": "CRITICAL", "finding_id": event.get("finding_id"),
            "decision": decision, "decided_by": decided_by}

    if decision not in APPROVE:
        status = "skipped" if decision in SKIP else "skipped_no_decision"
        return {**base, "status": status, "changed": False}

    plan = build_plan(event)
    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {**base, **{k: v for k, v in plan.items() if k != "steps"}, "executed_at": cutoff}

    if _dry_run(event):
        return {**result, "status": "dry_run", "changed": False,
                "note": "DRY_RUN 또는 sample=true → IAM/Lambda 변경 없음",
                "would_do": [_describe(s) for s in plan["steps"]],
                "would_attach_policies": {REVOKE_POLICY: revoke_document(cutoff),
                                          QUARANTINE_POLICY: quarantine_document()}}

    iam, lam = _clients(plan["account_id"], plan["region"], event.get("finding_id"))
    done, failed = [], []
    for step in plan["steps"]:
        try:
            info = run_step(step, iam, lam, cutoff)
            done.append({"step": _describe(step), **info})
        except R3ProtectedPrincipal:
            raise
        except Exception as exc:                       # 한 단계가 실패해도 나머지 격리는 계속
            LOG.exception("step failed: %s", step)
            failed.append({"step": _describe(step), "error": f"{type(exc).__name__}: {exc}"[:300]})

    result.update(changed=bool(done), verified=not failed, actions=done,
                  rollback=[d["rollback"] for d in done if d.get("rollback")])
    if failed:
        result.update(status="partial_failure", failed=failed)
        LOG.error(json.dumps(result, ensure_ascii=False))
        raise R3PartialFailure(json.dumps(result, ensure_ascii=False)[:30000])
    result["status"] = "completed"
    if plan.get("credential_instance_id"):
        result["follow_up"] = f"자격증명 발급 EC2 {plan['credential_instance_id']} 침해 여부 조사 (필요 시 R4 격리)"
    return result