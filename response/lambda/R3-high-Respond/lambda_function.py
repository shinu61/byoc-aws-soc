"""R3 HIGH 대응 Lambda (승인 후 실행)

흐름: enrich → R3 분류 → 증거 수집 → king_all 승인 요청(waitForTaskToken)
      → [세션 무효화 승인] 클릭 → 이 Lambda → 결과 검증

조치 (king_all R3 승인 버튼 문구와 동일)
  - 영구 Access Key(AKIA)            → 해당 키 비활성화 (Inactive)
  - 역할 임시 자격증명(ASIA, AssumedRole) → 역할에 aws:TokenIssueTime Deny 인라인 정책 부착
  - 사용자 임시 자격증명(ASIA, IAMUser)    → 사용자에 같은 Deny 인라인 정책 부착

되돌리기
  - 키: update-access-key --status Active
  - 세션: 역할/사용자에서 인라인 정책 SOC-R3-RevokeOlderSessions 삭제

환경 변수
  RESPONDER_ROLE_NAME    Workload 계정의 대응 역할 이름 (기본 soc-r3-responder)
  RESPONDER_EXTERNAL_ID  AssumeRole ExternalId (선택)
  ALLOWED_ACCOUNT_IDS    조치 허용 계정, 쉼표 구분 (기본 059865587057)
  PROTECTED_PRINCIPALS   절대 조치하지 않을 역할/사용자 이름, 쉼표 구분 (선택)
  REVOKE_POLICY_NAME     무효화 인라인 정책 이름 (기본 SOC-R3-RevokeOlderSessions)
  DRY_RUN                true 면 IAM 변경 없이 계획만 반환
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
POLICY_NAME = os.environ.get("REVOKE_POLICY_NAME", "SOC-R3-RevokeOlderSessions")

NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")

APPROVE_DECISIONS = {"approve", "approved"}
SKIP_DECISIONS = {"allowed_activity", "false_positive", "reject", "rejected", "deny", "denied"}

# 이 이름(또는 접두사)은 자동 조치 대상에서 제외 → 사람이 직접 판단
PROTECTED_PREFIXES = ("AWSServiceRole", "AWSReservedSSO_", "soc-")
BUILTIN_PROTECTED = {"OrganizationAccountAccessRole"}


class R3InputError(Exception):
    """입력이 R3 조치 조건에 맞지 않음 (재시도 무의미)."""


class R3ProtectedPrincipal(Exception):
    """보호 대상 주체 → 자동 조치 금지, 수동 처리."""


# ---------------------------------------------------------------- 설정

def _allowed_accounts():
    raw = os.environ.get("ALLOWED_ACCOUNT_IDS", "059865587057")
    return {a.strip() for a in raw.split(",") if a.strip()}


def _protected_names():
    raw = os.environ.get("PROTECTED_PRINCIPALS", "")
    names = {n.strip() for n in raw.split(",") if n.strip()}
    return names | BUILTIN_PROTECTED | {RESPONDER_ROLE_NAME}


def _dry_run(event):
    if os.environ.get("DRY_RUN", "false").strip().lower() == "true":
        return True
    # king_all 과 같은 규칙: sample=true 테스트 Finding 은 실제 조치하지 않음
    return event.get("dry_run") is True or event.get("sample") is True


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- 입력 해석

def _decision(event):
    """Interaction Lambda 가 SendTaskSuccess 로 넘긴 승인 결과.
    ResultPath "$.approval" 로 받는 것을 기본으로, 최상위 decision 도 허용."""
    approval = event.get("approval") if isinstance(event.get("approval"), dict) else {}
    for source in (approval, event):
        for key in ("decision", "action_id", "custom_id_action"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower(), approval
    return None, approval


def _plan(event):
    """누구에게 어떤 조치를 할지 결정. 애매하면 R3InputError."""
    if event.get("runbook_id") != "R3":
        raise R3InputError(f"runbook_id must be R3 (got {event.get('runbook_id')!r})")
    if event.get("resource_type") != "AwsIamAccessKey":
        raise R3InputError(f"resource_type must be AwsIamAccessKey (got {event.get('resource_type')!r})")

    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    account = str(details.get("resource_account_id") or details.get("principal_account_id")
                  or event.get("account_id") or "").strip()
    if not ACCOUNT_RE.match(account):
        raise R3InputError(f"target account id missing or invalid: {account!r}")
    if account not in _allowed_accounts():
        raise R3InputError(f"account {account} is not in ALLOWED_ACCOUNT_IDS")

    key_id = event.get("access_key_id")
    key_id = key_id.strip() if isinstance(key_id, str) and key_id.strip() else None
    if key_id and not KEY_RE.match(key_id):
        raise R3InputError(f"access_key_id has unexpected format: {key_id!r}")

    principal_type = str(event.get("principal_type") or "").strip()
    role = next((event.get(k).strip() for k in ("role_name", "iam_role_name")
                 if isinstance(event.get(k), str) and event.get(k).strip()), None)
    user = event.get("user_name").strip() if isinstance(event.get("user_name"), str) and event.get("user_name").strip() else None

    if key_id and key_id.startswith("AKIA"):
        action, kind, name = "deactivate_access_key", "user", user  # user 없으면 조회로 보충
    elif role and principal_type in ("AssumedRole", "Role", ""):
        action, kind, name = "revoke_role_sessions", "role", role
    elif user and principal_type == "IAMUser":
        action, kind, name = "revoke_user_sessions", "user", user
    else:
        raise R3InputError(
            f"cannot decide R3 action (principal_type={principal_type!r}, role={role!r}, "
            f"user={user!r}, key={key_id!r})")

    if name is not None:
        if not NAME_RE.match(name):
            raise R3InputError(f"principal name has unexpected format: {name!r}")
        _check_protected(name)

    return {
        "action": action,
        "account_id": account,
        "principal_kind": kind,
        "principal_name": name,
        "principal_type": principal_type or None,
        "access_key_id": key_id,
        "region": event.get("region"),
    }


def _check_protected(name):
    if name in _protected_names() or name.startswith(PROTECTED_PREFIXES):
        raise R3ProtectedPrincipal(f"{name} is protected; handle manually")


# ---------------------------------------------------------------- AWS

def _iam_client(account_id, finding_id):
    sts = boto3.client("sts")
    if sts.get_caller_identity()["Account"] == account_id:
        return boto3.client("iam")
    params = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{RESPONDER_ROLE_NAME}",
        "RoleSessionName": f"soc-r3-{uuid.uuid5(uuid.NAMESPACE_URL, str(finding_id)).hex[:12]}",
        "DurationSeconds": 900,
    }
    if EXTERNAL_ID:
        params["ExternalId"] = EXTERNAL_ID
    creds = sts.assume_role(**params)["Credentials"]
    return boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _revoke_document(revoke_before):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "SocR3RevokeOlderSessions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": revoke_before}},
        }],
    }


def _policy_time(document):
    if isinstance(document, str):
        document = json.loads(document)
    for stmt in document.get("Statement", []):
        value = (stmt.get("Condition", {}).get("DateLessThan", {}) or {}).get("aws:TokenIssueTime")
        if value:
            return value
    return None


def _revoke_sessions(iam, kind, name, revoke_before):
    doc = json.dumps(_revoke_document(revoke_before))
    if kind == "role":
        iam.put_role_policy(RoleName=name, PolicyName=POLICY_NAME, PolicyDocument=doc)
        stored = iam.get_role_policy(RoleName=name, PolicyName=POLICY_NAME)["PolicyDocument"]
        rollback = f"aws iam delete-role-policy --role-name {name} --policy-name {POLICY_NAME}"
    else:
        iam.put_user_policy(UserName=name, PolicyName=POLICY_NAME, PolicyDocument=doc)
        stored = iam.get_user_policy(UserName=name, PolicyName=POLICY_NAME)["PolicyDocument"]
        rollback = f"aws iam delete-user-policy --user-name {name} --policy-name {POLICY_NAME}"
    verified = _policy_time(stored) == revoke_before
    return {"verified": verified, "policy_name": POLICY_NAME, "rollback": rollback}


def _deactivate_key(iam, user, key_id):
    if not user:
        # 입력에 user_name 이 없으면 키 소유자를 조회
        user = iam.get_access_key_last_used(AccessKeyId=key_id).get("UserName")
        if not user or not NAME_RE.match(user):
            raise R3InputError(f"cannot resolve owner of {key_id}")
        _check_protected(user)

    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    current = next((k for k in keys if k["AccessKeyId"] == key_id), None)
    if current is None:
        raise R3InputError(f"{key_id} does not belong to user {user}")

    before = current["Status"]
    if before != "Inactive":
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    after = next(k["Status"] for k in keys if k["AccessKeyId"] == key_id)
    return {
        "principal_name": user,
        "status_before": before,
        "status_after": after,
        "verified": after == "Inactive",
        "rollback": f"aws iam update-access-key --user-name {user} --access-key-id {key_id} --status Active",
    }


# ---------------------------------------------------------------- 핸들러

def lambda_handler(event, context):
    if not isinstance(event, dict):
        raise R3InputError("event must be an object")

    finding_id = event.get("finding_id")
    decision, approval = _decision(event)
    base = {
        "runbook_id": "R3",
        "severity": event.get("severity"),
        "finding_id": finding_id,
        "decision": decision,
        "decided_by": approval.get("approved_by") or approval.get("user") or approval.get("username"),
    }

    if decision not in APPROVE_DECISIONS:
        # 정상 행위 / 오탐 / 결정 없음 → 아무 조치도 하지 않음
        reason = "not_approved" if decision in SKIP_DECISIONS else "no_approval_decision"
        LOG.info(json.dumps({**base, "status": "skipped", "reason": reason}, ensure_ascii=False))
        return {**base, "status": "skipped", "reason": reason, "changed": False}

    plan = _plan(event)
    now = _now()
    revoke_before = _iso(now)
    result = {**base, **plan, "executed_at": revoke_before}

    if _dry_run(event):
        result.update(status="dry_run", changed=False,
                      note="DRY_RUN 또는 sample=true → IAM 변경 없음")
        if plan["action"] != "deactivate_access_key":
            result["would_attach_policy"] = _revoke_document(revoke_before)
        LOG.info(json.dumps(result, ensure_ascii=False))
        return result

    iam = _iam_client(plan["account_id"], finding_id)

    if plan["action"] == "deactivate_access_key":
        outcome = _deactivate_key(iam, plan["principal_name"], plan["access_key_id"])
        result["principal_name"] = outcome.pop("principal_name")
        result["changed"] = outcome["status_before"] != "Inactive"
    else:
        outcome = _revoke_sessions(iam, plan["principal_kind"], plan["principal_name"], revoke_before)
        outcome["revoke_before"] = revoke_before
        result["changed"] = True

    result.update(outcome)
    result["status"] = "completed" if outcome["verified"] else "verify_failed"
    LOG.info(json.dumps(result, ensure_ascii=False))
    if not outcome["verified"]:
        # Step Functions Catch 로 수동 확인 경로에 보내기 위해 실패 처리
        raise RuntimeError(f"R3 response not verified: {json.dumps(result, ensure_ascii=False)}")
    return result