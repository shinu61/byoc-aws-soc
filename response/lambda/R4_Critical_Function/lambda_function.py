"""R4_Critical_Function: Discord approval for multi-EC2 CRITICAL findings.

AWS Lambda handler: lambda_function.lambda_handler

Entry points:
  1) Step Functions waitForTaskToken:
     {"finding": {normalized ASFF finding}, "taskToken": "...",
      "executionArn": "...", "approvalTimeoutSeconds": 900}
  2) Discord HTTP Interactions endpoint (API Gateway Lambda proxy event):
     {"headers": {...}, "body": "<RAW DISCORD JSON>", "isBase64Encoded": false}
  3) Alternatively, king_all can securely forward a Gateway interaction with
     {"mode":"interaction", "interaction":{...}} using an IAM-authorized
     synchronous Lambda Invoke. DO NOT expose this third entry point publicly.

Environment variables (required):
  R4_APPROVAL_TABLE         DynamoDB table with STRING partition key 'pk'
  DISCORD_BOT_TOKEN         Bot token (prefer a protected secret source)
  DISCORD_CHANNEL_ID       Target Discord channel ID
  APPROVER_USER_IDS        Comma-separated Discord user IDs (or use ROLE_IDS)
  APPROVER_ROLE_IDS        Comma-separated authorized role IDs (or use USER_IDS)
  DISCORD_PUBLIC_KEY       Required for direct Discord HTTP endpoint only

DynamoDB TTL attribute: expires_at (Number, Unix timestamp).
Permissions: dynamodb:GetItem,PutItem,UpdateItem,DeleteItem on table;
             states:SendTaskSuccess on callback executions.
Dependency for Discord HTTP endpoint: cryptography (Ed25519) OR PyNaCl.

No EC2 isolation is performed here. The Step Functions state machine must
validate approval.target_instance_ids and isolate only those IDs.
"""

import base64
import datetime as dt
import json
import logging
import os
import re
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)

DDB = boto3.resource("dynamodb")
SFN = boto3.client("stepfunctions")
EC2_ID_PATTERN = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
FINDING_SUFFIX = "AttackSequence:EC2/CompromisedInstanceGroup"
MAX_OPTIONS = 25
EPHEMERAL = 64


def env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def table():
    return DDB.Table(env("R4_APPROVAL_TABLE"))


def auth_sets():
    users = {s.strip() for s in os.environ.get("APPROVER_USER_IDS", "").split(",") if s.strip()}
    roles = {s.strip() for s in os.environ.get("APPROVER_ROLE_IDS", "").split(",") if s.strip()}
    if not users and not roles:
        raise RuntimeError("Set APPROVER_USER_IDS and/or APPROVER_ROLE_IDS")
    return users, roles


def get_actor(interaction):
    member = interaction.get("member") or {}
    user = member.get("user") or interaction.get("user") or {}
    return str(user.get("id") or ""), set(member.get("roles") or [])


def authorized(interaction):
    allowed_users, allowed_roles = auth_sets()
    user_id, user_roles = get_actor(interaction)
    return bool(user_id and (user_id in allowed_users or user_roles.intersection(allowed_roles)))


def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def candidate_ids(finding):
    candidates = finding.get("instance_ids")
    if not isinstance(candidates, list):
        raise ValueError("instance_ids must be a list from NormalizeFinding")
    if any(not isinstance(x, str) or not EC2_ID_PATTERN.fullmatch(x) for x in candidates):
        raise ValueError("Invalid EC2 instance ID in instance_ids")
    ids = list(dict.fromkeys(candidates))
    if not ids:
        raise ValueError("No EC2 candidates in this finding; manual review required")
    if len(ids) > MAX_OPTIONS:
        raise ValueError(f"{len(ids)} EC2 candidates exceed Discord menu limit of {MAX_OPTIONS}; manual review required")
    return ids


def custom_id(action, approval_id):
    return f"r4c:{action}:{approval_id}"


def components(approval_id, instance_ids, disabled=False, sample=False):
    return [
        {
            "type": 1,
            "components": [{
                "type": 3,
                "custom_id": custom_id("select", approval_id),
                "placeholder": "격리할 EC2를 선택하세요 (다중 선택 가능)",
                "min_values": 1,
                "max_values": len(instance_ids),
                "disabled": disabled,
                "options": [{"label": iid, "value": iid} for iid in instance_ids],
            }],
        },
        {
            "type": 1,
            "components": [
                {"type": 2, "style": 3, "label": "선택 대상 격리 승인", "custom_id": custom_id("approve", approval_id), "disabled": disabled or sample},
                {"type": 2, "style": 2, "label": "정상 행위", "custom_id": custom_id("benign", approval_id), "disabled": disabled},
                {"type": 2, "style": 4, "label": "오탐", "custom_id": custom_id("fp", approval_id), "disabled": disabled},
            ],
        },
    ]


def discord_api(method, route, payload):
    token = env("DISCORD_BOT_TOKEN")
    request = Request(
        url=f"https://discord.com/api/v10{route}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bot {token}", "Content-Type": "application/json", "User-Agent": "SOCing-R4-Critical/1.0"},
        method=method,
    )
    try:
        with urlopen(request, timeout=7) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        # Do not log authorization headers or Discord tokens.
        LOG.error("Discord API failure HTTP %s", exc.code)
        raise RuntimeError(f"Discord API returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("Discord API network error") from exc


def notify(finding, task_token, approval_timeout):
    auth_sets()  # fail closed if no reviewers are configured
    if finding.get("product") != "GuardDuty":
        raise ValueError("R4 CRITICAL expects a GuardDuty finding")
    if finding.get("severity") != "CRITICAL":
        raise ValueError("Only CRITICAL findings are supported")
    if not str(finding.get("finding_type") or "").endswith(FINDING_SUFFIX):
        raise ValueError("This is not the supported R4 EC2 AttackSequence finding")
    if finding.get("record_state") != "ACTIVE" or finding.get("workflow_status") != "NEW":
        raise ValueError("Only ACTIVE / NEW findings can request isolation approval")

    ids = candidate_ids(finding)
    ttl_seconds = max(60, min(int(approval_timeout), 3600))
    approval_id = uuid.uuid4().hex
    expires_at = int(time.time()) + ttl_seconds
    item = {
        "pk": f"approval#{approval_id}",
        "status": "PENDING",
        "task_token": task_token,
        "finding_id": str(finding.get("finding_id") or ""),
        "instance_ids": ids,
        "region": str(finding.get("region") or ""),
        "account_id": str(finding.get("account_id") or ""),
        "sample": bool(finding.get("sample")),
        "expires_at": expires_at,
    }
    table().put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")

    description = (
        "보안 전문가가 아래 EC2 목록에서 격리 대상을 선택한 다음 승인하세요. "
        "선택하지 않은 EC2는 격리하지 않습니다.\n"
        "각 전문가의 선택은 별도로 관리됩니다."
    )
    sample_note = "\n**SAMPLE Finding: 격리 승인 비활성 (실제 격리 금지)**" if item["sample"] else ""
    payload = {
        "content": "[CRITICAL][R4] EC2 AttackSequence 격리 검토",
        "embeds": [{
            "title": "AttackSequence:EC2/CompromisedInstanceGroup",
            "description": description + sample_note,
            "color": 15158332,
            "fields": [
                {"name": "Finding ID", "value": (item["finding_id"] or "정보 없음")[:1024], "inline": False},
                {"name": "EC2 후보", "value": "\n".join(ids)[:1024], "inline": False},
                {"name": "대기 시간", "value": f"{ttl_seconds}초", "inline": True},
            ],
        }],
        "components": components(approval_id, ids, sample=item["sample"]),
        "allowed_mentions": {"parse": []},
    }
    try:
        response = discord_api("POST", f"/channels/{env('DISCORD_CHANNEL_ID')}/messages", payload)
    except Exception:
        table().delete_item(Key={"pk": item["pk"]})
        raise
    LOG.info("R4 CRITICAL approval requested for finding %s, candidates=%d", item["finding_id"], len(ids))
    return {"status": "WAITING", "approval_id": approval_id, "message_id": response.get("id"), "candidate_count": len(ids)}


def selection_key(approval_id, user_id):
    return f"selection#{approval_id}#{user_id}"


def response(text, ephemeral=True):
    return {"type": 4, "data": {"content": text[:2000], "flags": EPHEMERAL if ephemeral else 0}}


def load_pending(approval_id):
    result = table().get_item(Key={"pk": f"approval#{approval_id}"}, ConsistentRead=True)
    item = result.get("Item")
    if not item:
        return None
    if int(item.get("expires_at", 0)) <= int(time.time()):
        return None
    return item


def handle_interaction(interaction):
    if interaction.get("type") == 1:  # Discord PING
        return {"type": 1}
    if interaction.get("type") != 3:  # Message component interaction
        return response("지원되지 않는 상호작용입니다.")
    if not authorized(interaction):
        return response("R4 격리 판정 권한이 없습니다.")

    c_id = str((interaction.get("data") or {}).get("custom_id") or "")
    parts = c_id.split(":", 2)
    if len(parts) != 3 or parts[0] != "r4c" or parts[1] not in ("select", "approve", "benign", "fp"):
        return response("R4 작업이 아닙니다.")
    action, approval_id = parts[1], parts[2]
    if not re.fullmatch(r"[a-f0-9]{32}", approval_id):
        return response("잘못된 승인 식별자입니다.")

    pending = load_pending(approval_id)
    if not pending or pending.get("status") != "PENDING":
        return response("이미 처리되었거나 승인 기한이 종료되었습니다.")
    user_id, _ = get_actor(interaction)
    candidates = pending.get("instance_ids") or []

    if action == "select":
        values = (interaction.get("data") or {}).get("values") or []
        if not values or len(values) != len(set(values)) or not set(values).issubset(set(candidates)):
            return response("EC2 후보 목록에 없는 인스턴스가 포함되었습니다.")
        table().put_item(Item={
            "pk": selection_key(approval_id, user_id),
            "instance_ids": values,
            "expires_at": int(pending["expires_at"]),
        })
        return response("격리 후보 선택 완료: " + ", ".join(values) + "\n실제 격리하려면 '선택 대상 격리 승인'을 누르세요.")

    decision = {"approve": "APPROVED", "benign": "BENIGN", "fp": "FALSE_POSITIVE"}[action]
    selected = []
    if decision == "APPROVED":
        if pending.get("sample"):
            return response("SAMPLE Finding은 실제 격리 승인을 할 수 없습니다.")
        record = table().get_item(Key={"pk": selection_key(approval_id, user_id)}, ConsistentRead=True).get("Item") or {}
        selected = record.get("instance_ids") or []
        if not selected:
            return response("먼저 격리할 EC2를 선택하세요.")
        if len(selected) != len(set(selected)) or not set(selected).issubset(set(candidates)):
            return response("격리 대상 목록이 유효하지 않습니다. 다시 선택하세요.")

    # Only one expert can commit a decision. Condition fails on concurrent clicks.
    try:
        table().update_item(
            Key={"pk": f"approval#{approval_id}"},
            UpdateExpression="SET #st=:processing, decided_by=:user, decided_at=:at",
            ConditionExpression="#st=:pending AND expires_at > :now",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":processing": "PROCESSING", ":pending": "PENDING",
                ":user": user_id, ":at": now_utc(), ":now": int(time.time()),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response("다른 보안 전문가가 먼저 처리했습니다.")
        raise

    result = {
        "decision": decision,
        "target_instance_ids": selected,
        "approved_by": user_id,
        "finding_id": pending.get("finding_id"),
        "decided_at": now_utc(),
        "sample": bool(pending.get("sample")),
    }
    try:
        SFN.send_task_success(taskToken=pending["task_token"], output=json.dumps(result))
    except Exception as exc:
        # Expose only an allowlisted error code to Discord; never show the Task Token,
        # SDK error text, credentials, or raw exception details to users.
        error_code = (exc.response.get("Error", {}).get("Code", "UnknownError")
                      if isinstance(exc, ClientError) else type(exc).__name__)
        public_codes = {
            "AccessDenied", "AccessDeniedException", "InvalidToken",
            "TaskDoesNotExist", "TaskTimedOut", "InvalidOutput",
            "KmsAccessDeniedException", "KmsInvalidStateException",
            "ThrottlingException", "EndpointConnectionError", "ConnectTimeoutError",
            "ReadTimeoutError", "NoCredentialsError", "ValidationException",
        }
        safe_code = error_code if error_code in public_codes else "OtherError"
        # Re-enable a pending request for retry if the callback failed.
        # Task token may already have expired; the deadline check remains in force.
        LOG.exception("R4 CRITICAL callback failed: approval_id=%s", approval_id)
        try:
            table().update_item(
                Key={"pk": f"approval#{approval_id}"},
                UpdateExpression="SET #st=:pending REMOVE decided_by, decided_at",
                ConditionExpression="#st=:processing",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":pending": "PENDING", ":processing": "PROCESSING"},
            )
        except Exception:
            LOG.exception("Failed to unlock R4 approval %s", approval_id)
        return response(f"승인 결과 전송 실패: {safe_code}. Step Functions 실행 상태를 확인하세요.")

    try:
        table().update_item(
            Key={"pk": f"approval#{approval_id}"},
            UpdateExpression="SET #st=:done, #decision=:decision",
            ExpressionAttributeNames={"#st": "status", "#decision": "decision"},
            ExpressionAttributeValues={":done": "DONE", ":decision": decision},
        )
    except Exception:
        LOG.exception("Step Functions callback succeeded; DynamoDB final status update failed")

    summary = (f"[R4] {decision} | 담당자 <@{user_id}> | "
               f"격리 대상: {', '.join(selected) if selected else '없음'}")
    LOG.info("R4 CRITICAL decision=%s selected_count=%d", decision, len(selected))
    # Discord type 7 updates the original message and disables further interactions.
    return {
        "type": 7,
        "data": {
            "content": summary[:2000],
            "components": components(approval_id, candidates, disabled=True),
            "allowed_mentions": {"parse": []},
        },
    }


def verify_discord_signature(headers, raw_body):
    key_hex = env("DISCORD_PUBLIC_KEY")
    lower = {str(k).lower(): v for k, v in headers.items()}
    sig = lower.get("x-signature-ed25519", "")
    ts = lower.get("x-signature-timestamp", "")
    if not sig or not ts:
        return False
    try:
        if abs(int(time.time()) - int(ts)) > 300:
            return False
        message = ts.encode("ascii") + raw_body
        signature = bytes.fromhex(sig)
        public_key = bytes.fromhex(key_hex)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except ImportError:
            from nacl.signing import VerifyKey
            VerifyKey(public_key).verify(message, signature)
        return True
    except Exception:
        return False


def http_response(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body, ensure_ascii=False)}


def lambda_handler(event, context):
    # Direct Discord HTTP Interactions endpoint (API Gateway proxy format).
    if "body" in event and "headers" in event:
        raw_body = event.get("body") or ""
        raw_bytes = base64.b64decode(raw_body) if event.get("isBase64Encoded") else raw_body.encode("utf-8")
        if not verify_discord_signature(event.get("headers") or {}, raw_bytes):
            return http_response(401, {"error": "invalid signature"})
        try:
            interaction = json.loads(raw_bytes)
            return http_response(200, handle_interaction(interaction))
        except (KeyError, ValueError, TypeError):
            return http_response(400, {"error": "invalid interaction payload"})

    # An IAM-authorized internal call forwarded by king_all (Gateway mode).
    if event.get("mode") == "interaction":
        return handle_interaction(event["interaction"])

    # Step Functions Task Token callback pattern.
    if not event.get("taskToken") or not isinstance(event.get("finding"), dict):
        raise ValueError("Expected finding and taskToken from Step Functions")
    return notify(event["finding"], event["taskToken"], event.get("approvalTimeoutSeconds", 900))