"""Create one Jira Cloud review ticket per MEDIUM Security Hub finding.

The input is the normalized common finding, optionally under ``finding``.
The original runbook is preserved. This function performs no containment.

Required environment: JIRA_BASE_URL, JIRA_PROJECT_KEY, JIRA_EMAIL,
JIRA_API_TOKEN, R1_TICKET_TABLE_NAME. Optional: JIRA_API_BASE_URL,
JIRA_ISSUE_TYPE (default Task), JIRA_ISSUE_TYPE_ID.
The DynamoDB table has a String partition key named finding_key; do not
expire its mapping records while matching Jira tickets need deduplication.
Interrupted or uncertain creation requires reconciliation in Jira before
resetting a record. A retry never blindly creates another ticket.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


HTTP_TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 65536
PENDING_REVIEW_AFTER_SECONDS = 120
_MISSING = "미확인"


@dataclass(frozen=True)
class Config:
    site_url: str
    api_url: str
    project_key: str
    email: str
    token: str = field(repr=False)
    table_name: str = ""
    issue_type: str = "Task"
    issue_type_id: str = ""


class ConfigurationError(ValueError):
    pass


class JiraFailure(Exception):
    """Contains controlled codes only, never credentials or response bodies."""

    def __init__(self, code, status="REVIEW_REQUIRED", http_status=None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.http_status = http_status


def _https_base(value, name, allow_path=False):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ConfigurationError(name + " must be a valid HTTPS URL") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or port not in (None, 443) or "\\" in value
            or any(character.isspace() for character in value)
            or (not allow_path and parsed.path not in ("", "/"))):
        raise ConfigurationError(name + " must be an HTTPS base URL without credentials or parameters")
    return value.rstrip("/")


def load_config(environ):
    names = ("JIRA_BASE_URL", "JIRA_PROJECT_KEY", "JIRA_EMAIL",
             "JIRA_API_TOKEN", "R1_TICKET_TABLE_NAME")
    values = {name: str(environ.get(name, "")).strip() for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ConfigurationError("Missing environment variables: " + ", ".join(missing))
    site = _https_base(values["JIRA_BASE_URL"], "JIRA_BASE_URL")
    api = _https_base(str(environ.get("JIRA_API_BASE_URL", site)).strip(),
                      "JIRA_API_BASE_URL", allow_path=True)
    project = values["JIRA_PROJECT_KEY"]
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", project):
        raise ConfigurationError("JIRA_PROJECT_KEY must be the project key, not its display name")
    if ":" in values["JIRA_EMAIL"] or "@" not in values["JIRA_EMAIL"]:
        raise ConfigurationError("JIRA_EMAIL must be the token owner's email")
    issue_id = str(environ.get("JIRA_ISSUE_TYPE_ID", "")).strip()
    if issue_id and not issue_id.isdigit():
        raise ConfigurationError("JIRA_ISSUE_TYPE_ID must be numeric")
    issue_type = str(environ.get("JIRA_ISSUE_TYPE", "Task")).strip() or "Task"
    return Config(site, api, project, values["JIRA_EMAIL"], values["JIRA_API_TOKEN"],
                  values["R1_TICKET_TABLE_NAME"], issue_type, issue_id)


def _text(value, limit=500):
    if value is None or value == "":
        return _MISSING
    if not isinstance(value, (str, int, float, bool)):
        return _MISSING
    return " ".join(str(value).split())[:limit] or _MISSING


def _first(finding, *names):
    return next((finding[name] for name in names if finding.get(name) not in (None, "")), None)


def finding_identity(finding, config):
    required = ("finding_id", "account_id", "region")
    if any(not isinstance(finding.get(name), str) or not finding[name].strip() for name in required):
        raise ValueError("finding_id, account_id and region are required")
    if not re.fullmatch(r"[0-9]{12}", finding["account_id"]):
        raise ValueError("account_id must contain 12 digits")
    product = finding.get("product_arn") or finding.get("product")
    if not isinstance(product, str) or not product.strip():
        raise ValueError("product_arn or product is required")
    identity = [config.site_url, config.project_key, finding["account_id"],
                finding["region"], product, finding["finding_id"]]
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_payload(finding, config, finding_key):
    """Only approved display fields cross the Jira boundary; no raw event dump."""
    runbook = _text(finding.get("runbook_id"), 20)
    kind = _text(_first(finding, "finding_type", "title"), 180)
    target = _text(_first(finding, "resource_name", "instance_id", "resource_id"), 120)
    is_test = finding.get("sample") is True or _text(finding.get("title")).upper().startswith("[TEST]")
    prefix = "[TEST]" if is_test else ""
    summary = (prefix + "[MEDIUM][" + runbook + "] " + kind + " / " + target)[:255]
    display = [
        ("처리 목적", "보안 경보 검토. 자동 차단·격리는 실행하지 않습니다."),
        ("Runbook", finding.get("runbook_id")),
        ("Finding 유형", finding.get("finding_type")),
        ("Finding ID", finding.get("finding_id")),
        ("제품", finding.get("product")),
        ("심각도", "MEDIUM"),
        ("계정", finding.get("account_id")),
        ("리전", finding.get("region")),
        ("리소스 유형", finding.get("resource_type")),
        ("대상 리소스", finding.get("resource_id")),
        ("인스턴스 ID", finding.get("instance_id")),
        ("출발지 IP", finding.get("source_ip")),
        ("최초 탐지", _first(finding, "event_first_seen", "first_observed_at")),
        ("최근 탐지", _first(finding, "event_last_seen", "last_observed_at")),
        ("탐지 설명", finding.get("description")),
        ("원본 링크", finding.get("source_url")),
    ]
    if is_test:
        display.insert(0, ("테스트 경보", "합성·샘플 경보의 티켓 생성 시험입니다."))
    details = finding.get("details")
    if isinstance(details, dict):
        for name in ("rule_id", "rule_level", "count"):
            if details.get(name) is not None:
                display.append((name, details[name]))
    paragraphs = [{"type": "paragraph", "content": [{"type": "text",
                    "text": label + ": " + _text(value, 1500 if label == "탐지 설명" else 500)}]}
                  for label, value in display]
    fields = {
        "project": {"key": config.project_key},
        "issuetype": {"id": config.issue_type_id} if config.issue_type_id else {"name": config.issue_type},
        "summary": summary,
        "description": {"type": "doc", "version": 1, "content": paragraphs},
        "labels": ["soc-medium", "soc-finding-" + finding_key] + (["soc-test"] if is_test else []),
    }
    # Assignment and workflow transitions are manual in the first version.
    return {"fields": fields}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def create_jira_issue(config, payload, opener=None):
    auth = base64.b64encode((config.email + ":" + config.token).encode("utf-8")).decode("ascii")
    request = urllib.request.Request(config.api_url + "/rest/api/3/issue",
                                    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                    headers={"Authorization": "Basic " + auth,
                                             "Accept": "application/json", "Content-Type": "application/json"},
                                    method="POST")
    opener = opener or urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = response.status
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        # Jira's error body can contain reflected request data; do not expose it.
        error.close()
        raise JiraFailure("JIRA_HTTP_" + str(status),
                          "REVIEW_REQUIRED" if status >= 500 else "FAILED", status) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise JiraFailure("JIRA_RESPONSE_UNCERTAIN") from None
    if status != 201 or len(body) > MAX_RESPONSE_BYTES:
        raise JiraFailure("JIRA_RESPONSE_UNEXPECTED", http_status=status)
    try:
        result = json.loads(body)
        key = result["key"]
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*-[0-9]+", key):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise JiraFailure("JIRA_CREATED_KEY_UNCONFIRMED", http_status=201) from None
    return {"jira_key": key, "jira_url": config.site_url + "/browse/" + key}


def _conditional_failure(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _finish(table, key, request_id, status, timestamp, values):
    names = {"#s": "status"}
    attrs = {":pending": "PENDING", ":request": request_id, ":status": status, ":updated": timestamp}
    assignments = ["#s = :status", "updated_at = :updated"]
    for index, (name, value) in enumerate(values.items()):
        names["#v" + str(index)] = name
        attrs[":v" + str(index)] = value
        assignments.append("#v" + str(index) + " = :v" + str(index))
    table.update_item(Key={"finding_key": key}, UpdateExpression="SET " + ", ".join(assignments),
                      ConditionExpression="#s = :pending AND request_id = :request",
                      ExpressionAttributeNames=names, ExpressionAttributeValues=attrs)


def _aws_table(name):
    import boto3  # Included in the AWS Lambda Python runtime; local tests use fakes.
    return boto3.resource("dynamodb").Table(name)


def _existing_result(common, existing, timestamp):
    status = existing.get("status", "REVIEW_REQUIRED")
    needs_review = (status != "CREATED" and (status != "PENDING"
                    or timestamp - existing.get("created_at", 0) >= PENDING_REVIEW_AFTER_SECONDS))
    output = dict(common, status=status, deduplicated=True, manual_review_required=needs_review)
    for name in ("jira_key", "jira_url", "error_code", "http_status"):
        if name in existing:
            output[name] = existing[name]
    return output


def handle_event(event, *, environ=None, table_factory=None, jira_create=None, clock=None):
    environ = os.environ if environ is None else environ
    finding = event.get("finding", event) if isinstance(event, dict) else None
    if not isinstance(finding, dict):
        raise ValueError("Input must be a common finding object or a finding wrapper")
    severity = finding.get("severity")
    if severity != "MEDIUM":
        return {"status": "SKIPPED", "created": False, "reason": "severity_not_medium"}
    if (finding.get("record_state") == "ARCHIVED"
            or finding.get("workflow_status") in ("RESOLVED", "SUPPRESSED")):
        return {"status": "SKIPPED", "created": False, "reason": "finding_closed"}
    # Severity-first routing may reach R1 before another runbook is assigned.
    finding = dict(finding)
    finding["runbook_id"] = finding.get("runbook_id") or "R1"
    config = load_config(environ)
    key = finding_identity(finding, config)
    payload = build_payload(finding, config, key)
    table = (table_factory or _aws_table)(config.table_name)
    timestamp = int((clock or time.time)())
    request_id = uuid.uuid4().hex
    common = {"finding_key": key, "finding_id": finding["finding_id"],
              "runbook_id": finding.get("runbook_id"), "created": False,
              "deduplicated": False, "manual_review_required": False}
    # Only ACTIVE + NEW may create a new ticket. An existing mapping may still
    # be returned for NOTIFIED or other nonterminal updates without another POST.
    if finding.get("record_state") != "ACTIVE" or finding.get("workflow_status") != "NEW":
        try:
            existing = table.get_item(Key={"finding_key": key}, ConsistentRead=True).get("Item", {})
        except Exception:
            return dict(common, status="ERROR", error_code="MAPPING_READ_FAILED", manual_review_required=True)
        if existing:
            return _existing_result(common, existing, timestamp)
        return dict(common, status="SKIPPED", reason="finding_not_active_new")
    record = {"finding_key": key, "status": "PENDING", "request_id": request_id,
              "finding_id": finding["finding_id"], "account_id": finding["account_id"],
              "region": finding["region"], "product": finding.get("product", "Unknown"),
              "jira_site": config.site_url, "jira_project": config.project_key,
              "runbook_id": finding.get("runbook_id") or "Unknown",
              "created_at": timestamp, "updated_at": timestamp}
    try:
        table.put_item(Item=record, ConditionExpression="attribute_not_exists(finding_key)")
    except Exception as error:
        if not _conditional_failure(error):
            return dict(common, status="ERROR", error_code="MAPPING_CLAIM_FAILED", manual_review_required=True)
        try:
            existing = table.get_item(Key={"finding_key": key}, ConsistentRead=True).get("Item", {})
        except Exception:
            return dict(common, status="ERROR", error_code="MAPPING_READ_FAILED", manual_review_required=True)
        return _existing_result(common, existing, timestamp)
    jira_create = jira_create or create_jira_issue
    try:
        jira_result = jira_create(config, payload)
    except Exception as error:
        failure = error if isinstance(error, JiraFailure) else JiraFailure("JIRA_RESPONSE_UNCERTAIN")
        values = {"error_code": failure.code}
        if failure.http_status is not None:
            values["http_status"] = failure.http_status
        try:
            _finish(table, key, request_id, failure.status, timestamp, values)
        except Exception:
            values["mapping_error"] = "MAPPING_FINALIZE_FAILED"
        return dict(common, status=failure.status, manual_review_required=True, **values)
    try:
        _finish(table, key, request_id, "CREATED", timestamp, jira_result)
    except Exception:
        return dict(common, status="CREATED_MAPPING_PENDING", created=True,
                    manual_review_required=True, error_code="MAPPING_FINALIZE_FAILED", **jira_result)
    return dict(common, status="CREATED", created=True, **jira_result)


class R1TicketResultUnconfirmed(RuntimeError):
    """Fail the Lambda Task with controlled reconciliation details only."""

    def __init__(self, result):
        result = result if isinstance(result, dict) else {}
        status = result.get("status")
        allowed_statuses = ("CREATED", "SKIPPED", "PENDING", "FAILED", "ERROR",
                            "REVIEW_REQUIRED", "CREATED_MAPPING_PENDING")
        self.status = status if isinstance(status, str) and status in allowed_statuses else "INVALID_RESPONSE"
        code = result.get("error_code")
        allowed_codes = ("JIRA_RESPONSE_UNCERTAIN", "JIRA_RESPONSE_UNEXPECTED",
                         "JIRA_CREATED_KEY_UNCONFIRMED", "MAPPING_READ_FAILED",
                         "MAPPING_CLAIM_FAILED", "MAPPING_FINALIZE_FAILED")
        self.error_code = (code if isinstance(code, str) and (code in allowed_codes
                           or re.fullmatch(r"JIRA_HTTP_[0-9]{3}", code))
                           else "R1_TICKET_RESULT_UNCONFIRMED")
        message = "status=" + self.status + "; error_code=" + self.error_code
        # A confirmed POST followed by a failed mapping update must retain the
        # Jira key for manual reconciliation. Never include arbitrary result data.
        key = result.get("jira_key")
        if (self.status == "CREATED_MAPPING_PENDING" and isinstance(key, str)
                and re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}-[0-9]{1,20}", key)):
            message += "; jira_key=" + key
        super().__init__(message)


def lambda_handler(event, context):
    """Return only confirmed R1 outcomes; all other results fail the Task.

    handle_event finishes its DynamoDB bookkeeping before this check. Its
    standalone return contract remains available to offline tests and callers.
    """
    result = handle_event(event)
    if isinstance(result, dict):
        status = result.get("status")
        if (isinstance(status, str) and status == "CREATED"
                and isinstance(result.get("jira_key"), str)
                and result["jira_key"] != ""
                and result.get("manual_review_required") is False):
            return result
        if (isinstance(status, str) and status == "SKIPPED"
                and result.get("reason") in ("finding_closed", "finding_not_active_new")):
            return result
    raise R1TicketResultUnconfirmed(result) from None
