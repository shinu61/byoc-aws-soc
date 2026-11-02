"""R7 webshell CRITICAL investigation Lambda."""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CRITICAL_RULE_IDS = {"100220"}


def lambda_handler(event, context):

    # 1. R7 이벤트인지 확인
    if event.get("runbook_id") != "R7":
        return {
            **event,
            "r7_webshell_result": {
                "status": "NOT_PERFORMED",
                "action_performed": False,
                "reason": "NOT_R7"
            }
        }

    details = event.get("details") or {}

    rule_id = str(details.get("rule_id", ""))
    severity = str(event.get("severity", "")).upper()

    # 2. 웹셸 CRITICAL Rule인지 확인
    if rule_id not in CRITICAL_RULE_IDS:
        return {
            **event,
            "r7_webshell_result": {
                "status": "NOT_PERFORMED",
                "action_performed": False,
                "reason": "NOT_WEBSHELL_CRITICAL_RULE",
                "rule_id": rule_id
            }
        }

    # 3. CRITICAL Severity인지 확인
    if severity != "CRITICAL":
        return {
            **event,
            "r7_webshell_result": {
                "status": "NOT_PERFORMED",
                "action_performed": False,
                "reason": "NOT_CRITICAL",
                "severity": severity
            }
        }

    # 4. 조사에 필요한 증거 정리
    evidence = {
        "finding_id": event.get("finding_id"),
        "event_id": event.get("event_id"),

        "severity": severity,
        "rule_id": rule_id,
        "rule_level": details.get("rule_level"),

        "instance_id": event.get("instance_id"),
        "resource_name": event.get("resource_name"),

        "agent_name": details.get("agent_name"),
        "agent_ip": details.get("agent_ip"),

        "resource_account_id": details.get("resource_account_id"),
        "region": event.get("region"),

        "first_observed_at": event.get("first_observed_at"),
        "last_observed_at": event.get("last_observed_at"),

        # 프로세스 실행 관련 정보
        # 정규화 Lambda가 해당 값을 전달하는 경우 수집
        "audit_euid": details.get("audit_euid"),
        "audit_command": details.get("audit_command"),
        "audit_exe": details.get("audit_exe"),
        "audit_cwd": details.get("audit_cwd"),

        "title": event.get("title"),
        "description": event.get("description"),
        "source_url": event.get("source_url")
    }

    logger.info(
        "R7 webshell CRITICAL evidence: %s",
        json.dumps(evidence, ensure_ascii=False)
    )

    # 5. R7에서는 리소스를 직접 변경하지 않음
    return {
        **event,
        "r7_webshell_result": {
            "status": "INVESTIGATION_REQUIRED",
            "action_performed": False,
            "evidence_collected": True,
            "resource_modified": False,
            "severity": "CRITICAL",
            "evidence": evidence,

            # 아래 값들은 다음 조치를 표현하기 위한 메타데이터
            "next_action": "MANUAL_REVIEW",
            "review_priority": "URGENT",
            "reclassify_if_confirmed": "R4"
        }
    }