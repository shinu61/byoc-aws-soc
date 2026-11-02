"""R7 webshell HIGH investigation Lambda."""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

HIGH_RULE_IDS = {"100110", "100111"}


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

    # 2. 웹셸 HIGH Rule인지 확인
    if rule_id not in HIGH_RULE_IDS:
        return {
            **event,
            "r7_webshell_result": {
                "status": "NOT_PERFORMED",
                "action_performed": False,
                "reason": "NOT_WEBSHELL_HIGH_RULE",
                "rule_id": rule_id
            }
        }

    # 3. HIGH 심각도인지 확인
    if severity != "HIGH":
        return {
            **event,
            "r7_webshell_result": {
                "status": "NOT_PERFORMED",
                "action_performed": False,
                "reason": "NOT_HIGH",
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

        "title": event.get("title"),
        "description": event.get("description"),
        "source_url": event.get("source_url")
    }

    logger.info(
        "R7 webshell HIGH evidence: %s",
        json.dumps(evidence, ensure_ascii=False)
    )

    # 5. R7에서는 리소스를 변경하지 않고 수동 조사로 넘김
    return {
        **event,
        "r7_webshell_result": {
            "status": "INVESTIGATION_REQUIRED",
            "action_performed": False,
            "evidence_collected": True,
            "resource_modified": False,
            "severity": "HIGH",
            "evidence": evidence,
            "next_action": "MANUAL_REVIEW",
            "reclassify_if_confirmed": "R4"
        }
    }