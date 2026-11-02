import os
import boto3
from ipaddress import ip_address

SCOPE = os.environ.get("WAF_SCOPE", "REGIONAL")
IPSET_NAME = os.environ["WAF_IPSET_NAME"]
IPSET_ID = os.environ["WAF_IPSET_ID"]
ROLE_ARN = os.environ["WAF_BLOCK_ROLE_ARN"]
ALLOWLIST = {ip for ip in os.environ.get("BLOCK_ALLOWLIST", "").split(",") if ip}

_sts = boto3.client("sts")


def _waf_client():
    creds = _sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="r2-waf-block")["Credentials"]
    return boto3.client(
        "wafv2",
        region_name="ap-northeast-2",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _blockable(value):
    try:
        ip = ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except (ValueError, TypeError):
        return False

def lambda_handler(event, context):
    source_ip = event.get("source_ip")
    if not _blockable(source_ip):
        return {"blocked": False, "reason": "invalid_or_internal_ip", "ip": source_ip}
    if source_ip in ALLOWLIST:
        return {"blocked": False, "reason": "allowlisted", "ip": source_ip}

    cidr = f"{source_ip}/32"
    waf = _waf_client()                      # ← 059 역할 빌려서 WAF 클라이언트 생성
    current = waf.get_ip_set(Name=IPSET_NAME, Scope=SCOPE, Id=IPSET_ID)
    addresses = current["IPSet"]["Addresses"]
    if cidr in addresses:
        return {"blocked": True, "reason": "already_blocked", "ip": cidr}

    waf.update_ip_set(
        Name=IPSET_NAME, Scope=SCOPE, Id=IPSET_ID,
        Addresses=addresses + [cidr],
        LockToken=current["LockToken"],
    )
    return {"blocked": True, "ip": cidr, "finding_id": event.get("finding_id")}