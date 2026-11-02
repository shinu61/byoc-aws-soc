import json
import re


WAZUH_PRODUCT_ARN = (
    "arn:aws:securityhub:ap-northeast-2:229251311221:"
    "product/229251311221/default"
)


def identify_product(product_arn, generator_id, product_fields=None):
    if product_arn.endswith(":product/aws/guardduty"):
        return "GuardDuty"

    if (
        product_arn == WAZUH_PRODUCT_ARN
        and generator_id.startswith("wazuh-rule-")
    ):
        location = (product_fields or {}).get("wazuh/location", "")
        if "eve.json" in location:
            return "Suricata"
        return "Wazuh"

    return "Unknown"


def extract_source_ip(finding, product_fields):
    # Wazuh ASFF
    source_ip = (finding.get("Network") or {}).get("SourceIpV4")
    if source_ip:
        return source_ip

    # 일반적인 GuardDuty ASFF
    for action_detail in (finding.get("Action") or {}).values():
        if not isinstance(action_detail, dict):
            continue

        remote_ip = action_detail.get("RemoteIpDetails") or {}
        if remote_ip.get("IpAddressV4"):
            return remote_ip["IpAddressV4"]

    # 일부 GuardDuty Finding
    for key, value in product_fields.items():
        key_lower = key.lower()
        if (
            "remoteipdetails" in key_lower
            and key_lower.endswith("ipaddressv4")
        ):
            return value

    return None

def extract_network_fields(finding):
    action = finding.get("Action") or {}

    if "NetworkConnectionAction" in action:
        network_action = action["NetworkConnectionAction"]

        remote_ip = (network_action.get("RemoteIpDetails") or {}).get("IpAddressV4")
        remote_port = (network_action.get("RemotePortDetails") or {}).get("Port")
        protocol = network_action.get("Protocol")
        direction = network_action.get("ConnectionDirection")

    else:
        remote_ip = None
        remote_port = None
        protocol = None
        direction = None

    return remote_ip, remote_port, protocol, direction

# ASFF Detection.Sequence.Signals[].ResourceIds may contain EC2 IDs or ARNs.
# Extract only unambiguous EC2 instance identifiers (not arbitrary text).
def parse_ec2_instance_id(value):
    if not isinstance(value, str):
        return None

    if re.fullmatch(r"i-[0-9a-fA-F]{8,17}", value):
        return value

    match = re.fullmatch(
        r"arn:aws(?:-cn|-us-gov)?:ec2:[a-z0-9-]+:[0-9]{12}:instance/(i-[0-9a-fA-F]{8,17})",
        value,
    )
    return match.group(1) if match else None


def extract_attack_sequence_instance_ids(resources, sequence):
    # Resources: explicitly typed EC2 resources in Security Hub ASFF.
    instance_ids = []
    seen = set()

    def add(value):
        instance_id = parse_ec2_instance_id(value)
        if instance_id and instance_id not in seen:
            seen.add(instance_id)
            instance_ids.append(instance_id)

    for resource in resources:
        if isinstance(resource, dict) and resource.get("Type") == "AwsEc2Instance":
            add(resource.get("Id"))

    # Signals: correlated GuardDuty signals may identify additional EC2s.
    for signal in sequence.get("Signals") or []:
        if not isinstance(signal, dict):
            continue
        for resource_id in signal.get("ResourceIds") or []:
            add(resource_id)

    return instance_ids


def extract_iam_fields(resources):
    result = {
        "principal_type": None,
        "user_name": None,
        "role_name": None,
        "access_key_id": None,
        "key_created_at": None,
    }

    for resource in resources:
        iam_access_key = (
            (resource.get("Details") or {}).get("AwsIamAccessKey") or {}
        )
        if not iam_access_key:
            continue

        principal_type = iam_access_key.get("PrincipalType")
        principal_name = iam_access_key.get("PrincipalName")
        principal_kind = (principal_type or "").replace("_", "").lower()

        result["principal_type"] = principal_type
        result["access_key_id"] = iam_access_key.get("AccessKeyId")
        result["key_created_at"] = iam_access_key.get("CreatedAt")

        if principal_kind in ("iamuser", "user"):
            result["user_name"] = principal_name
        elif principal_kind in ("assumedrole", "role"):
            session_issuer = (
                (iam_access_key.get("SessionContext") or {})
                .get("SessionIssuer") or {}
            )
            result["role_name"] = (
                session_issuer.get("UserName") or principal_name
            )

        break

    return result


SURICATA_TARGETS = {
    "10.0.10.253": {
        "resource_name": "Web-Server-A",
        "instance_id": "i-0b030a28a071f1d0a",
        "resource_id": "arn:aws:ec2:ap-northeast-2:059865587057:instance/i-0b030a28a071f1d0a",
        "account_id": "059865587057",
    },
    "10.0.11.161": {
        "resource_name": "Web-Server-B",
        "instance_id": "i-0761763ebb3ade025",
        "resource_id": "arn:aws:ec2:ap-northeast-2:059865587057:instance/i-0761763ebb3ade025",
        "account_id": "059865587057",
    },
}




def lambda_handler(event, context):
    findings = (event.get("detail") or {}).get("findings")
    if not isinstance(findings, list) or len(findings) != 1:
        raise ValueError(
            "Expected exactly one finding in event.detail.findings"
        )

    finding = findings[0]
    resources = finding.get("Resources") or []
    product_fields = finding.get("ProductFields") or {}
    finding_types = finding.get("Types") or []

    product = identify_product(
        finding.get("ProductArn", ""),
        finding.get("GeneratorId", ""),
        finding.get("ProductFields"),
    )

    finding_type = finding_types[0] if finding_types else None
    type_parts = finding_type.split("/", 2) if finding_type else []

    namespace = type_parts[0] if len(type_parts) > 0 else None
    category = type_parts[1] if len(type_parts) > 1 else None
    classifier = type_parts[2] if len(type_parts) > 2 else None

    first_resource = resources[0] if resources else {}
    

    instance_id = None
    for resource in resources:
        if resource.get("Type") != "AwsEc2Instance":
            continue

        match = re.search(
            r"i-[0-9a-fA-F]{8,17}",
            resource.get("Id") or "",
        )
        if match:
            instance_id = match.group(0)
            break
    
    resource_name = (first_resource.get("Tags") or {}).get("Name")
    resource_id = first_resource.get("Id")

    if product == "Suricata":
        dest_ip = (finding.get("ProductFields") or {}).get("wazuh/data.dest_ip")
        target = SURICATA_TARGETS.get(dest_ip)
        if target:
            resource_name = target["resource_name"]
            instance_id = target["instance_id"]
            resource_id = target["resource_id"]
            account_id = target["account_id"]


    # AttackSequence:EC2 may represent multiple instances.
    # Keep the original scalar instance_id for existing HIGH workflows.
    is_ec2_attack_sequence = any(
        isinstance(value, str)
        and value.endswith("AttackSequence:EC2/CompromisedInstanceGroup")
        for value in finding_types
    )
    sequence = (finding.get("Detection") or {}).get("Sequence") or {}

    if is_ec2_attack_sequence:
        instance_ids = extract_attack_sequence_instance_ids(resources, sequence)
    else:
        instance_ids = [instance_id] if instance_id else []

    remote_ip, remote_port, protocol, direction = extract_network_fields(finding)
    if product in ("Wazuh", "Suricata"):
        if product == "Wazuh":
            resource_name = (
                product_fields.get("wazuh/agent_name") or resource_name
            )
        details = {
            "rule_id": product_fields.get("wazuh/rule_id"),
            "rule_level": product_fields.get("wazuh/rule_level"),
            "rule_groups": product_fields.get("wazuh/rule_groups"),
            "agent_name": product_fields.get("wazuh/agent_name"),
            "agent_ip": product_fields.get("wazuh/agent_ip"),
            "request_method": product_fields.get("wazuh/data.protocol") or product_fields.get("wazuh/data.http.http_method"),
            "request_url": product_fields.get("wazuh/data.url") or product_fields.get("wazuh/uri"),
            "http_status": product_fields.get("wazuh/data.id") or product_fields.get("wazuh/data.http.status"),
            "count": product_fields.get("wazuh/count"),
            "resource_account_id": product_fields.get("wazuh/resource_account_id"),
        }
    else:
        action = finding.get("Action") or {}
        dns_action = action.get("DnsRequestAction") or {}
        details = {
            "action_type": action.get("ActionType"),
            "dns_domain": dns_action.get("Domain"),
            "dns_protocol": dns_action.get("Protocol"),
            "dns_blocked": dns_action.get("Blocked"),
        }

    result = {
        "event_id": event.get("id"),
        "finding_id": finding.get("Id"),
        "account_id": finding.get("AwsAccountId"),
        "region": finding.get("Region") or event.get("region"),
        "product": product,
        "title": finding.get("Title"),
        "description": finding.get("Description"),
        "finding_types": finding_types,
        "finding_type": finding_type,
        "namespace": namespace,
        "category": category,
        "classifier": classifier,
        "severity": (finding.get("Severity") or {}).get("Label"),
        "workflow_status": (
            (finding.get("Workflow") or {}).get("Status")
        ),
        "record_state": finding.get("RecordState"),
        "sample": finding.get("Sample"),
        "resource_type": first_resource.get("Type"),
        "resource_id": resource_id,
        "resource_name": resource_name,
        "instance_id": instance_id,
        "instance_ids": instance_ids,
        "sequence_uid": sequence.get("Uid") if is_ec2_attack_sequence else None,
        "sequence_signal_count": (
            len(sequence.get("Signals") or []) if is_ec2_attack_sequence else 0
        ),
        "source_ip": extract_source_ip(finding, product_fields),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "protocol": protocol,
        "direction": direction,
        "first_observed_at": finding.get("FirstObservedAt"),
        "last_observed_at": finding.get("LastObservedAt"),
        "source_url": finding.get("SourceUrl"),
        "details": details,
        **extract_iam_fields(resources),
    }

    print("NORMALIZED_FINDING=" + json.dumps(result, ensure_ascii=False))
    return result