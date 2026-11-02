import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

ISOLATION_SG_ID = os.environ["ISOLATION_SG_ID"]
WORKLOAD_ROLE_ARN = os.environ["WORKLOAD_ROLE_ARN"]

sts = boto3.client("sts")


def get_workload_ec2_client():
    response = sts.assume_role(
        RoleArn=WORKLOAD_ROLE_ARN,
        RoleSessionName="R4EC2Isolation"
    )

    credentials = response["Credentials"]

    return boto3.client(
        "ec2",
        region_name="ap-northeast-2",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )


def make_result(event, status, action_performed, reason=None, **extra):
    result = dict(event)

    isolation_result = {
        "status": status,
        "action_performed": action_performed
    }

    if reason is not None:
        isolation_result["reason"] = reason

    isolation_result.update(extra)
    result["isolation_result"] = isolation_result

    return result


def lambda_handler(event, context):
    if event.get("runbook_id") != "R4":
        return make_result(
            event,
            "NOT_PERFORMED",
            False,
            "NOT_R4"
        )

    approval = event.get("approval") or {}

    if approval.get("decision") != "APPROVED":
        return make_result(
            event,
            "NOT_PERFORMED",
            False,
            "NOT_APPROVED"
        )

    instance_id = event.get("instance_id")

    if not instance_id:
        raise ValueError("instance_id is required")

    ec2 = get_workload_ec2_client()

    try:
        response = ec2.describe_instances(
            InstanceIds=[instance_id]
        )

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]

        if error_code == "InvalidInstanceID.NotFound":
            return make_result(
                event,
                "NO_TARGET",
                False,
                "INSTANCE_NOT_FOUND"
            )

        raise

    reservations = response.get("Reservations", [])

    if not reservations:
        return make_result(
            event,
            "NO_TARGET",
            False,
            "INSTANCE_NOT_FOUND"
        )

    instances = reservations[0].get("Instances", [])

    if not instances:
        return make_result(
            event,
            "NO_TARGET",
            False,
            "INSTANCE_NOT_FOUND"
        )

    instance = instances[0]

    instance_state = instance["State"]["Name"]
    instance_vpc = instance["VpcId"]

    if instance_state in ("shutting-down", "terminated"):
        result = make_result(
            event,
            "NO_TARGET",
            False,
            "INSTANCE_" + instance_state.upper()
        )
        result["instance_state"] = instance_state
        return result

    if instance_state in ("pending", "stopping"):
        result = make_result(
            event,
            "RETRY_REQUIRED",
            False,
            "INSTANCE_" + instance_state.upper()
        )
        result["instance_state"] = instance_state
        return result

    if instance_state not in ("running", "stopped"):
        result = make_result(
            event,
            "NOT_PERFORMED",
            False,
            "UNSUPPORTED_INSTANCE_STATE"
        )
        result["instance_state"] = instance_state
        return result

    sg_response = ec2.describe_security_groups(
        GroupIds=[ISOLATION_SG_ID]
    )

    security_groups = sg_response.get("SecurityGroups", [])

    if not security_groups:
        raise ValueError(
            "Isolation security group not found: " + ISOLATION_SG_ID
        )

    isolation_sg = security_groups[0]

    if isolation_sg["VpcId"] != instance_vpc:
        raise ValueError(
            "Isolation SG belongs to another VPC. "
            "instance_vpc=" + instance_vpc +
            ", isolation_sg_vpc=" + isolation_sg["VpcId"]
        )

    network_interfaces = instance.get("NetworkInterfaces", [])

    if not network_interfaces:
        result = make_result(
            event,
            "NOT_PERFORMED",
            False,
            "NO_NETWORK_INTERFACES"
        )
        result["instance_state"] = instance_state
        return result

    eni_results = []
    action_performed = False

    for eni in network_interfaces:
        eni_id = eni["NetworkInterfaceId"]

        previous_groups = []

        for group in eni.get("Groups", []):
            previous_groups.append(group["GroupId"])

        if previous_groups == [ISOLATION_SG_ID]:
            eni_results.append({
                "network_interface_id": eni_id,
                "previous_security_groups": previous_groups,
                "new_security_groups": [ISOLATION_SG_ID],
                "status": "ALREADY_ISOLATED"
            })
            continue

        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[ISOLATION_SG_ID]
        )

        action_performed = True

        eni_results.append({
            "network_interface_id": eni_id,
            "previous_security_groups": previous_groups,
            "new_security_groups": [ISOLATION_SG_ID],
            "status": "ISOLATED"
        })

    verify_response = ec2.describe_instances(
        InstanceIds=[instance_id]
    )

    verified_instance = (
        verify_response["Reservations"][0]["Instances"][0]
    )

    verification_results = []
    fully_isolated = True

    for eni in verified_instance.get("NetworkInterfaces", []):
        current_groups = []

        for group in eni.get("Groups", []):
            current_groups.append(group["GroupId"])

        isolated = current_groups == [ISOLATION_SG_ID]

        if not isolated:
            fully_isolated = False

        verification_results.append({
            "network_interface_id": eni["NetworkInterfaceId"],
            "security_groups": current_groups,
            "isolated": isolated
        })

    isolation_timestamp = datetime.now(timezone.utc).isoformat()

    result = dict(event)
    result["instance_state"] = instance_state
    result["isolation_timestamp"] = isolation_timestamp
    result["isolation_sg_id"] = ISOLATION_SG_ID

    if not fully_isolated:
        result["isolation_status"] = "FAILED"
        result["isolation_result"] = {
            "status": "FAILED",
            "action_performed": action_performed,
            "reason": "SECURITY_GROUP_VERIFICATION_FAILED",
            "instance_id": instance_id,
            "isolation_security_group": ISOLATION_SG_ID,
            "network_interfaces": eni_results,
            "verification": verification_results
        }
        return result

    result["isolation_status"] = "ISOLATED"
    result["isolation_result"] = {
        "status": "ISOLATED",
        "action_performed": action_performed,
        "instance_id": instance_id,
        "isolation_security_group": ISOLATION_SG_ID,
        "network_interfaces": eni_results,
        "verification": verification_results
    }

    return result