import os

import boto3
from botocore.exceptions import ClientError

ACCOUNT = "059865587057"
REGION = "ap-northeast-2"


def lambda_handler(event, context):
    result = dict(
        event, enrichment_status=None, instance_state=None, vpc_id=None,
        security_groups=[], ir_automation_enabled=False, owner=None,
        private_ip=None, public_ip=None, instance_profile_arn=None,
        iam_role_name=None,
    )
    resource_account = None
    resource_id = event.get("resource_id") or ""
    if resource_id.startswith("arn:aws:ec2:"):
        arn_parts = resource_id.split(":")
        if len(arn_parts) > 4:
            resource_account = arn_parts[4]
    resource_account = (
        resource_account
        or (event.get("details") or {}).get("resource_account_id")
        or event.get("account_id")
    )
    if resource_account != ACCOUNT or event.get("region") != REGION:
        result["enrichment_status"] = "out_of_scope"
        return result
    if event.get("resource_type") != "AwsEc2Instance":
        result["enrichment_status"] = "not_applicable"
        return result
    instance_id = event.get("instance_id")
    if not instance_id:
        result["enrichment_status"] = "missing_instance_id"
        return result

    credentials = boto3.client("sts").assume_role(
        RoleArn=os.environ["WORKLOAD_ROLE_ARN"],
        RoleSessionName="SecurityHubEc2Enrichment",
    )["Credentials"]
    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=REGION,
    )
    try:
        reservations = session.client("ec2").describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        reservations = []

    instance = next((
        item for group in reservations if group.get("OwnerId") == ACCOUNT
        for item in group.get("Instances", [])
        if item.get("InstanceId") == instance_id
    ), None)
    if instance is None:
        result["enrichment_status"] = "not_found"
        return result

    tags = {tag["Key"]: tag.get("Value") for tag in instance.get("Tags", [])}
    profile_arn = (instance.get("IamInstanceProfile") or {}).get("Arn")
    role_name = None
    if profile_arn:
        profile = session.client("iam").get_instance_profile(
            InstanceProfileName=profile_arn.rsplit("/", 1)[-1]
        )["InstanceProfile"]
        roles = profile.get("Roles", [])
        role_name = roles[0]["RoleName"] if roles else None

    result.update({
        "enrichment_status": "success",
        "instance_state": instance.get("State", {}).get("Name"),
        "vpc_id": instance.get("VpcId"),
        "security_groups": [group["GroupId"] for group in instance.get("SecurityGroups", [])],
        "ir_automation_enabled": (tags.get("IR-Automation") or "").strip().lower() == "enabled",
        "owner": tags.get("Owner"),
        "private_ip": instance.get("PrivateIpAddress"),
        "public_ip": instance.get("PublicIpAddress"),
        "instance_profile_arn": profile_arn,
        "iam_role_name": role_name,
    })
    return result