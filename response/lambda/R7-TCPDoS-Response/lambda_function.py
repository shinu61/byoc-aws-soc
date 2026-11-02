"""R7 response Lambda: registered targets, no external state database.

Restore uses the original SG lists registered in TARGET_CONFIGS.
Only the already approved Attacker is registered in this version.
Adding a target also requires permissions for that target in its workload role.
Do not run isolate and restore concurrently for the same target.
TCP termination remains limited to the destination registered for each target.
NACL rules filter the registered IPv4 address at associated subnet boundaries.
They do not cover same-subnet traffic or replace host/SG isolation.
"""

import copy
import ipaddress
import json
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


DEFAULT_INSTANCE_ID = "i-071919a7ef794ee32"

# Original SG lists are the registered restore configuration, not runtime state.
# Do not replace them with the isolation SG after isolating an instance.
TARGET_CONFIGS = {
    "i-071919a7ef794ee32": {
        "account_id": "059865587057",
        "region": "ap-northeast-2",
        "workload_role_arn": (
            "arn:aws:iam::059865587057:role/R7-TCPDoS-Workload-Role"
        ),
        "vpc_id": "vpc-0cbc5623bb36e0cf7",
        "expected_private_ip": "10.0.10.193",
        "network_interfaces": {
            "eni-09ceb0fce64c8f8f0": {
                "original_security_groups": ["sg-02447c8b971479d0c"],
                "isolation_security_group": "sg-0976416982f8db596",
            }
        },
        "instance_role_name": "web-alb-demo-ssm-role",
        "instance_role_arn": (
            "arn:aws:iam::059865587057:role/web-alb-demo-ssm-role"
        ),
        "evidence_volume_id": "vol-07dad69405e3d7d2f",
        "connection_destination_ip": "10.0.10.253",
        "connection_destination_port": 80,
        "network_acl": {
            "id": "acl-0b02bf0cc0a15044a",
            "target_subnet_id": "subnet-0516973a4c5cfd47e",
            "ingress_rule_number": 90,
            "egress_rule_number": 90,
        },
    }
}

ACTIONS = {
    "check", "dry_run", "isolate", "restore",
    "iam_check", "iam_isolate", "iam_restore",
    "snapshot_check", "snapshot_create", "snapshot_status",
    "connection_test_send", "connection_terminate_send",
    "connection_status", "isolate_and_terminate_send",
    "nacl_check", "nacl_dry_run", "nacl_isolate", "nacl_restore",
}


def resolve_target(event, action):
    instance_id = event.get("instance_id")
    if instance_id is None and action == "check":
        instance_id = DEFAULT_INSTANCE_ID
    if not isinstance(instance_id, str) or instance_id not in TARGET_CONFIGS:
        raise ValueError("등록된 대상의 정확한 instance_id가 필요합니다.")

    target = copy.deepcopy(TARGET_CONFIGS[instance_id])
    target["instance_id"] = instance_id
    if event.get("account_id", target["account_id"]) != target["account_id"]:
        raise ValueError("입력 account_id가 등록된 대상 계정과 다릅니다.")
    if event.get("region", target["region"]) != target["region"]:
        raise ValueError("입력 region이 등록된 대상 리전과 다릅니다.")

    for eni_id, settings in target["network_interfaces"].items():
        if re.fullmatch(r"eni-(?:[0-9a-f]{8}|[0-9a-f]{17})", eni_id) is None:
            raise ValueError("등록된 ENI ID 형식이 올바르지 않습니다.")
        original = settings["original_security_groups"]
        isolation = settings["isolation_security_group"]
        if not original or len(original) != len(set(original)):
            raise ValueError("원래 SG 목록이 비어 있거나 중복되었습니다.")
        if isolation in original:
            raise ValueError("원래 SG 목록에 격리 SG를 넣을 수 없습니다.")
        for group_id in original + [isolation]:
            if re.fullmatch(r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})", group_id) is None:
                raise ValueError("등록된 SG ID 형식이 올바르지 않습니다.")
        settings["original_security_groups"] = sorted(original)
    if not target["network_interfaces"]:
        raise ValueError("대상의 ENI 설정이 없습니다.")

    ipaddress.IPv4Address(target["expected_private_ip"])
    ipaddress.IPv4Address(target["connection_destination_ip"])
    port = target["connection_destination_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("등록된 TCP 포트가 올바르지 않습니다.")

    # Existing environment variables are still checked for the original target.
    # New target entries use their own configuration, not these singleton values.
    if instance_id == DEFAULT_INSTANCE_ID:
        settings = next(iter(target["network_interfaces"].values()))
        legacy = {
            "TARGET_INSTANCE_ID": instance_id,
            "WORKLOAD_ROLE_ARN": target["workload_role_arn"],
            "ORIGINAL_SG_ID": settings["original_security_groups"][0],
            "ISOLATION_SG_ID": settings["isolation_security_group"],
            "INSTANCE_ROLE_NAME": target["instance_role_name"],
            "TARGET_VOLUME_ID": target["evidence_volume_id"],
        }
        for name, expected in legacy.items():
            if name in os.environ and os.environ[name] != expected:
                raise ValueError(f"환경 변수 {name}이 등록된 설정과 다릅니다.")
    return target


def get_session(target):
    credentials = boto3.client("sts", region_name=target["region"]).assume_role(
        RoleArn=target["workload_role_arn"],
        RoleSessionName="R7TCPDoSResponse",
    )["Credentials"]
    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=target["region"],
    )
    if session.client("sts").get_caller_identity()["Account"] != target["account_id"]:
        raise ValueError("대상 계정이 등록된 계정과 다릅니다.")
    return session


def get_instance(ec2, target):
    response = ec2.describe_instances(InstanceIds=[target["instance_id"]])
    instances = [
        instance
        for reservation in response["Reservations"]
        for instance in reservation["Instances"]
    ]
    if len(instances) != 1 or instances[0]["InstanceId"] != target["instance_id"]:
        raise ValueError("정확한 대상 인스턴스를 확인하지 못했습니다.")
    instance = instances[0]
    if instance.get("VpcId") != target["vpc_id"]:
        raise ValueError("인스턴스 VPC가 등록된 설정과 다릅니다.")
    return instance


def check_dry_run(operation, **kwargs):
    try:
        operation(DryRun=True, **kwargs)
    except ClientError as error:
        if error.response["Error"]["Code"] != "DryRunOperation":
            raise
    else:
        raise RuntimeError("예상하지 못한 DryRun 응답입니다.")


def get_registered_network_interfaces(ec2, target):
    # DescribeInstances embeds InstanceNetworkInterfaceAttachment objects.
    # Those do not contain InstanceId. Read attachment ownership using the
    # DescribeNetworkInterfaces response, whose Attachment does contain it.
    response = ec2.describe_network_interfaces(
        NetworkInterfaceIds=list(target["network_interfaces"])
    )
    interfaces = {
        interface["NetworkInterfaceId"]: interface
        for interface in response["NetworkInterfaces"]
    }
    if set(interfaces) != set(target["network_interfaces"]):
        raise ValueError("등록된 모든 ENI를 확인하지 못했습니다.")
    for interface in interfaces.values():
        attachment = interface.get("Attachment", {})
        if attachment.get("InstanceId") != target["instance_id"]:
            raise ValueError("ENI가 대상 인스턴스에 연결되어 있지 않습니다.")
        if attachment.get("Status") != "attached":
            raise ValueError("ENI 연결 상태가 attached가 아닙니다.")
        if interface.get("VpcId") != target["vpc_id"]:
            raise ValueError("ENI VPC가 등록된 대상 VPC와 다릅니다.")
    return interfaces


def inspect_security_groups(ec2, target):
    instance = get_instance(ec2, target)
    interfaces = {
        interface["NetworkInterfaceId"]: interface
        for interface in instance["NetworkInterfaces"]
    }
    registered = target["network_interfaces"]
    if set(interfaces) != set(registered):
        raise ValueError("현재 ENI 구성과 등록된 ENI 구성이 다릅니다.")
    interfaces = get_registered_network_interfaces(ec2, target)

    group_ids = sorted({
        group_id
        for settings in registered.values()
        for group_id in (
            settings["original_security_groups"]
            + [settings["isolation_security_group"]]
        )
    })
    groups = ec2.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]
    group_map = {group["GroupId"]: group for group in groups}
    if set(group_map) != set(group_ids):
        raise ValueError("등록된 보안 그룹을 모두 확인하지 못했습니다.")
    if any(group["VpcId"] != target["vpc_id"] for group in groups):
        raise ValueError("보안 그룹의 VPC가 대상 VPC와 다릅니다.")

    current = {}
    for eni_id, settings in registered.items():
        interface = interfaces[eni_id]
        isolation = group_map[settings["isolation_security_group"]]
        if isolation["IpPermissions"] or isolation["IpPermissionsEgress"]:
            raise ValueError("격리 그룹에 허용 규칙이 있습니다.")
        before = sorted(group["GroupId"] for group in interface["Groups"])
        if before not in (
            settings["original_security_groups"],
            [settings["isolation_security_group"]],
        ):
            raise ValueError(f"{eni_id}의 SG 구성이 등록된 설정과 다릅니다.")
        current[eni_id] = before
    return current


def handle_security_group(ec2, action, target):
    before = inspect_security_groups(ec2, target)
    desired = {}
    for eni_id, settings in target["network_interfaces"].items():
        if action == "isolate":
            desired[eni_id] = [settings["isolation_security_group"]]
        elif action == "restore":
            desired[eni_id] = settings["original_security_groups"]
        else:
            desired[eni_id] = before[eni_id]

    if action == "dry_run":
        for eni_id, settings in target["network_interfaces"].items():
            for group_ids in (
                [settings["isolation_security_group"]],
                settings["original_security_groups"],
            ):
                check_dry_run(
                    ec2.modify_network_interface_attribute,
                    NetworkInterfaceId=eni_id, Groups=group_ids,
                )
        result = {
            "status": "DRY_RUN_PASSED",
            "instance_id": target["instance_id"],
            "changed": False,
            "network_interfaces": [
                {"eni_id": eni_id, "current_security_groups": groups}
                for eni_id, groups in before.items()
            ],
        }
        if len(before) == 1:
            result["current_security_groups"] = next(iter(before.values()))
        return result

    pending = [eni_id for eni_id in before if before[eni_id] != desired[eni_id]]
    # For a multi-ENI target, check known permission failures before any changes.
    if len(before) > 1:
        for eni_id in pending:
            check_dry_run(
                ec2.modify_network_interface_attribute,
                NetworkInterfaceId=eni_id, Groups=desired[eni_id],
            )
    changed_enis = []
    try:
        for eni_id in pending:
            ec2.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=desired[eni_id],
            )
            changed_enis.append(eni_id)
    except Exception as error:
        print(json.dumps({
            "action": action, "instance_id": target["instance_id"],
            "changed_enis": changed_enis, "expected": desired,
            "error": str(error),
        }))
        # Do not automatically reopen an interface after a partial isolation.
        raise

    actual = get_registered_network_interfaces(ec2, target)
    rows = []
    for eni_id in before:
        interface = actual[eni_id]
        after = sorted(group["GroupId"] for group in interface["Groups"])
        rows.append({
            "eni_id": eni_id,
            "before": before[eni_id], "after": after,
            "expected": desired[eni_id],
            "verified": after == desired[eni_id],
            "change_requested": eni_id in changed_enis,
        })
    result = {
        "action": action,
        "instance_id": target["instance_id"],
        "account_id": target["account_id"], "region": target["region"],
        "network_interfaces": rows,
        "verified": all(row["verified"] for row in rows),
        "change_requested": bool(changed_enis),
        "restore_source": "registered_configuration",
    }
    # Keep existing single-ENI response fields for the already tested events.
    if len(rows) == 1:
        for key in ("before", "after", "expected"):
            result[key] = rows[0][key]
    return result


def handle_iam(session, action, target):
    iam = session.client("iam")
    role_name = target["instance_role_name"]
    role = iam.get_role(RoleName=role_name)["Role"]
    if role["Arn"] != target["instance_role_arn"]:
        raise ValueError("역할 ARN이 등록된 설정과 다릅니다.")

    instance_id = target["instance_id"]
    policy_name = f"R7-Isolate-{instance_id}"
    document = {
        "Version": "2012-10-17",
        "Statement": [{
            # Preserve the existing statement ID so old policies still match.
            "Sid": "DenyAttackerInstanceCredentials",
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"ArnEquals": {
                "ec2:SourceInstanceARN": (
                    f"arn:aws:ec2:{target['region']}:{target['account_id']}:"
                    f"instance/{instance_id}"
                )
            }},
        }],
    }

    def read_policy():
        try:
            return iam.get_role_policy(
                RoleName=role_name, PolicyName=policy_name,
            )["PolicyDocument"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                return None
            raise

    before = read_policy()
    if before is not None and before != document:
        raise ValueError("같은 이름의 다른 정책이 있습니다. 변경하지 않습니다.")
    changed = False
    if action == "iam_isolate" and before is None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name,
            PolicyDocument=json.dumps(document),
        )
        changed = True
    elif action == "iam_restore" and before is not None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        changed = True
    after = read_policy()
    expected_present = (
        True if action == "iam_isolate"
        else False if action == "iam_restore"
        else before is not None
    )
    return {
        "action": action, "instance_id": instance_id,
        "role_name": role_name, "policy_name": policy_name,
        "policy_present": after is not None,
        "policy_matches": after == document,
        "configuration_verified": (
            (after is not None) == expected_present
            and (after is None or after == document)
        ),
        "change_requested": changed,
    }


def handle_snapshot(ec2, action, event, target):
    instance_id = target["instance_id"]
    volume_id = target["evidence_volume_id"]
    if event.get("volume_id", volume_id) != volume_id:
        raise ValueError("등록된 증거 볼륨만 사용할 수 있습니다.")
    instance = get_instance(ec2, target)
    attached_volumes = [
        device["Ebs"]["VolumeId"]
        for device in instance.get("BlockDeviceMappings", [])
        if "Ebs" in device
    ]
    if volume_id not in attached_volumes:
        raise ValueError("대상 볼륨이 대상 인스턴스에 연결되어 있지 않습니다.")
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    if not any(
        attachment["InstanceId"] == instance_id and attachment["State"] == "attached"
        for attachment in volume["Attachments"]
    ):
        raise ValueError("볼륨 연결 상태가 다릅니다.")

    evidence_id = event.get("evidence_id", "")
    if not isinstance(evidence_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", evidence_id) is None:
        raise ValueError("영문·숫자·하이픈·밑줄로 evidence_id를 입력하세요.")
    tags = [
        {"Key": "R7:EvidenceId", "Value": evidence_id},
        {"Key": "R7:InstanceId", "Value": instance_id},
        {"Key": "R7:Purpose", "Value": "TCPDoS-Evidence"},
    ]
    create_args = {
        "VolumeId": volume_id,
        "Description": f"R7 TCPDoS evidence {evidence_id}",
        "TagSpecifications": [{"ResourceType": "snapshot", "Tags": tags}],
    }
    if action == "snapshot_check":
        check_dry_run(ec2.create_snapshot, **create_args)
        check_dry_run(
            ec2.create_tags, Resources=[instance_id],
            Tags=[{"Key": "R7:EvidenceId", "Value": evidence_id}],
        )
        return {
            "status": "SNAPSHOT_DRY_RUN_PASSED",
            "instance_id": instance_id, "volume_id": volume_id, "changed": False,
        }

    snapshots = []
    for page in ec2.get_paginator("describe_snapshots").paginate(
        OwnerIds=[target["account_id"]],
        Filters=[
            {"Name": "volume-id", "Values": [volume_id]},
            {"Name": "tag:R7:EvidenceId", "Values": [evidence_id]},
            {"Name": "tag:R7:InstanceId", "Values": [instance_id]},
            {"Name": "tag:R7:Purpose", "Values": ["TCPDoS-Evidence"]},
        ],
    ):
        snapshots.extend(page["Snapshots"])
    if len(snapshots) > 1:
        raise ValueError("동일한 증거 ID의 스냅샷이 여러 개입니다.")
    if action == "snapshot_status" and not snapshots:
        return {
            "status": "SNAPSHOT_NOT_FOUND", "evidence_id": evidence_id, "changed": False,
        }
    created = not bool(snapshots)
    snapshot = snapshots[0] if snapshots else ec2.create_snapshot(**create_args)
    snapshot_id = snapshot["SnapshotId"]
    print(json.dumps({
        "evidence_id": evidence_id, "snapshot_id": snapshot_id,
        "snapshot_created": created,
    }))
    if action == "snapshot_create":
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "R7:EvidenceId", "Value": evidence_id},
                {"Key": "R7:LastSnapshotId", "Value": snapshot_id},
            ],
        )
    return {
        "action": action, "instance_id": instance_id, "volume_id": volume_id,
        "evidence_id": evidence_id, "snapshot_id": snapshot_id,
        "snapshot_state": snapshot["State"],
        "snapshot_completed": snapshot["State"] == "completed",
        "snapshot_created": created,
        "instance_tags_written": action == "snapshot_create",
    }


CONNECTION_TEST_TEMPLATE = """python3 -u - <<'PY'
import socket
import subprocess

destination_ip = __DESTINATION_IP__
destination_port = __DESTINATION_PORT__
with socket.create_connection((destination_ip, destination_port), timeout=5) as connection:
    local_port = connection.getsockname()[1]
    connection.settimeout(3)
    filters = ["state", "established", "dst", destination_ip,
               "dport", "=", f":{destination_port}", "sport", "=", f":{local_port}"]
    print("TEST_CONNECTED:", connection.getsockname(), "->", connection.getpeername())
    before = subprocess.run(["ss", "-Htn"] + filters,
                            capture_output=True, text=True, check=True, timeout=5)
    print("BEFORE:", before.stdout.strip() or "NONE")
    if not before.stdout.strip():
        raise RuntimeError("Connection disappeared before termination")
    killed = subprocess.run(["ss", "-KHtn"] + filters,
                            capture_output=True, text=True, check=True, timeout=5)
    print("KILL_OUTPUT:", killed.stdout.strip() or "NONE")
    if not killed.stdout.strip():
        raise RuntimeError("No socket termination reported")
    after = subprocess.run(["ss", "-Htn"] + filters,
                           capture_output=True, text=True, check=True, timeout=5)
    print("AFTER:", after.stdout.strip() or "NONE")
    if after.stdout.strip():
        raise RuntimeError("Connection still exists")
    try:
        data = connection.recv(1024)
    except socket.timeout:
        raise RuntimeError("Receive timed out: termination not confirmed")
    except OSError as error:
        print("SOCKET_ERROR:", error)
    else:
        if data:
            raise RuntimeError("Unexpected data: termination not confirmed")
        print("SOCKET_EOF")
    print("TEST_PASSED")
PY
"""

CONNECTION_TERMINATE_TEMPLATE = """python3 -u - <<'PY'
import json
import subprocess

destination_ip = __DESTINATION_IP__
destination_port = __DESTINATION_PORT__
filters = ["state", "established", "dst", destination_ip, "dport", "=", f":{destination_port}"]

def run_ss(options):
    return subprocess.run(
        ["ss", options] + filters,
        capture_output=True, text=True, check=True, timeout=5,
    ).stdout

before = run_ss("-Htn")
killed = run_ss("-KHtn")
after = run_ss("-Htn")
result = {
    "scope": f"{destination_ip}:{destination_port}/TCP",
    "before_count": len(before.splitlines()),
    "closed_count": len(killed.splitlines()),
    "remaining_count": len(after.splitlines()),
    "scope_clear": not bool(after.strip()),
    "termination_observed": bool(killed.strip()),
}
print("R7_TERMINATION_RESULT=" + json.dumps(result))
if after.strip():
    raise RuntimeError("Target TCP connections still exist")
PY
"""


def termination_scope(target):
    return (
        f"{target['connection_destination_ip']}:"
        f"{target['connection_destination_port']}/TCP"
    )


def build_connection_script(target, mode):
    template = CONNECTION_TEST_TEMPLATE if mode == "test" else CONNECTION_TERMINATE_TEMPLATE
    return template.replace(
        "__DESTINATION_IP__", repr(target["connection_destination_ip"]),
    ).replace("__DESTINATION_PORT__", str(target["connection_destination_port"]))


def send_connection_command(session, mode, target):
    # SendCommand has no client token. Do not retry an ambiguous submission.
    ssm = session.client("ssm", config=Config(
        connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1},
    ))
    response = ssm.send_command(
        InstanceIds=[target["instance_id"]],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [build_connection_script(target, mode)],
            "executionTimeout": ["30"],
        },
        TimeoutSeconds=60, Comment=f"R7TCPDoSConnection:{mode}",
    )
    command_id = response["Command"]["CommandId"]
    print(json.dumps({
        "action": "ssm_command_sent", "mode": mode,
        "instance_id": target["instance_id"], "command_id": command_id,
    }))
    return {
        "status": "COMMAND_SENT", "instance_id": target["instance_id"],
        "command_id": command_id, "mode": mode,
        "termination_scope": termination_scope(target), "connection_verified": False,
    }


def read_connection_result(session, ec2, event, target):
    command_id = event.get("command_id", "")
    if not isinstance(command_id, str) or re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", command_id,
    ) is None:
        raise ValueError("정확한 command_id가 필요합니다.")
    try:
        result = session.client("ssm").get_command_invocation(
            CommandId=command_id, InstanceId=target["instance_id"],
        )
    except ClientError as error:
        if error.response["Error"]["Code"] != "InvocationDoesNotExist":
            raise
        return {
            "status": "NOT_VISIBLE_YET", "instance_id": target["instance_id"],
            "command_id": command_id, "connection_verified": False,
        }
    comments = {
        "R7TCPDoSConnection:test": "test",
        "R7TCPDoSConnection:terminate": "terminate",
        "R7TCPDoSConnection:isolate_terminate": "isolate_terminate",
    }
    if result.get("DocumentName") != "AWS-RunShellScript" or result.get("Comment") not in comments:
        raise ValueError("이 함수에서 발행한 연결 제어 명령이 아닙니다.")
    mode = comments[result["Comment"]]
    output = result.get("StandardOutputContent", "")
    successful = result["Status"] == "Success" and result.get("ResponseCode") == 0
    details = None
    for line in output.splitlines():
        if line.startswith("R7_TERMINATION_RESULT="):
            details = json.loads(line.split("=", 1)[1])
    if details is not None and (
        not isinstance(details, dict) or details.get("scope") != termination_scope(target)
    ):
        raise ValueError("명령 결과의 연결 종료 범위가 등록된 범위와 다릅니다.")
    test_passed = mode == "test" and successful and "TEST_PASSED" in output.splitlines()
    scope_clear = bool(
        mode in ("terminate", "isolate_terminate") and successful
        and details and details.get("scope_clear") is True
    )
    observed = bool(scope_clear and details.get("termination_observed") is True)
    group_check = handle_security_group(ec2, "check", target)
    isolation_present = all(
        row["after"] == [target["network_interfaces"][row["eni_id"]]["isolation_security_group"]]
        for row in group_check["network_interfaces"]
    )
    return {
        "status": result["Status"], "instance_id": target["instance_id"],
        "command_id": command_id, "mode": mode,
        "response_code": result.get("ResponseCode"),
        "stdout": output, "stderr": result.get("StandardErrorContent", ""),
        "test_passed": test_passed, "termination_scope": termination_scope(target),
        "termination_details": details, "termination_observed": observed,
        "scope_clear_at_command_time": scope_clear,
        "isolation_sg_present_now": isolation_present,
        "scope_cleanup_verified_with_sg": (
            mode == "isolate_terminate" and scope_clear and isolation_present
        ),
        "connection_verified": test_passed or observed,
    }


def handle_connection(session, ec2, action, event, context, target):
    if action == "connection_status":
        return read_connection_result(session, ec2, event, target)
    instance = get_instance(ec2, target)
    if (
        instance["State"]["Name"] != "running"
        or instance.get("PrivateIpAddress") != target["expected_private_ip"]
    ):
        raise ValueError("대상 인스턴스 상태 또는 IP가 등록된 설정과 다릅니다.")
    check = handle_security_group(ec2, "check", target)
    if not check["verified"]:
        raise RuntimeError("현재 보안 그룹 구성을 확인하지 못했습니다.")
    if action == "connection_test_send":
        if any(
            row["after"] != target["network_interfaces"][row["eni_id"]]["original_security_groups"]
            for row in check["network_interfaces"]
        ):
            raise ValueError("연결 생성 테스트는 SG 복구 상태에서 실행하세요.")
        return send_connection_command(session, "test", target)
    if action == "connection_terminate_send":
        return send_connection_command(session, "terminate", target)

    if context is not None and context.get_remaining_time_in_millis() < 15000:
        raise RuntimeError("남은 실행 시간이 부족합니다. 제한 시간을 60초로 설정하세요.")
    isolation = handle_security_group(ec2, "isolate", target)
    if not isolation["verified"]:
        return {
            "status": "SG_NOT_YET_VERIFIED", "instance_id": target["instance_id"],
            "security_group": isolation, "command_sent": False,
            "connection_verified": False,
        }
    try:
        sent = send_connection_command(session, "isolate_terminate", target)
    except Exception as error:
        print(json.dumps({
            "status": "SG_ISOLATED_COMMAND_SUBMISSION_UNCONFIRMED", "error": str(error),
        }))
        return {
            "status": "SG_ISOLATED_COMMAND_SUBMISSION_UNCONFIRMED",
            "instance_id": target["instance_id"], "security_group": isolation,
            "connection_verified": False, "error": str(error),
            "restore_action": "restore",
        }
    sent["status"] = "SG_ISOLATED_COMMAND_SENT"
    sent["security_group"] = isolation
    return sent


def nacl_configuration(target):
    settings = target.get("network_acl", {})
    acl_id = settings.get("id", "")
    if re.fullmatch(r"acl-(?:[0-9a-f]{8}|[0-9a-f]{17})", acl_id) is None:
        raise ValueError("등록된 NACL ID가 올바르지 않습니다.")
    subnet_id = settings.get("target_subnet_id", "")
    if re.fullmatch(r"subnet-(?:[0-9a-f]{8}|[0-9a-f]{17})", subnet_id) is None:
        raise ValueError("등록된 NACL 대상 서브넷이 올바르지 않습니다.")
    cidr = str(ipaddress.IPv4Network(target["expected_private_ip"] + "/32"))
    rules = []
    for egress, name in ((False, "ingress_rule_number"), (True, "egress_rule_number")):
        number = settings.get(name)
        if type(number) is not int or not 1 <= number <= 32766:
            raise ValueError("등록된 NACL 규칙 번호가 올바르지 않습니다.")
        rules.append({
            "RuleNumber": number, "Egress": egress, "Protocol": "-1",
            "RuleAction": "deny", "CidrBlock": cidr,
        })
    marker = {
        "Key": "R7:Nacl:" + target["instance_id"],
        "Value": "v1|" + cidr + "|in=" + str(rules[0]["RuleNumber"])
                 + "|out=" + str(rules[1]["RuleNumber"]),
    }
    return settings, rules, marker


def read_network_acl(ec2, target, settings):
    acls = ec2.describe_network_acls(NetworkAclIds=[settings["id"]])["NetworkAcls"]
    if len(acls) != 1 or acls[0]["NetworkAclId"] != settings["id"]:
        raise ValueError("등록된 NACL을 정확히 확인하지 못했습니다.")
    acl = acls[0]
    if acl.get("OwnerId") != target["account_id"] or acl.get("VpcId") != target["vpc_id"]:
        raise ValueError("NACL 계정 또는 VPC가 등록된 대상과 다릅니다.")
    return acl


def nacl_rule_at(acl, rule):
    matches = [entry for entry in acl["Entries"]
               if entry["Egress"] == rule["Egress"]
               and entry["RuleNumber"] == rule["RuleNumber"]]
    if len(matches) > 1:
        raise ValueError("동일한 방향과 번호의 NACL 규칙이 중복되었습니다.")
    return matches[0] if matches else None


def nacl_rule_matches(entry, expected):
    return (
        entry is not None
        and all(entry.get(key) == value for key, value in expected.items())
        and not any(key in entry for key in ("Ipv6CidrBlock", "PortRange", "IcmpTypeCode"))
    )


def inspect_nacl_ownership(acl, rules, marker):
    values = [tag["Value"] for tag in acl.get("Tags", []) if tag["Key"] == marker["Key"]]
    if len(values) > 1 or (values and values[0] != marker["Value"]):
        raise ValueError("NACL 소유 표시가 등록된 R7 설정과 다릅니다.")
    owned = bool(values)
    present = [nacl_rule_at(acl, rule) for rule in rules]
    conflicts = []
    for expected, entry in zip(rules, present):
        if entry is not None and (not owned or not nacl_rule_matches(entry, expected)):
            conflicts.append({
                "reason": "RULE_SLOT_NOT_OWNED_OR_CHANGED",
                "egress": expected["Egress"], "rule_number": expected["RuleNumber"],
                "entry": entry,
            })
    return owned, present, conflicts


def earlier_nacl_allow_rules(acl, rules):
    # A lower-numbered matching allow can override our deny, even for one port.
    conflicts = []
    for rule in rules:
        address = ipaddress.IPv4Network(rule["CidrBlock"]).network_address
        for entry in acl["Entries"]:
            if (entry["Egress"] == rule["Egress"]
                    and entry["RuleNumber"] < rule["RuleNumber"]
                    and entry["RuleAction"] == "allow"
                    and entry.get("CidrBlock")
                    and address in ipaddress.IPv4Network(entry["CidrBlock"])):
                conflicts.append({"reason": "EARLIER_ALLOW_MATCHES_TARGET", "entry": entry})
    return conflicts


def verify_nacl_target(ec2, target, settings, acl):
    instance = get_instance(ec2, target)
    if instance.get("PrivateIpAddress") != target["expected_private_ip"]:
        raise ValueError("NACL 대상의 현재 IP가 등록된 /32 주소와 다릅니다.")
    actual_enis = {item["NetworkInterfaceId"] for item in instance["NetworkInterfaces"]}
    if actual_enis != set(target["network_interfaces"]):
        raise ValueError("NACL 대상 ENI 구성이 등록된 설정과 다릅니다.")
    interfaces = get_registered_network_interfaces(ec2, target)
    for interface in interfaces.values():
        if interface.get("SubnetId") != settings["target_subnet_id"]:
            raise ValueError("NACL 대상 ENI 서브넷이 등록된 설정과 다릅니다.")
        if interface.get("Ipv6Addresses"):
            raise ValueError("IPv6 대상에는 이 IPv4 전용 NACL 기능을 적용할 수 없습니다.")
    associated = {item["SubnetId"] for item in acl["Associations"]}
    if settings["target_subnet_id"] not in associated:
        raise ValueError("등록된 NACL이 대상 서브넷에 연결되어 있지 않습니다.")


def nacl_permission_check(ec2, settings, rules, marker):
    for rule in rules:
        check_dry_run(ec2.create_network_acl_entry, NetworkAclId=settings["id"], **rule)
        check_dry_run(
            ec2.delete_network_acl_entry, NetworkAclId=settings["id"],
            RuleNumber=rule["RuleNumber"], Egress=rule["Egress"],
        )
    check_dry_run(ec2.create_tags, Resources=[settings["id"]], Tags=[marker])
    check_dry_run(ec2.delete_tags, Resources=[settings["id"]], Tags=[marker])


def nacl_result(acl, target, rules, marker, action, changed=False):
    owned, present, conflicts = inspect_nacl_ownership(acl, rules, marker)
    earlier = earlier_nacl_allow_rules(acl, rules)
    applied = owned and all(nacl_rule_matches(entry, rule)
                            for entry, rule in zip(present, rules)) and not earlier
    return {
        "action": action, "instance_id": target["instance_id"],
        "account_id": target["account_id"], "region": target["region"],
        "network_acl_id": acl["NetworkAclId"],
        "target_cidr": rules[0]["CidrBlock"],
        "associated_subnets": sorted(item["SubnetId"] for item in acl["Associations"]),
        "managed_rules": [
            {"expected": rule, "present": entry is not None,
             "matches": nacl_rule_matches(entry, rule), "actual": entry}
            for rule, entry in zip(rules, present)
        ],
        "owner_marker_present": owned, "identity_verified": True,
        "ready_for_apply": not conflicts and not earlier,
        "conflicts": conflicts + earlier,
        "nacl_isolated_configuration": applied,
        "change_requested": changed,
        "same_subnet_traffic_covered": False,
        "packet_blocking_verified": False,
        "scope": "IPv4 source on ingress / destination on egress of associated subnets",
    }


def handle_network_acl(ec2, action, target):
    settings, rules, marker = nacl_configuration(target)
    acl = read_network_acl(ec2, target, settings)
    owned, present, conflicts = inspect_nacl_ownership(acl, rules, marker)
    if action != "nacl_restore":
        verify_nacl_target(ec2, target, settings, acl)
    result = nacl_result(acl, target, rules, marker, action)
    if action == "nacl_check":
        result["status"] = "NACL_CHECKED"
        return result
    if conflicts:
        raise ValueError("NACL 규칙 충돌입니다. 기존 규칙을 덮어쓰거나 삭제하지 않습니다.")
    if action != "nacl_restore" and not result["ready_for_apply"]:
        raise ValueError("더 앞선 허용 규칙이 있어 등록된 NACL 차단 규칙을 적용할 수 없습니다.")
    if action == "nacl_dry_run":
        nacl_permission_check(ec2, settings, rules, marker)
        result.update(status="NACL_DRY_RUN_PASSED", changed=False)
        return result
    if action == "nacl_isolate" and result["nacl_isolated_configuration"]:
        result.update(status="NACL_RULES_APPLIED", configuration_verified=True)
        return result
    if action == "nacl_restore" and not owned and not any(present):
        result.update(status="NACL_RULES_RESTORED", configuration_verified=True)
        return result

    # Check both apply and recovery permissions before changing the shared ACL.
    # Recovery itself must work if the target is stopped, detached or unreachable.
    if action == "nacl_isolate":
        nacl_permission_check(ec2, settings, rules, marker)
    else:
        for rule, entry in zip(rules, present):
            if entry is not None:
                check_dry_run(ec2.delete_network_acl_entry, NetworkAclId=settings["id"],
                              RuleNumber=rule["RuleNumber"], Egress=rule["Egress"])
        check_dry_run(ec2.delete_tags, Resources=[settings["id"]], Tags=[marker])
    changed = False
    try:
        if action == "nacl_isolate" and not owned:
            changed = True
            ec2.create_tags(Resources=[settings["id"]], Tags=[marker])
        for rule in rules:
            current = read_network_acl(ec2, target, settings)
            current_owned, _, current_conflicts = inspect_nacl_ownership(current, rules, marker)
            if not current_owned or current_conflicts:
                raise ValueError("작업 도중 NACL 소유 표시 또는 규칙이 변경되었습니다.")
            if action == "nacl_isolate":
                verify_nacl_target(ec2, target, settings, current)
                if earlier_nacl_allow_rules(current, rules):
                    raise ValueError("작업 도중 더 앞선 허용 규칙이 추가되었습니다.")
            entry = nacl_rule_at(current, rule)
            if action == "nacl_isolate" and entry is None:
                changed = True
                ec2.create_network_acl_entry(NetworkAclId=settings["id"], **rule)
            elif action == "nacl_restore" and entry is not None:
                changed = True
                ec2.delete_network_acl_entry(NetworkAclId=settings["id"],
                                             RuleNumber=rule["RuleNumber"], Egress=rule["Egress"])
        after = read_network_acl(ec2, target, settings)
        after_owned, after_present, after_conflicts = inspect_nacl_ownership(after, rules, marker)
        if after_conflicts:
            raise ValueError("NACL 변경 후 등록된 규칙과 다른 규칙이 확인되었습니다.")
        if action == "nacl_restore" and not any(after_present):
            if after_owned:
                changed = True
                ec2.delete_tags(Resources=[settings["id"]], Tags=[marker])
            after = read_network_acl(ec2, target, settings)
        result = nacl_result(after, target, rules, marker, action, changed)
        if action == "nacl_isolate":
            verified = result["nacl_isolated_configuration"]
            result["status"] = "NACL_RULES_APPLIED" if verified else "NACL_CHANGE_NOT_YET_VERIFIED"
        else:
            verified = (not result["owner_marker_present"]
                        and not any(row["present"] for row in result["managed_rules"]))
            result["status"] = "NACL_RULES_RESTORED" if verified else "NACL_CHANGE_NOT_YET_VERIFIED"
        result["configuration_verified"] = verified
        return result
    except Exception as error:
        # Leave an owned partial deny in place. A separate restore can remove it;
        # reopening traffic on an apply failure would weaken containment.
        print(json.dumps({"status": "NACL_CHANGE_INCOMPLETE", "action": action,
                          "instance_id": target["instance_id"], "error": str(error)}))
        return {
            "action": action, "status": "NACL_CHANGE_INCOMPLETE",
            "instance_id": target["instance_id"], "network_acl_id": settings["id"],
            "target_cidr": rules[0]["CidrBlock"], "configuration_verified": False,
            "change_requested": changed, "packet_blocking_verified": False,
            "error": str(error), "recovery_action": "nacl_restore",
        }


def lambda_handler(event, context):
    if not isinstance(event, dict):
        raise ValueError("이벤트는 JSON 객체여야 합니다.")
    action = event.get("action", "check")
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError("지원하지 않는 action입니다.")
    target = resolve_target(event, action)
    session = get_session(target)
    if action.startswith("iam_"):
        return handle_iam(session, action, target)
    if action.startswith("nacl_"):
        ec2 = session.client(
            "ec2",
            config=Config(connect_timeout=3, read_timeout=5,
                          retries={"total_max_attempts": 1}),
        )
        return handle_network_acl(ec2, action, target)
    ec2 = session.client("ec2")
    if action.startswith("connection_") or action == "isolate_and_terminate_send":
        return handle_connection(session, ec2, action, event, context, target)
    if action.startswith("snapshot_"):
        return handle_snapshot(ec2, action, event, target)
    return handle_security_group(ec2, action, target)