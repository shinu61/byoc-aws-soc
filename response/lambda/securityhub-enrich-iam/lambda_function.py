import os
import boto3


ROLE_ARN = os.environ["CROSS_ACCOUNT_ROLE_ARN"]
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def allows_all(document):
    statements = document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        if statement.get("Effect") == "Allow" and "*" in actions:
            return True

    return False


def lambda_handler(event, context):
    principal_type = event.get("principal_type")

    if principal_type in ("IAMUser", "User"):
        principal_name = event.get("user_name")
        is_user = True

    elif principal_type in ("AssumedRole", "Role"):
        principal_name = event.get("role_name")
        is_user = False

    else:
        event.update({
            "attached_policies": [],
            "is_admin_like": None,
            "key_last_used_at": None,
            "last_used_service": None,
            "enrichment_status": "not_applicable"
        })
        return event

    if not principal_name:
        raise ValueError("IAM 사용자 또는 역할 이름이 없습니다.")

    credentials = boto3.client("sts").assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="SecurityHubIamEnrichment"
    )["Credentials"]

    iam = boto3.client(
        "iam",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    if is_user:
        managed = iam.list_attached_user_policies(
            UserName=principal_name
        ).get("AttachedPolicies", [])

        inline = iam.list_user_policies(
            UserName=principal_name
        ).get("PolicyNames", [])

        get_inline = lambda name: iam.get_user_policy(
            UserName=principal_name,
            PolicyName=name
        )["PolicyDocument"]

    else:
        managed = iam.list_attached_role_policies(
            RoleName=principal_name
        ).get("AttachedPolicies", [])

        inline = iam.list_role_policies(
            RoleName=principal_name
        ).get("PolicyNames", [])

        get_inline = lambda name: iam.get_role_policy(
            RoleName=principal_name,
            PolicyName=name
        )["PolicyDocument"]

    attached_policies = [
        policy["PolicyName"]
        for policy in managed
    ] + [
        f"inline:{name}"
        for name in inline
    ]

    is_admin_like = any(
        policy["PolicyArn"] == ADMIN_ARN
        for policy in managed
    )

    if not is_admin_like:
        for policy in managed:
            information = iam.get_policy(
                PolicyArn=policy["PolicyArn"]
            )["Policy"]

            document = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=information["DefaultVersionId"]
            )["PolicyVersion"]["Document"]

            if allows_all(document):
                is_admin_like = True
                break

    if not is_admin_like:
        is_admin_like = any(
            allows_all(get_inline(name))
            for name in inline
        )

    key_last_used_at = None
    last_used_service = None
    access_key_id = event.get("access_key_id")

    if (
        is_user
        and access_key_id
        and not access_key_id.startswith("ASIA")
    ):
        usage = iam.get_access_key_last_used(
            AccessKeyId=access_key_id
        ).get("AccessKeyLastUsed", {})

        last_used_date = usage.get("LastUsedDate")

        if last_used_date:
            key_last_used_at = last_used_date.isoformat()

        last_used_service = usage.get("ServiceName")

        if last_used_service == "N/A":
            last_used_service = None

    event.update({
        "attached_policies": attached_policies,
        "is_admin_like": is_admin_like,
        "key_last_used_at": key_last_used_at,
        "last_used_service": last_used_service,
        "enrichment_status": "success"
    })

    return event