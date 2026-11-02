import os, time, boto3
from botocore.exceptions import ClientError

TABLE = os.environ["DEDUP_TABLE"]
WINDOW = int(os.environ.get("DEDUP_WINDOW_SECONDS", "600"))
_t = boto3.resource("dynamodb").Table(TABLE)


def lambda_handler(event, context):
    key = f"{event.get('source_ip') or '-'}#{event.get('runbook_id') or '-'}"
    now = int(time.time())
    try:
        _t.put_item(
            Item={"dedup_key": key, "expires_at": now + WINDOW},
            ConditionExpression="attribute_not_exists(dedup_key) OR expires_at < :now",
            ExpressionAttributeValues={":now": now},
        )
        return {"duplicate": False}
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return {"duplicate": True}
        return {"duplicate": False}  