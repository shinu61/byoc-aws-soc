import boto3
def handler(event, context):
    sts = boto3.client('sts')
    me = sts.get_caller_identity()
    return {"whoami": me["Arn"]}
