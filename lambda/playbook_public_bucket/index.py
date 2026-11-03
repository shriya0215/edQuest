"""
playbook_public_bucket/index.py — Playbook 1: S3 Public Exposure Remediation
NIST Phases: Containment → Eradication
Trigger: SNS alarm, direct invoke {"bucket_name":"<name>"}, or AWS Config.
"""
import json, logging, os
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3    = boto3.client("s3")
sns   = boto3.client("sns")
TOPIC = os.environ["SNS_TOPIC_ARN"]
ENV   = os.environ.get("ENVIRONMENT", "unknown")

PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

def block_public_access(bucket):
    s3.put_bucket_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        })
    return "Block Public Access enabled."

def remove_public_acl(bucket):
    resp   = s3.get_bucket_acl(Bucket=bucket)
    grants = [g for g in resp["Grants"] if g.get("Grantee", {}).get("URI") not in PUBLIC_URIS]
    if len(grants) == len(resp["Grants"]):
        return "ACL: no public grants found."
    s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner": resp["Owner"], "Grants": grants})
    return f"ACL: removed {len(resp['Grants']) - len(grants)} public grant(s)."

def delete_public_policy(bucket):
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        if any(s.get("Effect") == "Allow" and s.get("Principal") in ("*", {"AWS": "*"})
               for s in policy.get("Statement", [])):
            s3.delete_bucket_policy(Bucket=bucket)
            return "Bucket policy deleted (contained public Allow)."
        return "Policy: no public Allow statements."
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return "Policy: none exists."
        raise

def remediate(bucket):
    inc    = f"PB1-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    steps  = []
    ok     = True
    for fn in [block_public_access, remove_public_acl, delete_public_policy]:
        try:
            steps.append(f"  ✅ {fn.__name__}: {fn(bucket)}")
        except ClientError as e:
            steps.append(f"  ❌ {fn.__name__}: {e}")
            ok = False

    status = "REMEDIATED" if ok else "PARTIAL – MANUAL ACTION REQUIRED"
    msg = (
        f"Playbook 1 – S3 Remediation\nBucket: {bucket}\nIncident: {inc}\n"
        f"Status: {status}\n" + "\n".join(steps) +
        ("" if ok else "\n\nManual: Console → S3 → Permissions → Block all public access.")
    )
    sns.publish(TopicArn=TOPIC, Subject=f"[PB1] {status}: {bucket}", Message=msg)
    logger.info("Remediation done for %s: %s", bucket, status)
    return {"incidentId": inc, "bucket": bucket, "success": ok, "steps": steps}

def extract_bucket(event):
    if "bucket_name" in event:
        return [event["bucket_name"]]
    if "resourceId" in event:
        return [event["resourceId"]]
    for rec in event.get("Records", []):
        msg = json.loads(rec.get("Sns", {}).get("Message", "{}"))
        b   = msg.get("detail", {}).get("requestParameters", {}).get("bucketName")
        if b:
            return [b]
    return [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

def lambda_handler(event, _ctx):
    logger.info("PB1 invoked: %s", json.dumps(event))
    buckets = extract_bucket(event)
    results = [remediate(b) for b in buckets]
    return {"statusCode": 200, "results": results}
