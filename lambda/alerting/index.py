"""
alerting/index.py — Security Alerting Lambda
Triggered by SNS (CloudWatch Alarm). Enriches the alarm with CloudTrail
context and publishes a structured alert back to SNS for email delivery.
"""
import json, logging, os
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns      = boto3.client("sns")
trail    = boto3.client("cloudtrail")
TOPIC    = os.environ["SNS_TOPIC_ARN"]
ENV      = os.environ.get("ENVIRONMENT", "unknown")

# Alarm name → severity / MITRE / action mapping
ALARM_MAP = {
    "root-account-usage": ("CRITICAL", "T1078.004", "Rotate root credentials immediately."),
    "s3-public-exposure":  ("HIGH",     "T1530",     "Invoke Playbook 1 – public-bucket-remediation."),
    "sg-open-ingress":     ("HIGH",     "T1562.007", "Invoke Playbook 2 – security-group-remediation."),
    "iam-policy-change":   ("MEDIUM",   "T1098",     "Review IAM change for privilege escalation."),
}

CLOUDTRAIL_EVENTS = {
    "root-account-usage": ["ConsoleLogin"],
    "s3-public-exposure":  ["PutBucketAcl", "PutBucketPolicy"],
    "sg-open-ingress":     ["AuthorizeSecurityGroupIngress"],
    "iam-policy-change":   ["PutRolePolicy", "AttachRolePolicy"],
}

def get_context(alarm_name: str):
    for key, val in ALARM_MAP.items():
        if key in alarm_name.lower():
            return key, *val
    return "unknown", "LOW", "N/A", "Investigate manually."

def enrich(alarm_key: str) -> str:
    events = CLOUDTRAIL_EVENTS.get(alarm_key, [])
    lines  = []
    for ev_name in events[:2]:
        try:
            resp = trail.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": ev_name}],
                MaxResults=1)
            for ev in resp.get("Events", []):
                d = json.loads(ev.get("CloudTrailEvent", "{}"))
                lines.append(f"  API: {ev_name} | User: {d.get('userIdentity',{}).get('arn','?')} | IP: {d.get('sourceIPAddress','?')}")
        except ClientError:
            pass
    return "\n".join(lines) or "  (no recent events found)"

def lambda_handler(event, _ctx):
    record   = event["Records"][0]["Sns"]
    alarm    = json.loads(record.get("Message", "{}"))
    name     = alarm.get("AlarmName", "unknown")
    inc_id   = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    key, sev, mitre, action = get_context(name)

    body = (
        f"{'='*60}\n"
        f"SECURITY ALERT [{sev}] | {inc_id}\n"
        f"{'='*60}\n"
        f"Alarm   : {name}\n"
        f"State   : {alarm.get('NewStateValue','ALARM')}\n"
        f"Reason  : {alarm.get('NewStateReason','')}\n"
        f"MITRE   : {mitre}\n"
        f"Action  : {action}\n"
        f"{'─'*60}\n"
        f"CloudTrail Evidence:\n{enrich(key)}\n"
        f"{'='*60}"
    )

    resp = sns.publish(TopicArn=TOPIC,
                       Subject=f"[{sev}] {name} | {inc_id}",
                       Message=body)
    logger.info("Alert published: %s", resp["MessageId"])
    return {"statusCode": 200, "incidentId": inc_id, "severity": sev}
