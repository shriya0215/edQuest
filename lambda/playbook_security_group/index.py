"""
playbook_security_group/index.py — Playbook 2: Permissive Security Group Remediation
NIST Phases: Containment → Eradication
Trigger: SNS alarm, direct invoke {"security_group_id":"sg-xxx"}, or AWS Config.
"""
import json, logging, os
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2   = boto3.client("ec2")
sns   = boto3.client("sns")
TOPIC = os.environ["SNS_TOPIC_ARN"]
ENV   = os.environ.get("ENVIRONMENT", "unknown")

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

def get_sg(sg_id):
    resp = ec2.describe_security_groups(GroupIds=[sg_id])
    return resp["SecurityGroups"][0] if resp["SecurityGroups"] else None

def find_permissive(sg):
    """Return list of (permission_dict, cidr) for all open-world ingress rules."""
    bad = []
    for perm in sg.get("IpPermissions", []):
        for r in perm.get("IpRanges", []):
            if r.get("CidrIp") in OPEN_CIDRS:
                bad.append((perm, r["CidrIp"], False))
        for r in perm.get("Ipv6Ranges", []):
            if r.get("CidrIpv6") in OPEN_CIDRS:
                bad.append((perm, r["CidrIpv6"], True))
    return bad

def build_ip_perm(perm, cidr, is_ipv6):
    p = {"IpProtocol": perm["IpProtocol"]}
    if perm["IpProtocol"] != "-1":
        p["FromPort"] = perm.get("FromPort", 0)
        p["ToPort"]   = perm.get("ToPort", 65535)
    p["Ipv6Ranges" if is_ipv6 else "IpRanges"] = [{"CidrIpv6" if is_ipv6 else "CidrIp": cidr}]
    return p

def revoke_rules(sg_id, bad_rules):
    revoked, failed = [], []
    for perm, cidr, is_ipv6 in bad_rules:
        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[build_ip_perm(perm, cidr, is_ipv6)])
            revoked.append(f"port={perm.get('FromPort','ALL')}/{perm['IpProtocol']} from {cidr}")
        except ClientError as e:
            failed.append(str(e))
    return revoked, failed

def remediate(sg_id):
    inc  = f"PB2-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    sg   = get_sg(sg_id)
    if not sg:
        return {"incidentId": inc, "sg": sg_id, "success": False, "error": "SG not found"}

    bad              = find_permissive(sg)
    revoked, failed  = revoke_rules(sg_id, bad) if bad else ([], [])

    # Verify
    sg_after   = get_sg(sg_id)
    remaining  = find_permissive(sg_after) if sg_after else bad
    ok         = not remaining and not failed

    status = "REMEDIATED" if ok else "PARTIAL – MANUAL ACTION REQUIRED"
    msg = (
        f"Playbook 2 – SG Remediation\nSG: {sg_id} ({sg.get('GroupName','?')})\nIncident: {inc}\n"
        f"Status: {status}\nRevoked ({len(revoked)}): " + (", ".join(revoked) or "none") +
        (f"\nFailed: {failed}" if failed else "") +
        ("" if ok else "\n\nManual: Console → EC2 → Security Groups → Inbound Rules → remove 0.0.0.0/0.")
    )
    sns.publish(TopicArn=TOPIC, Subject=f"[PB2] {status}: {sg_id}", Message=msg)
    logger.info("SG remediation %s for %s", status, sg_id)
    return {"incidentId": inc, "sg": sg_id, "success": ok, "revoked": revoked}

def extract_sgs(event):
    if "security_group_id" in event:
        return [event["security_group_id"]]
    if "resourceId" in event:
        return [event["resourceId"]]
    for rec in event.get("Records", []):
        msg  = json.loads(rec.get("Sns", {}).get("Message", "{}"))
        sg_id = msg.get("detail", {}).get("requestParameters", {}).get("groupId")
        if sg_id:
            return [sg_id]
    # Fallback: full region scan
    pages = ec2.get_paginator("describe_security_groups").paginate()
    return [sg["GroupId"] for p in pages for sg in p["SecurityGroups"] if find_permissive(sg)]

def lambda_handler(event, _ctx):
    logger.info("PB2 invoked: %s", json.dumps(event))
    sgs     = extract_sgs(event)
    results = [remediate(sg) for sg in sgs]
    return {"statusCode": 200, "results": results}
