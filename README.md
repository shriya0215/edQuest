# Cloud Security Incident Response Runbook
### Automated Alerting on AWS | NIST IR Lifecycle

---

## 📌 Project Overview
A cloud security incident response runbook for a simulated AWS environment.  
Covers **Detection → Analysis → Containment → Eradication → Recovery** phases  
using AWS CloudFormation, Lambda, SNS, and CloudWatch.

---

## 🗂️ Project Structure
```
cloud-security-runbook/
├── cfn/
│   ├── stack-core.yaml           # SNS, S3 (vulnerable), IAM Role
│   └── stack-lambda-alarms.yaml  # Lambda functions + CloudWatch Alarms
└── lambda/
    ├── alerting/index.py                  # Enriched security alert publisher
    ├── playbook_public_bucket/index.py    # Playbook 1: S3 public exposure fix
    └── playbook_security_group/index.py   # Playbook 2: Permissive SG rule fix
```

---

## ⚙️ Technologies Used
| Technology | Purpose |
|---|---|
| Python 3.12 | Lambda function logic |
| boto3 | AWS SDK — S3, EC2, SNS, CloudTrail |
| AWS CloudFormation (YAML) | Infrastructure as Code |
| AWS Lambda | Serverless automated remediation |
| AWS SNS | Alert notifications (email) |
| AWS CloudWatch | Alarm triggers on suspicious API calls |
| MITRE ATT&CK | Threat classification framework |

---

## 🔁 Architecture Flow
```
Suspicious API Call
      ↓
CloudWatch Alarm
      ↓
SNS Topic
      ↓
alerting/index.py  →  Enriched Email Alert (with CloudTrail context)
      ↓
Playbook Lambda    →  Auto-remediation + Report
```

---

## 🛡️ Automated Playbooks

### Playbook 1 — S3 Public Bucket Remediation
- Enables Block Public Access (all 4 settings)
- Removes public-allow ACL grants
- Deletes public-allow bucket policies
- Sends remediation report via SNS

### Playbook 2 — Permissive Security Group Remediation
- Detects ingress rules open to `0.0.0.0/0` or `::/0`
- Revokes all open-world rules
- Verifies fix and sends report via SNS

---

## 🚀 Deployment Steps
```bash
# 1. Deploy core stack
aws cloudformation deploy \
  --template-file cfn/stack-core.yaml \
  --stack-name sec-runbook-core \
  --parameter-overrides AlertEmail=your@email.com \
  --capabilities CAPABILITY_NAMED_IAM

# 2. Deploy Lambda + Alarms
aws cloudformation deploy \
  --template-file cfn/stack-lambda-alarms.yaml \
  --stack-name sec-runbook-functions \
  --capabilities CAPABILITY_NAMED_IAM
```

---

## 📋 NIST IR Lifecycle Mapping
| Phase | Implementation |
|---|---|
| Detection | CloudWatch Metric Filters + Alarms |
| Analysis | CloudTrail enrichment in alerting Lambda |
| Containment | Playbook 1 & 2 auto-remediation |
| Eradication | Policy/ACL/SG rule deletion |
| Recovery | SNS report + manual guidelines in code |
