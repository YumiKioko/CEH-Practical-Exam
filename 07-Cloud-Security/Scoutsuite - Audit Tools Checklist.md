  

# ☁️ ScoutSuite Utilities for Cloud Security Auditing
  
This document includes:

1. ✅ Cloud Audit Checklist (based on ScoutSuite findings)
2. ⚙️ CI/CD Pipeline Automation Script
3. 📚 CIS Benchmark Mapping Guide
 
---
 
## ✅ 1. Cloud Audit Checklist
  
### Identity and Access Management (IAM)

- [ ] MFA enabled for all users

- [ ] Root account not used

- [ ] No unused access keys

- [ ] IAM roles use least privilege

- [ ] No wildcard permissions (`*:*`)

 
### Storage (S3, GCS, Azure Blobs)

- [ ] No public READ or WRITE access

- [ ] Encryption at rest enabled

- [ ] Logging enabled

- [ ] Versioning enabled

- [ ] Lifecycle policies in place

  
### Compute (EC2, Azure VMs, GCE)

- [ ] No public IPs unless necessary

- [ ] Hardened AMIs/images

- [ ] SSH/RDP access restricted

- [ ] Instances tagged and named

- [ ] Up-to-date patching
  
### Networking

- [ ] No 0.0.0.0/0 for SSH, RDP

- [ ] Security Groups/NSGs use least privilege

- [ ] VPC flow logs enabled

- [ ] Subnet segmentation used
 
### Logging and Monitoring

- [ ] CloudTrail/Activity Logs enabled in all regions

- [ ] Logs sent to centralized storage/SIEM

- [ ] Log file validation enabled

- [ ] Alerts for high-risk actions
 

### Secrets and Encryption

- [ ] KMS encryption used

- [ ] Key rotation enabled

- [ ] No hardcoded credentials

- [ ] Secret scanning in CI/CD

---

## ⚙️ 2. CI/CD Pipeline Script (ScoutSuite + JSON Output)

  ### GitLab CI Example
  
```yaml

audit_cloud:

  image: python:3.9

  script:

    - pip install git+https://github.com/nccgroup/ScoutSuite.git

    - aws configure set aws_access_key_id $AWS_KEY

    - aws configure set aws_secret_access_key $AWS_SECRET

    - python -m ScoutSuite.scout aws --report-dir audit-results

  artifacts:

    paths:

      - audit-results/

    expire_in: 1 week

```

### GitHub Actions Example
 
```yaml

name: Cloud Audit

on:

  workflow_dispatch:
  
jobs:

  scoutsuite:

    runs-on: ubuntu-latest

    steps:

      - name: Checkout

        uses: actions/checkout@v3

      - name: Set up Python

        uses: actions/setup-python@v4

        with:

          python-version: '3.9'

      - name: Install ScoutSuite

        run: pip install git+https://github.com/nccgroup/ScoutSuite.git

      - name: Run ScoutSuite (AWS)

        run: |

          aws configure set aws_access_key_id ${{ secrets.AWS_KEY }}

          aws configure set aws_secret_access_key ${{ secrets.AWS_SECRET }}

          python -m ScoutSuite.scout aws --report-dir audit-results

      - name: Upload Results

        uses: actions/upload-artifact@v3

        with:

          name: scoutsuite-report

          path: audit-results/

```

  

---

## 📚 3. CIS Benchmark Mapping
  
| ScoutSuite Finding                  | CIS Control Reference               |
|--------------------------------------|--------------------------------------|
| MFA not enabled                      | CIS AWS 1.5 / Azure 1.1 / GCP 1.1    |
| Root account in use                  | CIS AWS 1.3                          |
| S3 bucket publicly accessible        | CIS AWS 2.1                          |
| CloudTrail not multi-region          | CIS AWS 4.1 / GCP 2.1                 |
| Open Security Group (0.0.0.0/0)      | CIS AWS 5.1                          |
| No log file validation               | CIS AWS 4.4                          |
| No encryption on storage             | CIS AWS 2.2 / Azure 6.2               |
| Key rotation not enabled              | CIS AWS 3.4 / Azure 5.2 / GCP 3.3     |
| Unused IAM keys                      | CIS AWS 1.20                         |
| No tagging of resources              | Best Practice (CIS 2.5 optional)     |

**Note**: Use this mapping as a guideline to prioritize findings against the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/).
  
---
 
## 🧩 Integrations & Automation Tips

  
- Use the JSON output for custom dashboards
- Integrate with SIEM for alerting on config drift
- Auto-upload reports to S3 with versioning
- Add ScoutSuite as a gate in Terraform pipelines
  
---
 