# zero-trust-aws

Walkthrough: https://www.cybersecbella.com/articles/zta_aws/

A five-tool security automation toolkit that implements zero trust principles on AWS — from automated Security Group auditing to NIST SP 800-207 gap analysis.

---

## Tools

| Tool | File | What it does |
|---|---|---|
| SG Auditor | `auditor/sg_auditor.py` | Scans all regions for Security Groups open to `0.0.0.0/0` on ports 22/3389. Posts ASFF findings to Security Hub. |
| AI Rule Reviewer | `reviewer/sg_diff.py` | Diffs Security Group snapshots before/after Ansible hardening. Sends delta to Claude and returns structured findings. |
| CIS Hardening | `ansible/` | Hardens EC2 instances to CIS Level 2 benchmark via Ansible + ansible-lockdown. Runs pre/post OpenSCAP scans. |
| Zeek Analyzer | `zeek/analyzer.py` | Parses Zeek `conn.log` and `dns.log`. Detects lateral movement, data staging, and DNS-based C2 patterns. |
| Gap Analyzer | `gap_analyzer/nist_800_207.py` | Scores your AWS account against the 7 NIST SP 800-207 zero trust tenets. Generates a markdown report with AI-written remediation priorities. |

---

## Repo structure

```
zero-trust-aws/
├── auditor/
│   ├── sg_auditor.py
│   └── tests/
│       └── test_sg_auditor.py
├── reviewer/
│   ├── sg_diff.py
│   └── tests/
│       └── test_sg_diff.py
├── zeek/
│   ├── analyzer.py
│   ├── detections/
│   │   ├── lateral_movement.py
│   │   ├── data_staging.py
│   │   └── dns_entropy.py
│   └── tests/
│       ├── test_analyzer.py
│       └── fixtures/
├── gap_analyzer/
│   ├── nist_800_207.py
│   ├── controls/
│   │   └── aws_controls_map.py
│   └── tests/
│       └── test_gap_analyzer.py
├── ansible/
│   ├── site.yml
│   ├── inventory/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       ├── all.yml
│   │       └── ec2_ubuntu.yml
│   └── playbooks/
│       ├── harden.yml
│       ├── scan_pre.yml
│       ├── scan_post.yml
│       └── ai_review.yml
├── scripts/
│   └── setup_iam.sh
├── .github/
│   └── workflows/
│       ├── test.yml
│       └── audit.yml
├── requirements.txt
├── requirements.yml
├── ansible.cfg
└── .env.example
```

---

## Quickstart

### 1. Prerequisites

- Python 3.11+
- AWS CLI v2 (see [AWS CLI setup](#aws-cli-setup) below)
- Ansible 2.12+ (`pip install ansible`)
- An Anthropic API key for the AI reviewer and gap analyzer narrative

### 2. Install dependencies

```bash
pip install -r requirements.txt
ansible-galaxy install -r requirements.yml
```

### 3. Set up IAM permissions

```bash
chmod +x scripts/setup_iam.sh

./scripts/setup_iam.sh \
  --account-id YOUR_ACCOUNT_ID \
  --region us-east-1
```

### 4. Set your API key

```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-your-key-here' >> ~/.bashrc
source ~/.bashrc
```

### 5. Run the tests

```bash
pytest auditor/tests/     -v
pytest reviewer/tests/    -v
pytest zeek/tests/        -v
pytest gap_analyzer/tests/ -v
```

---

## AWS CLI setup

If you don't have the AWS CLI installed, follow these steps. All commands run in WSL (Ubuntu) or any Linux terminal.

### Install AWS CLI v2

```bash
# Install dependencies
sudo apt update && sudo apt install -y unzip curl

# Download the installer
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

# Unzip and install
unzip awscliv2.zip
sudo ./aws/install

# Verify
aws --version
# Expected: aws-cli/2.x.x Python/3.x.x Linux/...
```

### Get your access keys

1. Log into the AWS console at **console.aws.amazon.com**
2. Click your account name (top right) → **Security credentials**
3. Scroll to **Access keys** → **Create access key**
4. Choose **Command Line Interface (CLI)** → confirm → **Create**
5. Copy the **Access Key ID** and **Secret Access Key** — you won't see the secret again

### Configure the CLI

```bash
aws configure
```

Enter your values when prompted:

```
AWS Access Key ID:     YOUR_ACCESS_KEY_ID
AWS Secret Access Key: YOUR_SECRET_ACCESS_KEY
Default region name:   us-east-1
Default output format: json
```

### Verify it works

```bash
aws sts get-caller-identity
```

Should return your account ID, user ARN, and account alias as JSON.

### Set a default region in your shell

```bash
echo 'export AWS_DEFAULT_REGION=us-east-1' >> ~/.bashrc
source ~/.bashrc
```

---

## Deploying test EC2 instances

To test the toolkit against real infrastructure, deploy two minimal EC2 instances — one intentionally misconfigured (to generate findings) and one clean (as a baseline). Estimated cost: under $0.05 for a two-hour test.

> **Warning:** Run teardown commands immediately after testing. The bad Security Group has port 22 open to the internet.

### Set up environment variables

```bash
export AWS_DEFAULT_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### Create a VPC and subnet

```bash
# VPC
export VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.99.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=zt-test-vpc},{Key=Environment,Value=test}]' \
  --query Vpc.VpcId --output text)

aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support

# Subnet
export SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.99.1.0/24 \
  --availability-zone ${AWS_DEFAULT_REGION}a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=zt-test-subnet}]' \
  --query Subnet.SubnetId --output text)

aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch

# Internet gateway
export IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=zt-test-igw}]' \
  --query InternetGateway.InternetGatewayId --output text)

aws ec2 attach-internet-gateway \
  --internet-gateway-id $IGW_ID --vpc-id $VPC_ID

# Route table
export RTB_ID=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.main,Values=true" \
  --query "RouteTables[0].RouteTableId" --output text)

aws ec2 create-route \
  --route-table-id $RTB_ID \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW_ID
```

### Create Security Groups

```bash
# Bad SG — intentionally open (generates auditor findings)
export BAD_SG_ID=$(aws ec2 create-security-group \
  --group-name zt-bad-sg \
  --description "Intentionally open SG for zero-trust testing" \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=zt-bad-sg},{Key=Environment,Value=test}]' \
  --query GroupId --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $BAD_SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id $BAD_SG_ID --protocol tcp --port 3389 --cidr 0.0.0.0/0

# Good SG — correctly scoped (baseline)
export GOOD_SG_ID=$(aws ec2 create-security-group \
  --group-name zt-good-sg \
  --description "Correctly scoped SG for zero-trust testing" \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=zt-good-sg},{Key=Environment,Value=test}]' \
  --query GroupId --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $GOOD_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0
```

### Create an IAM instance profile for SSM

```bash
aws iam create-role \
  --role-name zt-test-ec2-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }' --tags Key=Project,Value=zero-trust-aws

aws iam attach-role-policy \
  --role-name zt-test-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

aws iam create-instance-profile \
  --instance-profile-name zt-test-ec2-profile

aws iam add-role-to-instance-profile \
  --instance-profile-name zt-test-ec2-profile \
  --role-name zt-test-ec2-role

sleep 15   # wait for IAM to propagate
```

### Launch the instances

```bash
# Get the latest Ubuntu 22.04 AMI for your region
export AMI_ID=$(aws ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id \
  --query Parameter.Value --output text)

# Misconfigured target instance
export BAD_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $SUBNET_ID \
  --security-group-ids $BAD_SG_ID \
  --iam-instance-profile Name=zt-test-ec2-profile \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=zt-target},{Key=Environment,Value=test},{Key=Role,Value=app}]' \
  --query "Instances[0].InstanceId" --output text)

# Clean baseline instance
export GOOD_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $SUBNET_ID \
  --security-group-ids $GOOD_SG_ID \
  --iam-instance-profile Name=zt-test-ec2-profile \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=zt-baseline},{Key=Environment,Value=test},{Key=Role,Value=app}]' \
  --query "Instances[0].InstanceId" --output text)

# Wait for both to be running
aws ec2 wait instance-running \
  --instance-ids $BAD_INSTANCE_ID $GOOD_INSTANCE_ID

echo "Instances running: $BAD_INSTANCE_ID  $GOOD_INSTANCE_ID"
```

### Verify SSM connectivity (wait ~2 minutes after launch)

```bash
aws ssm describe-instance-information \
  --query "InstanceInformationList[*].{ID:InstanceId,Ping:PingStatus}" \
  --output table
```

Both instances should show `PingStatus: Online` before running any tools.

### Teardown — run immediately after testing

```bash
# Terminate instances
aws ec2 terminate-instances \
  --instance-ids $BAD_INSTANCE_ID $GOOD_INSTANCE_ID
aws ec2 wait instance-terminated \
  --instance-ids $BAD_INSTANCE_ID $GOOD_INSTANCE_ID

# Delete Security Groups
aws ec2 delete-security-group --group-id $BAD_SG_ID
aws ec2 delete-security-group --group-id $GOOD_SG_ID

# Delete VPC networking
aws ec2 detach-internet-gateway \
  --internet-gateway-id $IGW_ID --vpc-id $VPC_ID
aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID
aws ec2 delete-subnet --subnet-id $SUBNET_ID
aws ec2 delete-vpc --vpc-id $VPC_ID

# Delete IAM resources
aws iam remove-role-from-instance-profile \
  --instance-profile-name zt-test-ec2-profile \
  --role-name zt-test-ec2-role
aws iam delete-instance-profile \
  --instance-profile-name zt-test-ec2-profile
aws iam detach-role-policy \
  --role-name zt-test-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam delete-role --role-name zt-test-ec2-role

echo "Teardown complete"
```

---

## Usage

### SG Auditor

```bash
# Dry run — print findings without posting to Security Hub
python3 auditor/sg_auditor.py --dry-run --regions us-east-1

# Real run — post findings to Security Hub
python3 auditor/sg_auditor.py --regions us-east-1 --output findings.json
```

### Gap Analyzer

```bash
# Score your account against NIST SP 800-207
python3 gap_analyzer/nist_800_207.py \
  --region us-east-1 \
  --output report.md \
  --json-output scores.json
```

### Zeek Analyzer

```bash
python3 zeek/analyzer.py \
  --conn /path/to/conn.log \
  --dns  /path/to/dns.log \
  --min-severity medium \
  --output findings.ndjson
```

### AI Rule Reviewer

```bash
python3 reviewer/sg_diff.py \
  --before /tmp/sg_before.json \
  --after  /tmp/sg_after.json \
  --instance my-instance \
  --role app \
  --env prod \
  --owner platform-team
```

### Ansible CIS Hardening

```bash
# Pre-scan
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/scan_pre.yml

# Dry run
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/harden.yml --check

# Harden
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/harden.yml

# Post-scan
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/scan_post.yml
```

---

## IAM permissions

The minimum IAM permissions required are documented in `scripts/setup_iam.sh`. The script creates a least-privilege `ZeroTrustAuditPolicy` covering all five tools.

Never run any of these tools with `AdministratorAccess`.

---

## CI/CD

Two GitHub Actions workflows are included:

**`test.yml`** — runs the full pytest suite on every pull request. No AWS credentials required — all boto3 calls are mocked with moto.

**`audit.yml`** — runs the SG auditor daily via OIDC federation (no stored secrets). Fails the workflow and sends a GitHub notification if findings exist.

To enable the daily audit:

1. Run `setup_iam.sh` with `--github-org` and `--github-repo` to create the OIDC role
2. Add `AWS_ROLE_ARN` as a GitHub secret
3. Add `AWS_REGION` as a GitHub variable

---

## NIST SP 800-207 tenets

The gap analyzer scores your account against all seven zero trust tenets:

| # | Tenet | Key AWS controls |
|---|---|---|
| 1 | All resources identified | AWS Config, SSM Inventory |
| 2 | All communication secured | VPC Flow Logs, ACM, Macie |
| 3 | Per-session access | IAM roles, MFA, STS |
| 4 | Dynamic policy | Security Groups, GuardDuty, WAF |
| 5 | Continuous monitoring | CloudTrail, Inspector, CloudWatch |
| 6 | Dynamic auth/authz | Access Analyzer, credential rotation |
| 7 | Data collection | S3 logging, Config conformance packs |

---

## Contributing

This repo accompanies a specific article. If you find a bug or have a suggestion, open an issue — PRs welcome.

---

## Security

If you discover a security vulnerability in the tools themselves, please open a GitHub issue marked `[SECURITY]` rather than a public PR.

---

## License

MIT
