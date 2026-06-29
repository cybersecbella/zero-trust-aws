#!/usr/bin/env bash
# =============================================================================
# scripts/setup_iam.sh
#
# Creates the least-privilege IAM policy and an optional role for the
# zero-trust-aws toolkit. Covers all five tools:
#   - sg_auditor        (read SGs, post to Security Hub)
#   - gap_analyzer      (read-only across many services)
#   - sg_diff reviewer  (read Secrets Manager for the Anthropic API key)
#   - zeek analyzer     (read S3 bucket containing Zeek logs)
#   - ansible hardening (SSM on target instances — separate instance profile)
#
# Usage:
#   ./scripts/setup_iam.sh [options]
#
# Options:
#   --account-id   ACCOUNT_ID     AWS account ID (required)
#   --region       REGION         AWS region (default: us-east-1)
#   --policy-name  NAME           IAM policy name (default: ZeroTrustAuditPolicy)
#   --role-name    NAME           IAM role name to attach policy to (optional)
#   --github-org   ORG            GitHub org for OIDC trust (optional, for CI)
#   --github-repo  REPO           GitHub repo for OIDC trust (optional, for CI)
#   --zeek-bucket  BUCKET         S3 bucket containing Zeek logs (optional)
#   --secret-arn   ARN            Secrets Manager ARN for Anthropic key (optional)
#   --dry-run                     Print policy JSON; do not create resources
#   --help                        Show this message
#
# Examples:
#   # Create policy only
#   ./scripts/setup_iam.sh --account-id 123456789012
#
#   # Create policy + OIDC role for GitHub Actions
#   ./scripts/setup_iam.sh \
#     --account-id 123456789012 \
#     --github-org  my-org \
#     --github-repo zero-trust-aws \
#     --zeek-bucket my-zeek-logs-bucket \
#     --secret-arn  arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/anthropic/key
#
# IAM permissions needed to run this script:
#   iam:CreatePolicy, iam:CreatePolicyVersion
#   iam:CreateRole, iam:AttachRolePolicy (if creating a role)
#   iam:GetOpenIDConnectProvider, iam:CreateOpenIDConnectProvider (if using OIDC)
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
ACCOUNT_ID=""
REGION="us-east-1"
POLICY_NAME="ZeroTrustAuditPolicy"
ROLE_NAME=""
GITHUB_ORG=""
GITHUB_REPO=""
ZEEK_BUCKET=""
SECRET_ARN=""
DRY_RUN=false

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --account-id)  ACCOUNT_ID="$2";  shift 2 ;;
    --region)      REGION="$2";      shift 2 ;;
    --policy-name) POLICY_NAME="$2"; shift 2 ;;
    --role-name)   ROLE_NAME="$2";   shift 2 ;;
    --github-org)  GITHUB_ORG="$2";  shift 2 ;;
    --github-repo) GITHUB_REPO="$2"; shift 2 ;;
    --zeek-bucket) ZEEK_BUCKET="$2"; shift 2 ;;
    --secret-arn)  SECRET_ARN="$2";  shift 2 ;;
    --dry-run)     DRY_RUN=true;     shift   ;;
    --help)
      sed -n '/^# Usage/,/^# ===/p' "$0" | grep -v "^# ===" | sed 's/^# //'
      exit 0 ;;
    *) error "Unknown argument: $1" ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────────
[[ -z "$ACCOUNT_ID" ]] && error "--account-id is required."
[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || error "--account-id must be a 12-digit number."

if [[ -n "$GITHUB_ORG" || -n "$GITHUB_REPO" ]]; then
  [[ -z "$GITHUB_ORG"  ]] && error "--github-org is required when --github-repo is set."
  [[ -z "$GITHUB_REPO" ]] && error "--github-repo is required when --github-org is set."
  [[ -z "$ROLE_NAME"   ]] && ROLE_NAME="ZeroTrustGitHubActionsRole"
fi

# ── Build optional S3 statement ───────────────────────────────────────────────
if [[ -n "$ZEEK_BUCKET" ]]; then
  S3_STATEMENT=$(cat <<EOJSON
    ,{
      "Sid": "ZeekLogReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::${ZEEK_BUCKET}",
        "arn:aws:s3:::${ZEEK_BUCKET}/*"
      ]
    }
EOJSON
)
else
  S3_STATEMENT=""
  warn "No --zeek-bucket provided; S3 read access for Zeek logs not included."
fi

# ── Build optional Secrets Manager statement ──────────────────────────────────
if [[ -n "$SECRET_ARN" ]]; then
  SM_STATEMENT=$(cat <<EOJSON
    ,{
      "Sid": "AnthropicKeyRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "${SECRET_ARN}"
    }
EOJSON
)
else
  SM_STATEMENT=""
  warn "No --secret-arn provided; Secrets Manager access for Anthropic key not included."
fi

# ── Build policy JSON ─────────────────────────────────────────────────────────
POLICY_JSON=$(cat <<EOJSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SgAuditorEc2Read",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityHubWrite",
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchImportFindings",
        "securityhub:GetFindings",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerIamRead",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListAccessKeys",
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListVirtualMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerCloudTrailRead",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerGuardDutyRead",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:ListFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerConfigRead",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConformancePacks",
        "config:GetConformancePackComplianceDetails",
        "config:DescribeConfigRules",
        "config:GetComplianceDetailsByConfigRule"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerMonitoringRead",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricStatistics",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerSecurityServicesRead",
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListFindings",
        "macie2:GetMacieSession",
        "macie2:ListFindings",
        "accessanalyzer:ListAnalyzers",
        "accessanalyzer:ListFindings",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GapAnalyzerSsoRead",
      "Effect": "Allow",
      "Action": [
        "sso:ListInstances",
        "sso-admin:ListInstances",
        "sso-admin:DescribePermissionSet",
        "identitystore:ListUsers"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SsmInventoryRead",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeInstanceInformation",
        "ssm:ListInventoryEntries",
        "ssm:GetInventory"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsRead",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribePolicyTypes",
        "organizations:ListPolicies",
        "organizations:DescribeOrganization"
      ],
      "Resource": "*"
    },
    {
      "Sid": "StsCallerIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
    ${S3_STATEMENT}
    ${SM_STATEMENT}
  ]
}
EOJSON
)

# ── Dry run — print and exit ──────────────────────────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  echo ""
  info "DRY RUN — policy that would be created:"
  echo ""
  echo "$POLICY_JSON" | python3 -m json.tool
  echo ""
  info "No AWS resources were created."
  exit 0
fi

# ── Check AWS CLI ─────────────────────────────────────────────────────────────
command -v aws >/dev/null 2>&1 || error "AWS CLI not found. Install it first: https://aws.amazon.com/cli/"
aws sts get-caller-identity --output text --query Account >/dev/null 2>&1 \
  || error "No valid AWS credentials found. Run 'aws configure' or export credentials."

CALLER=$(aws sts get-caller-identity --query '[Account,Arn]' --output text)
info "Caller: $CALLER"
info "Account: $ACCOUNT_ID  Region: $REGION"
echo ""

# ── Create / update IAM policy ────────────────────────────────────────────────
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

if aws iam get-policy --policy-arn "$POLICY_ARN" >/dev/null 2>&1; then
  warn "Policy '$POLICY_NAME' already exists — creating new version."
  # Keep only the 4 most recent non-default versions (IAM limit is 5)
  VERSIONS=$(aws iam list-policy-versions \
    --policy-arn "$POLICY_ARN" \
    --query 'Versions[?!IsDefaultVersion].VersionId' \
    --output text)
  for v in $VERSIONS; do
    info "  Deleting old policy version $v ..."
    aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$v"
  done
  aws iam create-policy-version \
    --policy-arn "$POLICY_ARN" \
    --policy-document "$POLICY_JSON" \
    --set-as-default \
    --output text >/dev/null
  success "Policy '$POLICY_NAME' updated."
else
  info "Creating IAM policy '$POLICY_NAME' ..."
  aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "$POLICY_JSON" \
    --description "Least-privilege policy for zero-trust-aws toolkit" \
    --tags Key=Project,Value=zero-trust-aws Key=ManagedBy,Value=setup_iam.sh \
    --output text >/dev/null
  success "Policy '$POLICY_NAME' created: $POLICY_ARN"
fi

# ── Create OIDC provider for GitHub Actions (if requested) ────────────────────
if [[ -n "$GITHUB_ORG" ]]; then
  OIDC_URL="https://token.actions.githubusercontent.com"
  OIDC_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
  THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"

  if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" \
       >/dev/null 2>&1; then
    info "GitHub OIDC provider already exists."
  else
    info "Creating GitHub Actions OIDC provider ..."
    aws iam create-open-id-connect-provider \
      --url "$OIDC_URL" \
      --client-id-list "sts.amazonaws.com" \
      --thumbprint-list "$THUMBPRINT" \
      --output text >/dev/null
    success "OIDC provider created."
  fi

  # ── Create role with OIDC trust policy ────────────────────────────────────
  TRUST_POLICY=$(cat <<EOJSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "${OIDC_ARN}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_ORG}/${GITHUB_REPO}:*"
        }
      }
    }
  ]
}
EOJSON
)

  if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
    warn "Role '$ROLE_NAME' already exists — updating trust policy."
    aws iam update-assume-role-policy \
      --role-name "$ROLE_NAME" \
      --policy-document "$TRUST_POLICY" >/dev/null
  else
    info "Creating IAM role '$ROLE_NAME' ..."
    aws iam create-role \
      --role-name "$ROLE_NAME" \
      --assume-role-policy-document "$TRUST_POLICY" \
      --description "GitHub Actions OIDC role for zero-trust-aws toolkit" \
      --tags Key=Project,Value=zero-trust-aws Key=ManagedBy,Value=setup_iam.sh \
      --output text >/dev/null
    success "Role '$ROLE_NAME' created."
  fi

  info "Attaching policy to role ..."
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN"
  success "Policy attached to role '$ROLE_NAME'."

  ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo "  Add this to your GitHub Actions workflow:"
  echo ""
  echo "    permissions:"
  echo "      id-token: write"
  echo "      contents: read"
  echo ""
  echo "    - uses: aws-actions/configure-aws-credentials@v4"
  echo "      with:"
  echo "        role-to-assume: ${ROLE_ARN}"
  echo "        aws-region: ${REGION}"
  echo "────────────────────────────────────────────────────────"
fi

# ── Also attach SecurityAudit managed policy for gap_analyzer ─────────────────
if [[ -n "$ROLE_NAME" ]]; then
  info "Attaching AWS SecurityAudit managed policy ..."
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/SecurityAudit" || \
    warn "Could not attach SecurityAudit policy — check permissions."
  success "SecurityAudit managed policy attached."
fi

echo ""
success "Setup complete."
info "Policy ARN: $POLICY_ARN"
[[ -n "$ROLE_NAME" ]] && info "Role ARN:   arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
info "Next steps:"
echo "  1. Verify the policy with: aws iam simulate-principal-policy"
echo "  2. Test the auditor:       python3 auditor/sg_auditor.py --dry-run --regions ${REGION}"
echo "  3. Test the gap analyzer:  python3 gap_analyzer/nist_800_207.py --dry-run --region ${REGION}"