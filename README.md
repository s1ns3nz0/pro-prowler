# Pro-Prowler

NIST SP 800-30 IaC risk assessment for Terraform infrastructure — powered by 81 Prowler-derived security checks and AI-driven business context analysis.

## What It Does

Pro-Prowler scans your Terraform plan and tells you:
- **Security misconfigurations** across S3, EC2, RDS, IAM, ECS, VPC, Lambda, and 30+ AWS services
- **Risk severity** using NIST SP 800-30 methodology
- **Compliance gaps** against PCI-DSS, ISO 27001, ISO 27701, SOC 2, GDPR, and ISMS-P
- **AI-powered business context** — asset criticality, data classification, attack path narratives
- **Gate recommendation** — pass/warn/block for CI pipelines

## Quick Start

```bash
# 1. Clone
git clone https://github.com/s1ns3nz0/pro-prowler.git
cd pro-prowler

# 2. Configure
cp .env.example .env
vim .env                  # Set ANTHROPIC_API_KEY (required)

# 3. Start dashboard server
docker compose up -d

# 4. Install CLI
pip install .

# 5. Scan your infrastructure
pro-prowler scan /path/to/your/terraform/dir

# 6. View results
open http://localhost:8000/dashboard
```

## Commands

### `pro-prowler scan <dir>`

One command — runs `terraform init`, `plan`, exports JSON, runs 9-agent assessment pipeline, pushes results to the dashboard server.

```bash
# Basic scan
pro-prowler scan ./infra

# Scan a specific branch
pro-prowler scan ./infra --branch production

# With AWS profile
pro-prowler scan ./infra --profile prod-account

# With tfvars
pro-prowler scan ./infra --var-file environments/prod.tfvars

# With business context documents
pro-prowler scan ./infra \
  --context-file security-policy.pdf \
  --context-source "PCI-DSS Level 1 e-commerce platform"
```

### `pro-prowler assess <plan.json>`

Assess a pre-built Terraform plan JSON file. Useful for CI pipelines where `terraform plan` already ran.

```bash
terraform show -json plan.out > plan.json
pro-prowler assess plan.json --repository org/repo --commit $SHA
```

### `pro-prowler configure`

Interactive setup — saves server URL, LLM API key, and AWS profile to `~/.pro-prowler/config.yaml`. Optional if you use `.env`.

```bash
pro-prowler configure
```

### `pro-prowler serve`

Start the dashboard server without Docker (for development).

```bash
pro-prowler serve --data-dir ./data --port 8000
```

## Configuration

### `.env` file

```bash
# Where the CLI sends results (default: http://localhost:8000)
PRO_PROWLER_SERVER=http://localhost:8000

# Server listen port
PORT=8000

# LLM Provider (anthropic, openai, ollama)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# GitHub token (optional — for repo scanning and fix PRs)
GITHUB_TOKEN=ghp_...
```

### AWS Credentials

Pro-Prowler uses the standard AWS credential chain for `terraform plan`:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS profile (`~/.aws/credentials` + `~/.aws/config`)
3. IAM instance role (EC2/ECS)

```bash
# Use a specific AWS profile
pro-prowler scan ./infra --profile production

# Or set environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
pro-prowler scan ./infra
```

## CI Integration

### Option 1: CLI in CI (recommended)

```yaml
- name: Install Pro-Prowler
  run: pip install git+https://github.com/s1ns3nz0/pro-prowler.git

- name: Assess
  run: |
    terraform show -json plan.out > plan.json
    pro-prowler assess plan.json \
      --repository ${{ github.repository }} \
      --commit ${{ github.sha }}
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    PRO_PROWLER_SERVER: https://your-server.com
```

### Option 2: GitHub Action

```yaml
- uses: s1ns3nz0/pro-prowler/.github/action@main
  with:
    plan-file: infra/plan.json
    server: https://your-server.com
    threshold: 60
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Option 3: Webhook (auto-pull)

Add to your existing workflow:
```yaml
- run: terraform show -json plan.out > plan.json
- uses: actions/upload-artifact@v4
  with:
    name: terraform-plan
    path: plan.json
```

Register the webhook in the Pro-Prowler dashboard under CI Integration.

## Architecture

```
CLI (pro-prowler scan)          Dashboard Server (Docker)
┌──────────────────────┐       ┌──────────────────────────┐
│ terraform plan       │       │ FastAPI + Jinja2          │
│ 9-Agent Pipeline:    │──────>│ Project management        │
│   IaC Parser         │ POST  │ Snapshot storage          │
│   Cloud Misconfig    │ /api/ │ Compliance views          │
│   Context Analysis   │       │ AI chat assistant         │
│   Risk Analysis      │       │ GitHub fix PRs            │
│   Impact Assessment  │       │ Webhook receiver          │
│   Compliance Mapping │       │ CI Integration snippets   │
│   Change Management  │       └──────────────────────────┘
│   Report Generation  │
└──────────────────────┘
```

### 9-Agent Pipeline

| Agent | Purpose |
|---|---|
| **IaC Parser** | Terraform plan JSON to normalized resource inventory |
| **Cloud Misconfiguration** | 81 Prowler-derived checks with remediation and attack scenarios |
| **Repository Analysis** | Clone repos, detect tech stack, extract app context |
| **Context Analysis (AI)** | Business context from docs — asset criticality, data classification |
| **Risk Analysis** | NIST SP 800-30 risk determination + AI attack path narratives |
| **Impact Assessment** | 4-dimension business impact with context-aware severity |
| **Compliance Mapping** | Gap analysis across 6 frameworks (PCI-DSS, ISO 27001, GDPR, ...) |
| **Change Management** | Gate recommendation (pass/warn/block) + audit trail |
| **Report Generation** | HTML dashboard, JSON snapshot, XML report |

### Security Checks

81 checks across 15 AWS services:

| Service | Checks | Examples |
|---|---|---|
| S3 | 6 | Public access block, encryption, versioning, logging |
| EC2 | 5 | EBS encryption, IMDSv2, public IP, monitoring |
| RDS | 7 | Encryption at rest, Multi-AZ, deletion protection, IAM auth |
| IAM | 8 | MFA, password policy, unused credentials, wildcard permissions |
| ECS | 4 | Container insights, root user, logging, network mode |
| VPC | 3 | Flow logs, security group egress, default VPC |
| ELB | 5 | HTTPS listener, WAF, access logging, TLS policy |
| Lambda | 4 | VPC deployment, environment encryption, tracing |
| CloudFront | 3 | HTTPS, WAF, logging |
| DynamoDB | 3 | Encryption, PITR, auto-scaling |
| + 5 more | 33 | API Gateway, ElastiCache, Secrets Manager, SNS/SQS, Monitoring |

### Compliance Frameworks

| Framework | Controls |
|---|---|
| PCI-DSS | Payment card industry data security |
| ISO 27001 | Information security management |
| ISO 27701 | Privacy information management |
| SOC 2 | Service organization controls |
| GDPR | General Data Protection Regulation |
| ISMS-P | Korean information security management |

## CLI Options Reference

```
pro-prowler scan [OPTIONS] [TERRAFORM_DIR]

  -p, --profile TEXT        AWS profile
  -b, --branch TEXT         Git branch to scan
  --var-file PATH           Terraform .tfvars file (repeatable)
  --repository TEXT         Repository name (auto-detected from git remote)
  --commit TEXT             Git commit hash
  --context-file PATH       Business context doc (.txt/.md/.pdf/.docx, repeatable)
  --context-source TEXT     Inline business context (repeatable)
  --no-context              Skip AI analysis (basic scan only)
  --threshold INT           Quality score threshold (default: 60)
  --server TEXT             Override server URL from .env
  --local-report            Also generate local HTML/JSON reports
  -o, --output-dir PATH     Report output directory (default: ./reports)
  -v, --verbose             Show detailed agent logs
```

## Requirements

- Python 3.11+
- Terraform (for `scan` command)
- Docker (for dashboard server)
- Anthropic/OpenAI API key (for AI features)
