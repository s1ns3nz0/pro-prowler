"""Repository Analysis Agent — scans repo structure, detects tools, extracts context."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.schemas import (
    AppInsight,
    DetectedEnvironment,
    DetectedTool,
    GovernanceInsight,
    RepoAnalysis,
    RepoAnalysisInput,
    RepoAnalysisOutput,
)

logger = logging.getLogger(__name__)

# Config files to read for business context
_CONFIG_FILES = [
    "package.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Cargo.toml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env.example",
    "README.md",
    "README",
]

# Data-related dependency keywords → data type indicators
_DATA_INDICATORS: dict[str, str] = {
    "stripe": "payment processing (PCI scope)",
    "braintree": "payment processing (PCI scope)",
    "adyen": "payment processing (PCI scope)",
    "paypal": "payment processing (PCI scope)",
    "bcrypt": "password hashing (auth data)",
    "passport": "authentication (user credentials)",
    "jsonwebtoken": "JWT auth tokens",
    "jwt": "JWT auth tokens",
    "oauth": "OAuth authentication",
    "sequelize": "ORM (database access)",
    "prisma": "ORM (database access)",
    "sqlalchemy": "ORM (database access)",
    "django": "web framework with ORM",
    "mongoose": "MongoDB ODM",
    "typeorm": "ORM (database access)",
    "redis": "cache/session store",
    "celery": "async task queue",
    "boto3": "AWS SDK (cloud API access)",
    "aws-sdk": "AWS SDK (cloud API access)",
    "pg": "PostgreSQL database (structured data store)",
    "postgres": "PostgreSQL database (structured data store)",
    "mysql2": "MySQL database (structured data store)",
    "mysql": "MySQL database (structured data store)",
    "sendgrid": "email service (PII in transit)",
    "twilio": "SMS/communications (PII)",
    "sentry": "error tracking (may capture PII)",
    "elasticsearch": "search engine (indexed data)",
    "kafka": "event streaming",
    "rabbitmq": "message queue",
    "grpc": "RPC framework",
    "graphql": "API query language",
    "multer": "file upload handling",
    "sharp": "image processing",
    "puppeteer": "browser automation",
    "selenium": "browser automation",
    "cryptography": "encryption library",
    "pycryptodome": "encryption library",
    "hipaa": "health data compliance",
    "gdpr": "privacy compliance",
    "pci": "payment card compliance",
}

# Environment directory name patterns
_ENV_PATTERNS = [
    "prod", "production", "prd",
    "staging", "stg", "stage",
    "dev", "development",
    "test", "testing", "qa",
    "sandbox", "demo",
]


def _clone_repo(repository: str, target: Path) -> bool:
    """Try to clone a repo. Returns False on failure."""
    import os
    import subprocess

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        url = f"https://x-access-token:{token}@github.com/{repository}.git"
    else:
        url = f"https://github.com/{repository}.git"

    try:
        subprocess.run(
            ["git", "clone", "--depth=1", url, str(target)],
            check=True, capture_output=True, timeout=30,
        )
        return True
    except Exception as e:
        logger.warning("Failed to clone %s: %s", repository, e)
        return False


def _detect_tools(repo_dir: Path) -> list[DetectedTool]:
    """Detect IaC and infrastructure tools in the repo."""
    tools: list[DetectedTool] = []

    # Terraform
    tf_files = list(repo_dir.rglob("*.tf"))
    if tf_files:
        paths = [str(f.relative_to(repo_dir)) for f in tf_files[:10]]
        tools.append(DetectedTool(
            name="terraform", paths=paths, assessed=True,
        ))

    # Terragrunt
    tg_files = list(repo_dir.rglob("terragrunt.hcl"))
    if tg_files:
        paths = [str(f.relative_to(repo_dir)) for f in tg_files[:5]]
        tools.append(DetectedTool(
            name="terragrunt", paths=paths, assessed=True,
        ))

    # CloudFormation
    for pattern in ["*.template", "*.template.json", "*.template.yaml"]:
        cf_files = list(repo_dir.rglob(pattern))
        if cf_files:
            paths = [str(f.relative_to(repo_dir)) for f in cf_files[:5]]
            tools.append(DetectedTool(
                name="cloudformation", paths=paths, assessed=False,
            ))
            break

    # Pulumi
    pulumi_files = list(repo_dir.rglob("Pulumi.yaml"))
    if pulumi_files:
        paths = [str(f.relative_to(repo_dir)) for f in pulumi_files]
        tools.append(DetectedTool(
            name="pulumi", paths=paths, assessed=False,
        ))

    # Docker
    dockerfiles = list(repo_dir.rglob("Dockerfile"))
    if dockerfiles:
        paths = [str(f.relative_to(repo_dir)) for f in dockerfiles[:5]]
        tools.append(DetectedTool(
            name="docker", paths=paths, assessed=False,
        ))

    # Kubernetes
    k8s_patterns = ["*.yaml", "*.yml"]
    for p in k8s_patterns:
        for f in repo_dir.rglob(p):
            try:
                content = f.read_text(errors="ignore")[:500]
                if "apiVersion:" in content and "kind:" in content:
                    tools.append(DetectedTool(
                        name="kubernetes",
                        paths=[str(f.relative_to(repo_dir))],
                        assessed=False,
                    ))
                    break
            except Exception:
                continue
        else:
            continue
        break

    return tools


def _detect_environments(repo_dir: Path) -> list[DetectedEnvironment]:
    """Detect environment directories."""
    envs: list[DetectedEnvironment] = []
    seen: set[str] = set()

    for d in repo_dir.iterdir():
        if not d.is_dir():
            continue
        name_lower = d.name.lower()
        for pattern in _ENV_PATTERNS:
            if pattern in name_lower and name_lower not in seen:
                envs.append(DetectedEnvironment(
                    name=d.name,
                    path=str(d.relative_to(repo_dir)),
                ))
                seen.add(name_lower)
                break

    # Check for environments/ or envs/ directory
    for env_dir_name in ["environments", "envs", "env"]:
        env_dir = repo_dir / env_dir_name
        if env_dir.is_dir():
            for d in env_dir.iterdir():
                if d.is_dir() and d.name.lower() not in seen:
                    envs.append(DetectedEnvironment(
                        name=d.name,
                        path=str(d.relative_to(repo_dir)),
                    ))
                    seen.add(d.name.lower())

    return envs


def _extract_app_insight(
    repo_dir: Path, repo_name: str,
) -> AppInsight:
    """Extract business context from config files."""
    tech_stack: list[str] = []
    dependencies: list[str] = []
    data_indicators: list[str] = []
    config_files_found: list[str] = []
    description = ""

    for config_name in _CONFIG_FILES:
        # Search root and one level of subdirectories
        candidates = [repo_dir / config_name]
        for subdir in repo_dir.iterdir():
            if subdir.is_dir() and not subdir.name.startswith("."):
                candidates.append(subdir / config_name)

        config_path = None
        for c in candidates:
            if c.exists():
                config_path = c
                break
        if config_path is None:
            continue

        rel = str(config_path.relative_to(repo_dir))
        config_files_found.append(rel)
        try:
            content = config_path.read_text(errors="ignore")
        except Exception:
            continue

        if config_name == "package.json":
            tech_stack.append("Node.js")
            try:
                pkg = json.loads(content)
                all_deps = {}
                all_deps.update(pkg.get("dependencies", {}))
                all_deps.update(pkg.get("devDependencies", {}))
                dependencies = list(all_deps.keys())[:20]
                if pkg.get("description"):
                    description = pkg["description"]
            except json.JSONDecodeError:
                pass

        elif config_name == "requirements.txt":
            tech_stack.append("Python")
            for line in content.splitlines():
                dep = line.strip().split("==")[0].split(">=")[0].lower()
                if dep and not dep.startswith("#"):
                    dependencies.append(dep)

        elif config_name == "pyproject.toml":
            tech_stack.append("Python")

        elif config_name == "go.mod":
            tech_stack.append("Go")

        elif config_name == "pom.xml":
            tech_stack.append("Java")

        elif config_name == "Gemfile":
            tech_stack.append("Ruby")

        elif config_name == "Cargo.toml":
            tech_stack.append("Rust")

        elif config_name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            tech_stack.append("Docker")

        elif config_name == "README.md" and not description:
            lines = content.splitlines()
            for line in lines[1:6]:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    description = stripped[:200]
                    break

    # Detect data indicators from dependencies
    for dep in dependencies:
        dep_lower = dep.lower()
        for keyword, indicator in _DATA_INDICATORS.items():
            if keyword in dep_lower:
                if indicator not in data_indicators:
                    data_indicators.append(indicator)

    return AppInsight(
        repo=repo_name,
        tech_stack=list(set(tech_stack)),
        dependencies=dependencies[:20],
        data_indicators=data_indicators,
        description=description,
    )


# Governance document file patterns
_GOVERNANCE_PATTERNS = [
    "*.md", "*.txt", "*.pdf", "*.docx", "*.rst",
]
_GOVERNANCE_KEYWORDS = [
    "policy", "isms", "governance", "security",
    "privacy", "classification", "compliance",
    "data-handling", "access-control", "incident",
    "acceptable-use", "risk-management", "soc",
    "pci", "gdpr", "iso27001", "iso27701", "hipaa",
]


def _extract_governance_insight(
    repo_dir: Path, repo_name: str,
) -> GovernanceInsight:
    """Extract governance/policy context from a governance repo."""
    docs_found: list[str] = []
    data_classification_rules: list[str] = []
    compliance_scope_rules: list[str] = []
    security_policies: list[str] = []
    content_parts: list[str] = []

    # Find governance documents by keyword matching
    for pattern in _GOVERNANCE_PATTERNS:
        for f in sorted(repo_dir.rglob(pattern)):
            fname = f.name.lower()
            if any(kw in fname for kw in _GOVERNANCE_KEYWORDS):
                rel = str(f.relative_to(repo_dir))
                docs_found.append(rel)

                # Read content (first 2000 chars for context)
                try:
                    text = f.read_text(errors="ignore")[:2000]
                except Exception:
                    continue

                content_parts.append(f"[{rel}]\n{text}")
                text_lower = text.lower()

                # Extract rules heuristically
                if any(w in text_lower for w in [
                    "classif", "confidential", "restricted",
                    "internal", "public",
                ]):
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped and len(stripped) > 20:
                            if any(w in stripped.lower() for w in [
                                "classif", "confidential",
                                "restricted", "pii", "sensitive",
                            ]):
                                data_classification_rules.append(
                                    stripped[:150],
                                )

                if any(w in text_lower for w in [
                    "pci", "gdpr", "iso", "soc", "hipaa",
                    "compliance", "scope",
                ]):
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped and len(stripped) > 20:
                            if any(w in stripped.lower() for w in [
                                "pci", "gdpr", "iso", "soc",
                                "scope", "requirement",
                            ]):
                                compliance_scope_rules.append(
                                    stripped[:150],
                                )

                if any(w in text_lower for w in [
                    "policy", "shall", "must", "require",
                ]):
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped and any(w in stripped.lower() for w in [
                            "shall", "must", "required",
                            "prohibited", "encrypt",
                        ]):
                            security_policies.append(
                                stripped[:150],
                            )

    # Build summary from all content
    summary = "\n\n".join(content_parts[:5])
    if len(summary) > 3000:
        summary = summary[:3000]

    return GovernanceInsight(
        repo=repo_name,
        documents_found=docs_found[:20],
        data_classification_rules=data_classification_rules[:10],
        compliance_scope_rules=compliance_scope_rules[:10],
        security_policies=security_policies[:10],
        raw_content_summary=summary,
    )


def _build_structure_summary(
    tools: list[DetectedTool],
    envs: list[DetectedEnvironment],
    insights: list[AppInsight],
) -> str:
    """Build a human-readable structure summary."""
    parts: list[str] = []

    tool_names = [t.name for t in tools]
    assessed = [t.name for t in tools if t.assessed]
    not_assessed = [t.name for t in tools if not t.assessed]

    parts.append(f"Detected tools: {', '.join(tool_names) or 'none'}")
    if assessed:
        parts.append(f"Assessed: {', '.join(assessed)}")
    if not_assessed:
        parts.append(
            f"Not assessed: {', '.join(not_assessed)} "
            f"(parsers not yet available)"
        )
    if envs:
        env_names = [e.name for e in envs]
        parts.append(f"Environments: {', '.join(env_names)}")
    if insights:
        for i in insights:
            if i.tech_stack:
                parts.append(
                    f"{i.repo}: {', '.join(i.tech_stack)}"
                )
            if i.data_indicators:
                parts.append(
                    f"  Data: {', '.join(i.data_indicators)}"
                )

    return ". ".join(parts)


class RepoAnalysisAgent(BaseAgent):
    name = "repo_analysis"
    critical = False  # Non-critical — pipeline works without it

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, RepoAnalysisInput):
            return ValidationResult(
                valid=False, error="Expected RepoAnalysisInput",
            )
        return ValidationResult(valid=True)

    def assess(
        self, input_data: RepoAnalysisInput,
    ) -> RepoAnalysisOutput:
        repository = input_data.repository
        linked_repos = input_data.linked_repos

        all_tools: list[DetectedTool] = []
        all_envs: list[DetectedEnvironment] = []
        all_insights: list[AppInsight] = []
        all_governance: list[GovernanceInsight] = []
        all_config_files: list[str] = []

        # Build list: main repo + linked repos with types
        repos_to_scan: list[tuple[str, str]] = []
        if repository:
            repos_to_scan.append((repository, "iac"))
        for lr in linked_repos:
            repos_to_scan.append((lr.repository, lr.repo_type))

        work_dir = Path(tempfile.mkdtemp(prefix="repo-analysis-"))
        try:
            for repo, repo_type in repos_to_scan:
                if not repo:
                    continue
                repo_dir = work_dir / repo.replace("/", "_")
                if not _clone_repo(repo, repo_dir):
                    logger.warning(
                        "Skipping %s — clone failed", repo,
                    )
                    continue

                # IaC repo: detect tools + environments
                if repo == repository:
                    tools = _detect_tools(repo_dir)
                    all_tools.extend(tools)
                    envs = _detect_environments(repo_dir)
                    all_envs.extend(envs)

                # Application repos: extract app context
                if repo_type in ("application", "iac"):
                    insight = _extract_app_insight(repo_dir, repo)
                    all_insights.append(insight)
                    all_config_files.extend(
                        f"{repo}:{f}" for f in _CONFIG_FILES
                        if (repo_dir / f).exists()
                    )

                # Governance repos: extract policy docs
                if repo_type == "governance":
                    gov = _extract_governance_insight(
                        repo_dir, repo,
                    )
                    all_governance.append(gov)
                    all_config_files.extend(
                        f"{repo}:{d}"
                        for d in gov.documents_found
                    )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

        summary = _build_structure_summary(
            all_tools, all_envs, all_insights,
        )

        analysis = RepoAnalysis(
            repository=repository,
            structure_summary=summary,
            detected_tools=all_tools,
            environments=all_envs,
            app_insights=all_insights,
            governance_insights=all_governance,
            config_files_read=all_config_files,
        )

        logger.info(
            "Repo analysis: %d tools, %d envs, "
            "%d app insights, %d governance docs "
            "from %d repos",
            len(all_tools), len(all_envs),
            len(all_insights), len(all_governance),
            len(repos_to_scan),
        )

        return RepoAnalysisOutput(analysis=analysis)
