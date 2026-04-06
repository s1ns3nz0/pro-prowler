"""CLI entry point for Pro-Prowler."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import click
import yaml

from iac_risk import __version__

CONFIG_DIR = Path.home() / ".pro-prowler"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


# --- Config Management ---


def _load_user_config() -> dict:
    """Load ~/.pro-prowler/config.yaml."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}


def _save_user_config(cfg: dict) -> None:
    """Write ~/.pro-prowler/config.yaml."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)


def _resolve_config() -> dict:
    """Resolve config from file + env vars. Env vars override file."""
    cfg = _load_user_config()
    # Env var overrides
    if os.environ.get("PRO_PROWLER_SERVER"):
        cfg["server"] = os.environ["PRO_PROWLER_SERVER"]
    if os.environ.get("LLM_PROVIDER"):
        cfg["llm_provider"] = os.environ["LLM_PROVIDER"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cfg["anthropic_api_key"] = os.environ["ANTHROPIC_API_KEY"]
    if os.environ.get("OPENAI_API_KEY"):
        cfg["openai_api_key"] = os.environ["OPENAI_API_KEY"]
    if os.environ.get("OLLAMA_BASE_URL"):
        cfg["ollama_base_url"] = os.environ["OLLAMA_BASE_URL"]
    if os.environ.get("AWS_PROFILE"):
        cfg["aws_profile"] = os.environ["AWS_PROFILE"]
    if os.environ.get("GITHUB_TOKEN"):
        cfg["github_token"] = os.environ["GITHUB_TOKEN"]
    return cfg


def _apply_config_to_env(cfg: dict) -> None:
    """Push config values into environment for LLM client and other services."""
    provider = cfg.get("llm_provider", "anthropic")
    if provider and "LLM_PROVIDER" not in os.environ:
        os.environ["LLM_PROVIDER"] = provider
    key_map = {
        "anthropic_api_key": "ANTHROPIC_API_KEY",
        "openai_api_key": "OPENAI_API_KEY",
        "ollama_base_url": "OLLAMA_BASE_URL",
    }
    for cfg_key, env_key in key_map.items():
        val = cfg.get(cfg_key, "")
        if val and env_key not in os.environ:
            os.environ[env_key] = val
    if cfg.get("aws_profile") and "AWS_PROFILE" not in os.environ:
        os.environ["AWS_PROFILE"] = cfg["aws_profile"]
    if cfg.get("github_token") and "GITHUB_TOKEN" not in os.environ:
        os.environ["GITHUB_TOKEN"] = cfg["github_token"]


def _load_env() -> None:
    """Auto-load .env file if present (for local development)."""
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip()
                if key and key not in os.environ:
                    os.environ[key] = val


# --- Setup and Validation ---


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)s %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


def _require_configured() -> dict:
    """Ensure Pro-Prowler is configured. Returns resolved config."""
    _load_env()
    cfg = _resolve_config()

    # Default server to localhost:8000 if not configured
    if not cfg.get("server"):
        cfg["server"] = "http://localhost:8000"

    return cfg


def _require_llm_key(cfg: dict) -> None:
    """Check that an LLM API key is available."""
    provider = cfg.get("llm_provider", "anthropic").lower()
    key_map = {
        "anthropic": ("anthropic_api_key", "ANTHROPIC_API_KEY"),
        "openai": ("openai_api_key", "OPENAI_API_KEY"),
        "ollama": ("ollama_base_url", "OLLAMA_BASE_URL"),
    }
    cfg_key, env_key = key_map.get(provider, ("anthropic_api_key", "ANTHROPIC_API_KEY"))

    if not cfg.get(cfg_key) and not os.environ.get(env_key):
        click.echo(
            f"Error: {env_key} is not set.\n\n"
            f"Pro-Prowler uses AI for business context analysis, "
            f"attack path generation, and risk assessment.\n\n"
            f"Set it via:\n"
            f"  1. pro-prowler configure\n"
            f"  2. export {env_key}=sk-...\n"
            f"  3. Use --no-context to skip AI (basic scan only)\n",
            err=True,
        )
        raise SystemExit(1)


# --- Helper Functions ---


def _read_context_file(file_path: Path) -> str:
    """Read a context document file. Supports text, PDF, and DOCX."""
    suffix = file_path.suffix.lower()

    if suffix in (".txt", ".md", ".yaml", ".yml", ".json", ".rst"):
        try:
            return file_path.read_text(errors="ignore")[:8000]
        except Exception as e:
            click.echo(f"Warning: Could not read {file_path}: {e}", err=True)
            return ""

    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(str(file_path))
            parts = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    parts.append(text)
            return "\n\n".join(parts)[:8000]
        except Exception as e:
            click.echo(
                f"Warning: Could not read PDF {file_path}: {e}", err=True,
            )
            return ""

    if suffix == ".docx":
        try:
            from docx import Document
            doc = Document(str(file_path))
            return "\n\n".join(
                p.text for p in doc.paragraphs if p.text
            )[:8000]
        except Exception as e:
            click.echo(
                f"Warning: Could not read DOCX {file_path}: {e}", err=True,
            )
            return ""

    click.echo(
        f"Warning: Unsupported file type {suffix} for {file_path}",
        err=True,
    )
    return ""


def _fetch_project_context(server_url: str, repository: str) -> list[str]:
    """Fetch project context sources from the server."""
    import urllib.request

    url = f"{server_url.rstrip('/')}/api/projects"
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            projects = json.loads(resp.read())
    except Exception:
        return []

    project = None
    for p in projects:
        if p.get("repository") == repository:
            project = p
            break
    if not project:
        return []

    pid = project.get("id", "")
    detail_url = f"{server_url.rstrip('/')}/api/projects/{pid}/detail"
    try:
        req = urllib.request.Request(detail_url, headers={
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            detail = json.loads(resp.read())
    except Exception:
        return []

    docs: list[str] = []
    for src in detail.get("context_sources", []):
        if isinstance(src, dict) and src.get("key") and src.get("value"):
            docs.append(
                f"Project context — {src['key']}: {src['value']}",
            )
    return docs


def _push_to_server(
    server_url: str,
    result: object,
    repository: str,
    commit_hash: str,
) -> dict | None:
    """Push PipelineResult to a Pro-Prowler server."""
    import urllib.request

    url = f"{server_url.rstrip('/')}/api/snapshots/upload"
    payload = json.dumps({
        "repository": repository,
        "commit_hash": commit_hash,
        "result": result.model_dump(),  # type: ignore[union-attr]
    }, default=str).encode()

    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except Exception as e:
        click.echo(f"Warning: Failed to push to server: {e}", err=True)
        return None


def _switch_branch(terraform_dir: Path, branch: str) -> str | None:
    """Checkout a git branch. Returns the original branch name to restore."""
    import subprocess

    repo_dir = terraform_dir.resolve()
    while repo_dir != repo_dir.parent:
        if (repo_dir / ".git").exists():
            break
        repo_dir = repo_dir.parent
    else:
        raise click.ClickException(
            f"No git repository found for {terraform_dir}",
        )

    r = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    original = r.stdout.strip() if r.returncode == 0 else None

    if original == branch:
        return None

    r = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    if r.stdout.strip():
        raise click.ClickException(
            f"Uncommitted changes in {repo_dir}. "
            f"Commit or stash before switching branches.",
        )

    click.echo(f"Switching to branch: {branch}")
    subprocess.run(
        ["git", "fetch", "origin", branch],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    r = subprocess.run(
        ["git", "checkout", branch],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise click.ClickException(
            f"Failed to checkout branch '{branch}': {r.stderr.strip()}",
        )

    return original


def _restore_branch(terraform_dir: Path, branch: str) -> None:
    """Restore the original git branch."""
    import subprocess

    repo_dir = terraform_dir.resolve()
    while repo_dir != repo_dir.parent:
        if (repo_dir / ".git").exists():
            break
        repo_dir = repo_dir.parent

    click.echo(f"Restoring branch: {branch}")
    subprocess.run(
        ["git", "checkout", branch],
        cwd=str(repo_dir), capture_output=True, text=True,
    )


def _run_terraform(
    terraform_dir: Path,
    profile: str | None,
    var_files: tuple[Path, ...],
) -> Path:
    """Run terraform init, plan, and show -json. Returns path to plan.json."""
    import subprocess
    import tempfile

    env = os.environ.copy()
    if profile:
        env["AWS_PROFILE"] = profile

    tf_dir = str(terraform_dir)
    click.echo(f"Terraform directory: {tf_dir}")

    click.echo("Running terraform init...")
    r = subprocess.run(
        ["terraform", "init", "-input=false"],
        cwd=tf_dir, env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        click.echo(r.stderr, err=True)
        raise click.ClickException("terraform init failed")

    click.echo("Running terraform plan...")
    plan_out = os.path.join(
        tempfile.gettempdir(), "pro-prowler-plan.out",
    )
    cmd = ["terraform", "plan", "-input=false", f"-out={plan_out}"]
    for vf in var_files:
        cmd.append(f"-var-file={vf}")
    r = subprocess.run(
        cmd, cwd=tf_dir, env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        click.echo(r.stderr, err=True)
        raise click.ClickException("terraform plan failed")

    click.echo("Exporting plan JSON...")
    plan_json = os.path.join(
        tempfile.gettempdir(), "pro-prowler-plan.json",
    )
    r = subprocess.run(
        ["terraform", "show", "-json", plan_out],
        cwd=tf_dir, env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        click.echo(r.stderr, err=True)
        raise click.ClickException("terraform show -json failed")

    Path(plan_json).write_text(r.stdout)

    # Validate plan JSON
    try:
        plan_data = json.loads(r.stdout)
        resource_count = len(plan_data.get("resource_changes", []))
        click.echo(f"Plan exported: {resource_count} resources")
        if resource_count == 0:
            click.echo(
                "Warning: Plan has 0 resource changes. "
                "Check your Terraform configuration and AWS credentials.",
                err=True,
            )
    except json.JSONDecodeError:
        raise click.ClickException(
            "terraform show -json produced invalid JSON. "
            "Ensure terraform_wrapper is disabled if using setup-terraform.",
        )

    return Path(plan_json)


def _run_assessment(
    plan_data: dict,
    cfg: dict,
    no_context: bool,
    threshold: int,
    repository: str,
    commit_hash: str,
    extra_documents: list[str],
    local_report: bool,
    output_dir: Path,
    formats: tuple[str, ...],
    config_file: Path | None,
    business_docs: Path | None,
    verbose: bool,
) -> None:
    """Run pipeline, print summary, push to server."""
    from iac_risk.agents.report_generation import ReportGenerationAgent
    from iac_risk.config import load_config
    from iac_risk.core.schemas import ReportGenerationInput
    from iac_risk.orchestrator.runner import PipelineRunner
    from iac_risk.services.prowler_catalog import ProwlerCatalog

    server = cfg.get("server", "")

    # Fetch context from server project settings
    if server and repository and not no_context:
        server_ctx = _fetch_project_context(server, repository)
        extra_documents.extend(server_ctx)

    config = load_config(
        config_file=config_file,
        output_dir=str(output_dir),
        formats=formats,
        business_docs=str(business_docs) if business_docs else None,
        cache_dir=".pro-prowler-cache",
        skip_context=no_context,
        fail_threshold=threshold,
        extra_documents=extra_documents,
        repository=repository,
    )

    # Run pipeline
    catalog = ProwlerCatalog()
    runner = PipelineRunner(
        config=config, plan_data=plan_data, catalog=catalog,
    )
    result = runner.run()

    # Local reports (opt-in)
    if local_report:
        report_agent = ReportGenerationAgent()
        report_input = ReportGenerationInput(
            output_dir=config.output_dir,
            output_formats=config.output_formats,
        )
        report_result = report_agent.run((result, report_input))
        if report_result.output:
            for fmt, path in report_result.output.report_paths.items():
                click.echo(f"  {fmt.upper()}: {path}", err=True)

    # Print summary
    qs = result.quality_score
    click.echo()
    click.echo(f"Quality Score: {qs.score}/100 (Grade {qs.grade.value})")

    counts = qs.finding_counts
    parts = []
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
        count = counts.get(sev, 0)
        if count > 0:
            parts.append(f"{count} {sev}")
    if parts:
        click.echo(f"Findings: {', '.join(parts)}")
    else:
        click.echo("Findings: None")

    if qs.compliance_coverage:
        click.echo("Compliance:")
        for fw, cov in sorted(qs.compliance_coverage.items()):
            click.echo(f"  {fw}: {cov:.0f}%")

    # Push to server
    if server:
        if not repository:
            repository = "unknown"

        click.echo()
        click.echo(f"Pushing to {server}...")
        resp = _push_to_server(server, result, repository, commit_hash)
        if resp:
            sid = resp.get("snapshot_id", "")
            click.echo(f"Dashboard: {server.rstrip('/')}/dashboard/snapshots/{sid}")

    # Exit code
    passed = qs.score >= config.fail_threshold
    click.echo()
    if passed:
        click.echo(
            f"PASS (score {qs.score} >= threshold {config.fail_threshold})",
        )
    else:
        click.echo(
            f"FAIL (score {qs.score} < threshold {config.fail_threshold})",
        )
        raise SystemExit(1)


# --- CLI Commands ---


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Pro-Prowler — NIST SP 800-30 based risk assessment for Infrastructure as Code."""


@main.command()
def configure() -> None:
    """Set up Pro-Prowler (server URL, LLM key, AWS profile)."""
    existing = _load_user_config()

    server = click.prompt(
        "Pro-Prowler Server URL",
        default=existing.get("server", "http://localhost:8000"),
    )

    provider = click.prompt(
        "LLM Provider (anthropic/openai/ollama)",
        default=existing.get("llm_provider", "anthropic"),
    )

    api_key = ""
    if provider == "anthropic":
        api_key = click.prompt(
            "Anthropic API Key",
            default=existing.get("anthropic_api_key", ""),
            hide_input=True,
            show_default=False,
            prompt_suffix=" (hidden): " if not existing.get("anthropic_api_key") else " [****]: ",
        )
    elif provider == "openai":
        api_key = click.prompt(
            "OpenAI API Key",
            default=existing.get("openai_api_key", ""),
            hide_input=True,
            show_default=False,
        )
    elif provider == "ollama":
        api_key = click.prompt(
            "Ollama Base URL",
            default=existing.get("ollama_base_url", "http://localhost:11434"),
        )

    aws_profile = click.prompt(
        "AWS Profile (optional, press Enter to skip)",
        default=existing.get("aws_profile", ""),
    )

    github_token = click.prompt(
        "GitHub Token (optional, for repo scanning)",
        default=existing.get("github_token", ""),
        hide_input=True,
        show_default=False,
        prompt_suffix=" (hidden): " if not existing.get("github_token") else " [****]: ",
    )

    cfg: dict = {
        "server": server,
        "llm_provider": provider,
    }
    if provider == "anthropic" and api_key:
        cfg["anthropic_api_key"] = api_key
    elif provider == "openai" and api_key:
        cfg["openai_api_key"] = api_key
    elif provider == "ollama" and api_key:
        cfg["ollama_base_url"] = api_key
    if aws_profile:
        cfg["aws_profile"] = aws_profile
    if github_token:
        cfg["github_token"] = github_token

    _save_user_config(cfg)
    click.echo(f"\nConfiguration saved to {CONFIG_FILE}")
    click.echo(f"Server: {server}")
    click.echo(f"LLM: {provider}")
    if aws_profile:
        click.echo(f"AWS Profile: {aws_profile}")
    click.echo("\nYou're ready! Try: pro-prowler scan ./infra")


@main.command()
@click.argument("plan_file", type=click.Path(exists=True, path_type=Path))
@click.option("--repository", default="", help="Repository name (e.g. org/repo)")
@click.option("--commit", "commit_hash", default="", help="Git commit hash")
@click.option("--no-context", is_flag=True, help="Skip AI context analysis")
@click.option("--threshold", default=60, type=int, help="Quality score threshold")
@click.option("--local-report", is_flag=True, help="Also generate local HTML/JSON reports")
@click.option("--output-dir", "-o", default="./reports", type=click.Path(path_type=Path))
@click.option(
    "--format", "-f", "formats", multiple=True,
    type=click.Choice(["html", "xml", "json"]), default=["html", "json"],
)
@click.option("--server", default=None, help="Override server URL from config")
@click.option(
    "--context-source", "context_sources", multiple=True,
    help="Business context (repeatable)",
)
@click.option(
    "--context-file", "context_files", multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Context document path (repeatable, .txt/.md/.pdf/.docx)",
)
@click.option(
    "--config", "-c", "config_file",
    type=click.Path(exists=True, path_type=Path), default=None,
)
@click.option("--business-docs", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--verbose", "-v", is_flag=True)
def assess(
    plan_file: Path,
    repository: str,
    commit_hash: str,
    no_context: bool,
    threshold: int,
    local_report: bool,
    output_dir: Path,
    formats: tuple[str, ...],
    server: str | None,
    context_sources: tuple[str, ...],
    context_files: tuple[Path, ...],
    config_file: Path | None,
    business_docs: Path | None,
    verbose: bool,
) -> None:
    """Assess a Terraform plan JSON file and push results to the server."""
    _setup_logging(verbose)
    cfg = _require_configured()
    _apply_config_to_env(cfg)

    if server:
        cfg["server"] = server

    if not no_context:
        _require_llm_key(cfg)

    with open(plan_file) as f:
        plan_data = json.load(f)

    # Build extra documents
    extra_documents: list[str] = []
    for src in context_sources:
        extra_documents.append(f"Business context: {src}")
    for fpath in context_files:
        text = _read_context_file(fpath)
        if text:
            extra_documents.append(f"Document ({fpath.name}):\n{text}")

    if not repository:
        repository = plan_file.stem

    _run_assessment(
        plan_data=plan_data,
        cfg=cfg,
        no_context=no_context,
        threshold=threshold,
        repository=repository,
        commit_hash=commit_hash,
        extra_documents=extra_documents,
        local_report=local_report,
        output_dir=output_dir,
        formats=formats,
        config_file=config_file,
        business_docs=business_docs,
        verbose=verbose,
    )


@main.command()
@click.argument(
    "terraform_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--profile", "-p", default=None,
    help="AWS profile (overrides config)",
)
@click.option(
    "--branch", "-b", default=None,
    help="Git branch to checkout before scanning",
)
@click.option(
    "--var-file", "var_files", multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Terraform .tfvars file (repeatable)",
)
@click.option("--repository", default="", help="Repository name (e.g. org/repo)")
@click.option("--commit", "commit_hash", default="", help="Git commit hash")
@click.option("--no-context", is_flag=True, help="Skip AI context analysis")
@click.option("--threshold", default=60, type=int, help="Quality score threshold")
@click.option("--local-report", is_flag=True, help="Also generate local HTML/JSON reports")
@click.option("--output-dir", "-o", default="./reports", type=click.Path(path_type=Path))
@click.option(
    "--format", "-f", "formats", multiple=True,
    type=click.Choice(["html", "xml", "json"]), default=["html", "json"],
)
@click.option("--server", default=None, help="Override server URL from config")
@click.option(
    "--context-source", "context_sources", multiple=True,
    help="Business context (repeatable)",
)
@click.option(
    "--context-file", "context_files", multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Context document path (repeatable)",
)
@click.option("--verbose", "-v", is_flag=True)
def scan(
    terraform_dir: Path,
    profile: str | None,
    branch: str | None,
    var_files: tuple[Path, ...],
    repository: str,
    commit_hash: str,
    no_context: bool,
    threshold: int,
    local_report: bool,
    output_dir: Path,
    formats: tuple[str, ...],
    server: str | None,
    context_sources: tuple[str, ...],
    context_files: tuple[Path, ...],
    verbose: bool,
) -> None:
    """Scan a Terraform directory: plan + assess + push to server.

    Examples:

      pro-prowler scan ./infra

      pro-prowler scan ./infra --branch production --profile prod

      pro-prowler scan ./infra --var-file prod.tfvars
    """
    _setup_logging(verbose)
    cfg = _require_configured()
    _apply_config_to_env(cfg)

    if server:
        cfg["server"] = server
    if profile:
        cfg["aws_profile"] = profile
        os.environ["AWS_PROFILE"] = profile

    if not no_context:
        _require_llm_key(cfg)

    # Switch branch if requested
    original_branch = None
    if branch:
        original_branch = _switch_branch(terraform_dir, branch)

    try:
        plan_json = _run_terraform(
            terraform_dir, cfg.get("aws_profile"), var_files,
        )
    except Exception:
        if original_branch:
            _restore_branch(terraform_dir, original_branch)
        raise

    with open(plan_json) as f:
        plan_data = json.load(f)

    # Build extra documents
    extra_documents: list[str] = []
    for src in context_sources:
        extra_documents.append(f"Business context: {src}")
    for fpath in context_files:
        text = _read_context_file(fpath)
        if text:
            extra_documents.append(f"Document ({fpath.name}):\n{text}")

    if not repository:
        # Auto-detect from git remote
        import subprocess
        r = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(terraform_dir), capture_output=True, text=True,
        )
        if r.returncode == 0:
            remote = r.stdout.strip()
            repository = (
                remote.replace("https://github.com/", "")
                .replace("git@github.com:", "")
                .removesuffix(".git")
            )

    try:
        _run_assessment(
            plan_data=plan_data,
            cfg=cfg,
            no_context=no_context,
            threshold=threshold,
            repository=repository,
            commit_hash=commit_hash,
            extra_documents=extra_documents,
            local_report=local_report,
            output_dir=output_dir,
            formats=formats,
            config_file=None,
            business_docs=None,
            verbose=verbose,
        )
    finally:
        if original_branch:
            _restore_branch(terraform_dir, original_branch)


@main.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8000, type=int)
@click.option(
    "--data-dir", default="./data",
    type=click.Path(path_type=Path),
)
@click.option("--reload", is_flag=True, help="Auto-reload for development")
def serve(host: str, port: int, data_dir: Path, reload: bool) -> None:
    """Start the Pro-Prowler web server."""
    import uvicorn

    from iac_risk.web.app import create_app
    from iac_risk.web.config import WebConfig

    _load_env()
    cfg = _resolve_config()
    _apply_config_to_env(cfg)

    web_config = WebConfig(data_dir=data_dir, host=host, port=port)
    app = create_app(web_config)

    click.echo(f"Starting server on {host}:{port}")
    click.echo(f"Data directory: {data_dir}")
    click.echo(f"Dashboard: http://{host}:{port}/dashboard")
    click.echo(f"API docs:  http://{host}:{port}/docs")

    uvicorn.run(app, host=host, port=port, reload=reload)
