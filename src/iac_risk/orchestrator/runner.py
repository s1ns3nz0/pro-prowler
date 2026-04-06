"""Pipeline runner with DAG-based parallel execution."""

from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from iac_risk.agents.base import BaseAgent
from iac_risk.agents.change_management import ChangeManagementAgent
from iac_risk.agents.cloud_misconfig import CloudMisconfigAgent
from iac_risk.agents.compliance_mapping import ComplianceMappingAgent
from iac_risk.agents.context_analysis import ContextAnalysisAgent
from iac_risk.agents.iac_parser import IaCParserAgent
from iac_risk.agents.impact_assessment import ImpactAssessmentAgent
from iac_risk.agents.repo_analysis import RepoAnalysisAgent
from iac_risk.agents.risk_analysis import RiskAnalysisAgent
from iac_risk.core.enums import AgentStatus
from iac_risk.core.exceptions import PipelineError
from iac_risk.core.schemas import (
    AgentResult,
    ChangeManagementInput,
    CloudMisconfigInput,
    ComplianceMappingInput,
    ContextAnalysisInput,
    IaCParserInput,
    ImpactAssessmentInput,
    PipelineConfig,
    PipelineResult,
    RepoAnalysisInput,
    RiskAnalysisInput,
)
from iac_risk.orchestrator.context import PipelineContext
from iac_risk.orchestrator.dag import build_default_dag
from iac_risk.services.prowler_catalog import ProwlerCatalog
from iac_risk.services.quality_score import calculate_quality_score

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Executes the agent pipeline according to DAG dependencies."""

    def __init__(
        self,
        config: PipelineConfig,
        plan_data: dict[str, Any],
        catalog: ProwlerCatalog | None = None,
    ) -> None:
        self.config = config
        self.plan_data = plan_data
        self.catalog = catalog or ProwlerCatalog()
        self.ctx = PipelineContext()
        self.dag = build_default_dag(skip_context=config.skip_context_analysis)
        self._agents = self._build_agents()

    def _build_agents(self) -> dict[str, BaseAgent]:
        agents: dict[str, BaseAgent] = {
            "iac_parser": IaCParserAgent(),
            "cloud_misconfig": CloudMisconfigAgent(catalog=self.catalog),
            "risk_analysis": RiskAnalysisAgent(catalog=self.catalog),
            "impact_assessment": ImpactAssessmentAgent(),
            "compliance_mapping": ComplianceMappingAgent(catalog=self.catalog),
            "change_management": ChangeManagementAgent(),
        }
        if not self.config.skip_context_analysis:
            agents["repo_analysis"] = RepoAnalysisAgent()
            agents["context_analysis"] = ContextAnalysisAgent()
        return agents

    def _build_input(self, agent_name: str) -> Any:
        """Build the input for an agent from pipeline context."""
        if agent_name == "iac_parser":
            return IaCParserInput(plan_data=self.plan_data)

        if agent_name == "repo_analysis":
            return RepoAnalysisInput(
                repository=self.config.repository,
                linked_repos=self.config.linked_repos,
            )

        if agent_name == "context_analysis":
            # Feed repo analysis output into context analysis
            repo_out = self.ctx.get_output("repo_analysis")
            app_insights = []
            governance_insights = []
            if repo_out:
                analysis = (
                    repo_out.get("analysis", {})
                    if isinstance(repo_out, dict)
                    else repo_out.analysis
                )
                if isinstance(analysis, dict):
                    app_insights = analysis.get(
                        "app_insights", [],
                    )
                    governance_insights = analysis.get(
                        "governance_insights", [],
                    )
                else:
                    app_insights = [
                        i.model_dump() for i in analysis.app_insights
                    ]
                    governance_insights = [
                        g.model_dump()
                        for g in analysis.governance_insights
                    ]
            from iac_risk.core.schemas import (
                AppInsight,
                GovernanceInsight,
            )
            return ContextAnalysisInput(
                business_docs_dir=self.config.business_docs_dir,
                cache_dir=self.config.cache_dir,
                app_insights=[
                    AppInsight.model_validate(i)
                    if isinstance(i, dict) else i
                    for i in app_insights
                ],
                governance_insights=[
                    GovernanceInsight.model_validate(g)
                    if isinstance(g, dict) else g
                    for g in governance_insights
                ],
                extra_documents=self.config.extra_documents,
            )

        if agent_name == "cloud_misconfig":
            parser_out = self.ctx.get_output("iac_parser")
            return CloudMisconfigInput(inventory=parser_out.inventory)

        if agent_name == "risk_analysis":
            parser_out = self.ctx.get_output("iac_parser")
            misconfig_out = self.ctx.get_output("cloud_misconfig")
            context_out = self.ctx.get_output("context_analysis")
            contexts = context_out.contexts if context_out else []
            return RiskAnalysisInput(
                inventory=parser_out.inventory,
                findings=misconfig_out.findings,
                business_contexts=contexts,
            )

        if agent_name == "impact_assessment":
            misconfig_out = self.ctx.get_output("cloud_misconfig")
            risk_out = self.ctx.get_output("risk_analysis")
            context_out = self.ctx.get_output("context_analysis")
            contexts = context_out.contexts if context_out else []
            return ImpactAssessmentInput(
                findings=misconfig_out.findings,
                risk_determinations=risk_out.risk_determinations,
                business_contexts=contexts,
            )

        if agent_name == "compliance_mapping":
            misconfig_out = self.ctx.get_output("cloud_misconfig")
            impact_out = self.ctx.get_output("impact_assessment")
            context_out = self.ctx.get_output("context_analysis")
            contexts = context_out.contexts if context_out else []
            return ComplianceMappingInput(
                findings=misconfig_out.findings,
                impact_ratings=impact_out.impact_ratings,
                business_contexts=contexts,
                frameworks=self.config.compliance_frameworks,
            )

        if agent_name == "change_management":
            parser_out = self.ctx.get_output("iac_parser")
            misconfig_out = self.ctx.get_output("cloud_misconfig")
            compliance_out = self.ctx.get_output("compliance_mapping")
            context_out = self.ctx.get_output("context_analysis")
            contexts = context_out.contexts if context_out else []
            return ChangeManagementInput(
                inventory=parser_out.inventory,
                findings=misconfig_out.findings,
                gap_analyses=compliance_out.gap_analyses,
                business_contexts=contexts,
            )

        if agent_name == "report_generation":
            return None

        raise PipelineError(f"Unknown agent: {agent_name}")

    def _run_agent(self, agent_name: str) -> AgentResult:
        agent = self._agents.get(agent_name)
        if not agent:
            return AgentResult(
                agent_name=agent_name,
                status=AgentStatus.SKIPPED,
                error="Agent not configured",
            )

        input_data = self._build_input(agent_name)
        return agent.run(input_data)

    def run(self) -> PipelineResult:
        """Execute the full pipeline."""
        start = time.monotonic()
        completed: set[str] = set()
        failed_critical = False

        # Exclude report_generation — handled after pipeline
        execution_nodes = {
            name for name in self.dag.nodes if name != "report_generation"
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            running: dict[str, Future[AgentResult]] = {}

            while completed & execution_nodes != execution_nodes and not failed_critical:
                # Find ready agents
                ready = [
                    n for n in self.dag.get_ready_nodes(completed)
                    if n in execution_nodes and n not in running
                ]

                # Submit ready agents
                for name in ready:
                    logger.info("Starting agent: %s", name)
                    future = executor.submit(self._run_agent, name)
                    running[name] = future

                if not running:
                    break

                # Wait for any completion
                done_futures = set()
                for name, future in running.items():
                    if future.done():
                        done_futures.add(name)

                if not done_futures:
                    # Wait for at least one to complete
                    for future in as_completed(running.values()):
                        break
                    # Re-check
                    for name, future in running.items():
                        if future.done():
                            done_futures.add(name)

                for name in done_futures:
                    future = running.pop(name)
                    result = future.result()
                    self.ctx.set_result(name, result)
                    logger.info(
                        "Agent %s: %s (%dms)",
                        name,
                        result.status.value,
                        result.duration_ms,
                    )

                    if result.status == AgentStatus.COMPLETED:
                        completed.add(name)
                    elif result.status == AgentStatus.FAILED:
                        node = self.dag.get_node(name)
                        if node and node.critical:
                            logger.error("Critical agent '%s' failed: %s", name, result.error)
                            failed_critical = True
                        else:
                            logger.warning("Non-critical agent '%s' failed: %s", name, result.error)
                            completed.add(name)  # Allow pipeline to continue

        # Calculate quality score
        misconfig_out = self.ctx.get_output("cloud_misconfig")
        impact_out = self.ctx.get_output("impact_assessment")
        compliance_out = self.ctx.get_output("compliance_mapping")

        findings = misconfig_out.findings if misconfig_out else []
        impact_ratings = impact_out.impact_ratings if impact_out else []
        compliance_coverage = {}
        if compliance_out:
            for ga in compliance_out.gap_analyses:
                compliance_coverage[ga.framework.value] = ga.coverage_score

        quality_score = calculate_quality_score(findings, impact_ratings, compliance_coverage)

        return PipelineResult(
            agent_results=self.ctx.all_results,
            quality_score=quality_score,
            total_duration_ms=int((time.monotonic() - start) * 1000),
        )
