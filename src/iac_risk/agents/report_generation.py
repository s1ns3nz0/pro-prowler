"""Report Generation Agent — produces HTML, XML, and JSON reports."""

from __future__ import annotations

import logging
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.schemas import (
    PipelineResult,
    ReportGenerationInput,
    ReportGenerationOutput,
)

logger = logging.getLogger(__name__)


class ReportGenerationAgent(BaseAgent):
    name = "report_generation"
    critical = True

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, tuple) or len(input_data) != 2:
            return ValidationResult(
                valid=False,
                error="Expected (PipelineResult, ReportGenerationInput) tuple",
            )
        return ValidationResult(valid=True)

    def assess(
        self, input_data: tuple[PipelineResult, ReportGenerationInput],
    ) -> ReportGenerationOutput:
        result, config = input_data
        output_dir = config.output_dir
        formats = config.output_formats
        report_paths: dict[str, str] = {}

        if "json" in formats:
            from iac_risk.reports.json_renderer import render_json
            path = render_json(result, output_dir)
            report_paths["json"] = str(path)
            logger.info("JSON report written to %s", path)

        if "xml" in formats:
            from iac_risk.reports.xml_renderer import render_xml
            path = render_xml(result, output_dir)
            report_paths["xml"] = str(path)
            logger.info("XML report written to %s", path)

        if "html" in formats:
            from iac_risk.reports.html_renderer import render_html
            path = render_html(result, output_dir)
            report_paths["html"] = str(path)
            logger.info("HTML report written to %s", path)

        return ReportGenerationOutput(report_paths=report_paths)
